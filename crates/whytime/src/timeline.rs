//! Per-thread timelines rebuilt from the ring buffer records.
//!
//! Every tracked thread's life is a gap-free sequence of [`Seg`]ments: mixed on-CPU/preempted
//! stretches (accumulated in kernel), blocks (classified on arrival), and wake-to-run runqueue
//! waits. Processes own threads and know their parent, so the critical-path walk in
//! [`crate::attribute`] can descend from the wrapped command into its descendants.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use procctx::{Config, ExecEvent, ExitEvent, ForkEvent, ProcFs, ProcKey, ProcTable, StartClock};
use whytime_abi::{
    CpuSegment, EV_EPISODE, EV_EXEC, EV_EXIT, EV_FORK, EpisodeRecord, EvHeader, ExecRecord,
    ExitRecord, ForkRecord, ST_BLOCKED, ST_RUNNABLE, ST_RUNNING, ST_WOKEN, TaskState,
};

use crate::classify::{Blocked, Classifier};

/// Index into [`Trace::procs`].
pub type ProcId = usize;
/// Index into [`Trace::threads`].
pub type ThreadId = usize;

/// The process table a [`Trace`] keeps, comparing process starts at clock-tick (`AT_CLKTCK`)
/// resolution. whytime only feeds it events and looks records up by key, which never reads
/// `/proc`, so a replayed trace rebuilds it exactly.
pub fn proc_table(ticks_per_sec: NonZeroU64) -> ProcTable<ProcFs> {
    ProcTable::new(
        ProcFs::new(),
        Config {
            start_clock: StartClock::BootNs { ticks_per_sec },
            read_environ: false,
            ..Config::default()
        },
    )
}

/// What a thread was doing during a [`Seg`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegKind {
    /// On a CPU for `run` ns and preempted for `rq` ns, interleaved in unknown order.
    Mixed {
        /// On-CPU nanoseconds.
        run: u64,
        /// Preempted (runnable, off-CPU) nanoseconds.
        rq: u64,
    },
    /// Woken, waiting to be scheduled.
    Runq,
    /// Blocked on something.
    Blocked(Box<Block>),
}

/// A classified off-CPU interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// What it waited for.
    pub what: Blocked,
    /// Thread-group id of the task that ended the block; 0 when unknown.
    pub waker_tgid: u32,
}

/// A half-open interval `[start, end)` of `CLOCK_MONOTONIC` nanoseconds on one thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seg {
    /// Start.
    pub start: u64,
    /// End.
    pub end: u64,
    /// Activity.
    pub kind: SegKind,
}

/// One thread's timeline.
#[derive(Debug)]
pub struct Thread {
    /// Kernel thread id.
    pub tid: u32,
    /// Owning process.
    pub proc: ProcId,
    /// Fork (or first exec) time.
    pub birth: u64,
    /// Exit time, if it exited.
    pub death: Option<u64>,
    /// Segments in time order, non-overlapping.
    pub segs: Vec<Seg>,
}

/// One process lifetime in the traced tree.
#[derive(Debug)]
pub struct Proc {
    /// procctx identity: tgid and `start_boottime`.
    pub key: ProcKey,
    /// Fork (or, for the wrapped command, exec) time.
    pub birth: u64,
    /// Exit time of the whole thread group.
    pub death: Option<u64>,
    /// `comm` history: each entry holds from its timestamp on.
    pub comms: Vec<(u64, Arc<str>)>,
    /// Threads, the original leader first.
    pub threads: Vec<ThreadId>,
    /// Child processes.
    pub children: Vec<ProcId>,
    /// On-CPU nanoseconds over all threads.
    pub cpu_ns: u64,
}

impl Proc {
    /// `comm` at time `ts`.
    pub fn comm_at(&self, ts: u64) -> &Arc<str> {
        let i = self.comms.partition_point(|(from, _)| *from <= ts);
        &self.comms[i.saturating_sub(1)].1
    }

    /// The latest `comm`.
    pub fn comm(&self) -> &Arc<str> {
        &self.comms[self.comms.len() - 1].1
    }
}

/// The observation window: the wrapped command's first exec to its exit (or a deadline).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    /// The wrapped command's exec.
    pub start: Option<u64>,
    /// Exit of the wrapped command's last thread.
    pub exit: Option<u64>,
}

/// Every tracked process and thread, built incrementally from records.
#[derive(Debug)]
pub struct Trace {
    /// Processes in order of appearance.
    pub procs: Vec<Proc>,
    /// Threads in order of appearance.
    pub threads: Vec<Thread>,
    /// The wrapped command, once its exec record arrived.
    pub root: Option<ProcId>,
    /// Observation window.
    pub window: Window,
    /// Records decoded.
    pub records: u64,
    /// Records that could not be decoded.
    pub malformed: u64,
    /// Identity, argv and exit status of every process.
    pub table: ProcTable<ProcFs>,
    root_pid: u32,
    live_procs: HashMap<u32, ProcId>,
    live_threads: HashMap<u32, ThreadId>,
    classifier: Classifier,
}

impl Trace {
    /// An empty trace for the wrapped command `root_pid`.
    pub fn new(root_pid: u32, classifier: Classifier, table: ProcTable<ProcFs>) -> Self {
        Self {
            procs: Vec::new(),
            threads: Vec::new(),
            root: None,
            window: Window::default(),
            records: 0,
            malformed: 0,
            table,
            root_pid,
            live_procs: HashMap::new(),
            live_threads: HashMap::new(),
            classifier,
        }
    }

    /// Decodes and applies one ring buffer record.
    pub fn ingest(&mut self, bytes: &[u8]) {
        self.records += 1;
        let applied = wire::from_bytes::<EvHeader>(bytes).and_then(|hdr| match hdr.kind {
            EV_FORK => wire::from_bytes::<ForkRecord>(bytes).map(|r| self.on_fork(r)),
            EV_EXEC => wire::from_bytes::<ExecRecord>(bytes).map(|r| self.on_exec(r)),
            EV_EPISODE => wire::from_bytes::<EpisodeRecord>(bytes).map(|r| self.on_episode(r)),
            EV_EXIT => wire::from_bytes::<ExitRecord>(bytes).map(|r| self.on_exit(r)),
            _ => None,
        });
        if applied.is_none() {
            self.malformed += 1;
        }
    }

    fn on_fork(&mut self, r: &ForkRecord) {
        let ts = r.hdr.ts;
        if r.child_tgid == r.hdr.tgid {
            if let Some(&proc) = self.live_procs.get(&r.hdr.tgid) {
                self.new_thread(r.child_tid, proc, ts);
            }
            return;
        }
        let parent = self.live_procs.get(&r.hdr.tgid).copied();
        let comm = parent.map_or_else(|| Arc::from("?"), |p| Arc::clone(self.procs[p].comm()));
        let key = ProcKey {
            pid: r.child_tgid,
            start: r.child_start,
        };
        let proc = self.new_proc(key, parent, ts, comm);
        self.new_thread(r.child_tid, proc, ts);
        self.table.on_fork(ForkEvent {
            ts_ns: ts,
            parent: r.hdr.tgid,
            child: key,
            is_thread: false,
        });
    }

    fn on_exec(&mut self, r: &ExecRecord) {
        let ExecRecord { hdr, seg, .. } = *r;
        let comm: Arc<str> = Arc::from(String::from_utf8_lossy(cstr(&r.comm)).as_ref());
        let key = ProcKey {
            pid: hdr.tgid,
            start: r.start,
        };
        let proc = if let Some(&proc) = self.live_procs.get(&hdr.tgid) {
            self.procs[proc].comms.push((hdr.ts, Arc::clone(&comm)));
            proc
        } else {
            // The wrapped command (forked before tracking began), or a process whose fork
            // record was lost: its timeline starts here.
            let proc = self.new_proc(key, None, hdr.ts, Arc::clone(&comm));
            if hdr.tgid == self.root_pid && self.root.is_none() {
                self.root = Some(proc);
                self.window.start = Some(hdr.ts);
            }
            proc
        };
        if r.old_tid != hdr.tid
            && let Some(thread) = self.live_threads.remove(&r.old_tid)
        {
            // A non-leader thread exec'd and now carries the leader's tid.
            self.threads[thread].tid = hdr.tid;
            self.live_threads.insert(hdr.tid, thread);
        }
        let thread = self.thread(hdr.tid, proc, seg.start);
        self.push_mixed(thread, &seg, hdr.ts);

        let argv_len = usize::try_from(r.argv_len).map_or(0, |n| n.min(r.argv.len()));
        let argv = &r.argv[..argv_len];
        self.table.on_exec(ExecEvent {
            ppid: Some(r.ppid),
            comm: Some(cstr(&r.comm)),
            argv: Some(argv),
            argv_truncated: argv_len == r.argv.len(),
            ..ExecEvent::new(hdr.ts, key)
        });
    }

    fn on_episode(&mut self, r: &EpisodeRecord) {
        let hdr = r.hdr;
        let Some(proc) = self.live_procs.get(&hdr.tgid).copied() else {
            return;
        };
        let thread = self.thread(hdr.tid, proc, r.seg.start);
        let block_ts = r.block_ts.max(r.seg.start);
        let run_ts = hdr.ts.max(block_ts);
        // No observed wakeup (it raced with the switch-out): count the whole gap as blocked.
        let wake_ts = if (block_ts..=run_ts).contains(&r.wake_ts) {
            r.wake_ts
        } else {
            run_ts
        };
        self.push_mixed(thread, &r.seg, block_ts);
        let what = self.classifier.classify(hdr.tgid, &r.sys, r.block_state);
        self.push_block(thread, block_ts, wake_ts, what, r.waker_tgid);
        self.push(thread, wake_ts, run_ts, SegKind::Runq);
    }

    fn on_exit(&mut self, r: &ExitRecord) {
        let hdr = r.hdr;
        if let Some(thread) = self.live_threads.remove(&hdr.tid) {
            self.push_mixed(thread, &r.seg, hdr.ts);
            self.threads[thread].death = Some(hdr.ts);
        }
        if r.group_dead == 0 {
            return;
        }
        let Some(proc) = self.live_procs.remove(&hdr.tgid) else {
            return;
        };
        self.procs[proc].death = Some(hdr.ts);
        self.table.on_exit(ExitEvent {
            ts_ns: hdr.ts,
            key: self.procs[proc].key,
            code: r.code,
        });
        if self.root == Some(proc) {
            self.window.exit = Some(hdr.ts);
        }
    }

    /// Closes the timelines of threads still alive at `end` from their in-kernel state.
    pub fn sweep(&mut self, tasks: &[(u32, TaskState)], end: u64) {
        for (tid, state) in tasks {
            let Some(&thread) = self.live_threads.get(tid) else {
                continue;
            };
            let proc = self.threads[thread].proc;
            let open = |extra_run: bool| {
                let since = end.saturating_sub(state.last_ts);
                let (run, rq) = if extra_run { (since, 0) } else { (0, since) };
                CpuSegment {
                    start: state.seg.start,
                    run_ns: state.seg.run_ns + run,
                    rq_ns: state.seg.rq_ns + rq,
                }
            };
            match state.state {
                ST_RUNNING => self.push_mixed(thread, &open(true), end),
                ST_RUNNABLE => self.push_mixed(thread, &open(false), end),
                ST_BLOCKED | ST_WOKEN => {
                    self.push_mixed(thread, &state.seg, state.block_ts);
                    let tgid = self.procs[proc].key.pid;
                    let what = self
                        .classifier
                        .classify(tgid, &state.sys, state.block_state);
                    let wake = if state.state == ST_WOKEN {
                        state.wake_ts.clamp(state.block_ts, end.max(state.block_ts))
                    } else {
                        end
                    };
                    self.push_block(thread, state.block_ts, wake, what, state.waker_tgid);
                    self.push(thread, wake, end, SegKind::Runq);
                }
                _ => {}
            }
        }
    }

    fn new_proc(
        &mut self,
        key: ProcKey,
        parent: Option<ProcId>,
        birth: u64,
        comm: Arc<str>,
    ) -> ProcId {
        let id = self.procs.len();
        self.procs.push(Proc {
            key,
            birth,
            death: None,
            comms: vec![(birth, comm)],
            threads: Vec::new(),
            children: Vec::new(),
            cpu_ns: 0,
        });
        if let Some(parent) = parent {
            self.procs[parent].children.push(id);
        }
        self.live_procs.insert(key.pid, id);
        id
    }

    fn new_thread(&mut self, tid: u32, proc: ProcId, birth: u64) -> ThreadId {
        let id = self.threads.len();
        self.threads.push(Thread {
            tid,
            proc,
            birth,
            death: None,
            segs: Vec::new(),
        });
        self.procs[proc].threads.push(id);
        self.live_threads.insert(tid, id);
        id
    }

    /// The live thread `tid`, created (born at `birth`) if its fork record was lost.
    fn thread(&mut self, tid: u32, proc: ProcId, birth: u64) -> ThreadId {
        match self.live_threads.get(&tid) {
            Some(&thread) => thread,
            None => self.new_thread(tid, proc, birth),
        }
    }

    fn push_mixed(&mut self, thread: ThreadId, seg: &CpuSegment, end: u64) {
        let proc = self.threads[thread].proc;
        self.procs[proc].cpu_ns += seg.run_ns;
        self.push(
            thread,
            seg.start,
            end,
            SegKind::Mixed {
                run: seg.run_ns,
                rq: seg.rq_ns,
            },
        );
    }

    fn push_block(
        &mut self,
        thread: ThreadId,
        start: u64,
        end: u64,
        what: Blocked,
        waker_tgid: u32,
    ) {
        let block = Block { what, waker_tgid };
        self.push(thread, start, end, SegKind::Blocked(Box::new(block)));
    }

    /// Appends a segment, trimming any overlap with the previous one; empty segments are
    /// dropped.
    fn push(&mut self, thread: ThreadId, start: u64, end: u64, kind: SegKind) {
        let segs = &mut self.threads[thread].segs;
        let start = segs.last().map_or(start, |last| start.max(last.end));
        if end > start {
            segs.push(Seg { start, end, kind });
        }
    }
}

/// The bytes of a NUL-terminated C string buffer, without the terminator.
fn cstr(bytes: &[u8]) -> &[u8] {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..len]
}

#[cfg(test)]
mod tests {
    use libc::SYS_nanosleep;

    use super::*;
    use crate::classify::Class;
    use crate::testkit::{episode, exec, exit, feed, fork, seg, sys, task, trace};

    fn spans(thread: &Thread) -> Vec<(u64, u64)> {
        thread.segs.iter().map(|s| (s.start, s.end)).collect()
    }

    fn blocked_class(seg: &Seg) -> Option<Class> {
        match &seg.kind {
            SegKind::Blocked(block) => Some(block.what.class),
            _ => None,
        }
    }

    #[test]
    fn an_episode_chains_on_cpu_blocked_and_runqueue_segments_without_gaps() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        let sleep = sys(SYS_nanosleep);
        feed(&mut t, &episode(100, 100, seg(1_000, 300, 100), sleep, [1_400, 2_000, 2_100]));
        feed(&mut t, &exit(3_000, 100, 100, seg(2_100, 900, 0), 0, true));

        let thread = &t.threads[0];
        assert_eq!(
            spans(thread),
            [(1_000, 1_400), (1_400, 2_000), (2_000, 2_100), (2_100, 3_000)]
        );
        let segs = &thread.segs;
        assert!(matches!(segs[0].kind, SegKind::Mixed { run: 300, rq: 100, .. }));
        assert_eq!(blocked_class(&segs[1]), Some(Class::Sleep));
        assert_eq!(segs[2].kind, SegKind::Runq);
        assert!(matches!(segs[3].kind, SegKind::Mixed { run: 900, rq: 0, .. }));
        assert_eq!(t.procs[0].cpu_ns, 1_200);
        assert_eq!(
            t.window,
            Window {
                start: Some(1_000),
                exit: Some(3_000)
            }
        );
    }

    #[test]
    fn a_wakeup_that_was_not_seen_counts_the_whole_gap_as_blocked() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        let sleep = sys(SYS_nanosleep);
        // No wakeup observed.
        feed(&mut t, &episode(100, 100, seg(1_000, 400, 0), sleep, [1_400, 0, 2_100]));
        // A stale wake time from before the block.
        feed(&mut t, &episode(100, 100, seg(2_100, 100, 0), sleep, [2_200, 1_500, 2_600]));

        let thread = &t.threads[0];
        assert_eq!(
            spans(thread),
            [(1_000, 1_400), (1_400, 2_100), (2_100, 2_200), (2_200, 2_600)]
        );
        assert_eq!(blocked_class(&thread.segs[1]), Some(Class::Sleep));
        assert_eq!(blocked_class(&thread.segs[3]), Some(Class::Sleep));
        assert!(thread.segs.iter().all(|s| s.kind != SegKind::Runq));
    }

    #[test]
    fn a_non_leader_exec_moves_its_thread_onto_the_leader_tid() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        feed(&mut t, &fork(1_100, 100, 100, 101, 100));
        // Thread 101 execs: the kernel ends the leader, then 101 takes over tid 100.
        feed(&mut t, &exit(1_900, 100, 100, seg(1_000, 900, 0), 0, false));
        feed(&mut t, &exec(2_000, 101, 100, "tool", seg(1_100, 900, 0)));
        let sleep = sys(SYS_nanosleep);
        feed(&mut t, &episode(100, 100, seg(2_000, 100, 0), sleep, [2_100, 2_500, 2_500]));
        feed(&mut t, &exit(3_000, 100, 100, seg(2_500, 500, 0), 0, true));

        assert_eq!(t.threads.len(), 2, "the post-exec tid is not a new thread");
        let (leader, execer) = (&t.threads[0], &t.threads[1]);
        assert_eq!(leader.death, Some(1_900));
        assert_eq!(execer.tid, 100);
        assert_eq!(execer.death, Some(3_000));
        assert_eq!(
            spans(execer),
            [(1_100, 2_000), (2_000, 2_100), (2_100, 2_500), (2_500, 3_000)]
        );
        let proc = &t.procs[0];
        assert_eq!(proc.comm_at(1_999).as_ref(), "app");
        assert_eq!(proc.comm_at(2_000).as_ref(), "tool");
        assert_eq!(proc.death, Some(3_000));
    }

    #[test]
    fn only_the_last_thread_of_the_command_ends_the_window() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        feed(&mut t, &fork(1_100, 100, 100, 101, 100));
        feed(&mut t, &fork(1_200, 100, 100, 200, 200));

        feed(&mut t, &exit(2_000, 101, 100, seg(1_100, 900, 0), 0, false));
        assert_eq!(t.threads[1].death, Some(2_000));
        assert_eq!(t.procs[0].death, None);
        // A child process ending is not the command ending.
        feed(&mut t, &exit(2_500, 200, 200, seg(1_200, 1_300, 0), 0, true));
        assert_eq!(t.procs[1].death, Some(2_500));
        assert_eq!(t.window.exit, None);

        feed(&mut t, &exit(3_000, 100, 100, seg(1_000, 2_000, 0), 7 << 8, true));
        assert_eq!(t.procs[0].death, Some(3_000));
        assert_eq!(t.window.exit, Some(3_000));
        let info = t.table.get_key(t.procs[0].key).expect("root in the process table");
        assert_eq!(info.exit.and_then(|exit| exit.code), Some(7 << 8));
    }

    #[test]
    fn the_sweep_closes_every_open_interval_at_the_window_end() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        for tid in 101..=103 {
            feed(&mut t, &fork(1_000 + u64::from(tid - 100) * 100, 100, 100, tid, 100));
        }
        let mut blocked = task(100, ST_BLOCKED, seg(1_000, 500, 0));
        blocked.block_ts = 1_500;
        blocked.sys = sys(SYS_nanosleep);
        let mut woken = task(100, ST_WOKEN, seg(1_100, 400, 0));
        woken.block_ts = 1_500;
        woken.wake_ts = 9_000;
        woken.sys = sys(SYS_nanosleep);
        let mut running = task(100, ST_RUNNING, seg(1_200, 300, 0));
        running.last_ts = 9_500;
        let mut preempted = task(100, ST_RUNNABLE, seg(1_300, 300, 0));
        preempted.last_ts = 9_500;
        let untracked = task(999, ST_RUNNING, seg(0, 1, 0));
        let tasks = [
            (100, blocked),
            (101, woken),
            (102, running),
            (103, preempted),
            (999, untracked),
        ];
        t.sweep(&tasks, 10_000);

        assert_eq!(t.threads.len(), 4);
        let [blocked, woken, running, preempted] = [0, 1, 2, 3].map(|i| &t.threads[i]);
        assert_eq!(spans(blocked), [(1_000, 1_500), (1_500, 10_000)]);
        assert_eq!(blocked_class(&blocked.segs[1]), Some(Class::Sleep));
        assert_eq!(
            spans(woken),
            [(1_100, 1_500), (1_500, 9_000), (9_000, 10_000)]
        );
        assert_eq!(woken.segs[2].kind, SegKind::Runq);
        assert_eq!(spans(running), [(1_200, 10_000)]);
        assert!(matches!(running.segs[0].kind, SegKind::Mixed { run: 800, rq: 0, .. }));
        assert_eq!(spans(preempted), [(1_300, 10_000)]);
        assert!(matches!(preempted.segs[0].kind, SegKind::Mixed { run: 300, rq: 500, .. }));
        assert_eq!(t.procs[0].cpu_ns, 500 + 400 + 800 + 300);
    }
}
