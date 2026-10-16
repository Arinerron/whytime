//! Per-thread timelines rebuilt from the ring buffer records.
//!
//! Every tracked thread's life is a gap-free sequence of [`Seg`]ments: mixed on-CPU/preempted
//! stretches (accumulated in kernel), blocks (classified on arrival), and wake-to-run runqueue
//! waits. Processes own threads and know their parent, so the critical-path walk in
//! [`crate::attribute`] can descend from the wrapped command into its descendants.

use std::collections::HashMap;
use std::sync::Arc;

use procctx::{ExecEvent, ExitEvent, ForkEvent, ProcFs, ProcKey, ProcTable};
use whytime_abi::{
    CpuSegment, EPF_FAULT, EPF_READY, EV_EPISODE, EV_EXEC, EV_EXIT, EV_FORK, EpisodeRecord,
    EvHeader, ExecRecord, ExitRecord, ForkRecord, ST_BLOCKED, ST_RUNNABLE, ST_RUNNING, ST_WOKEN,
    TaskState,
};

use crate::classify::{BlockInfo, Blocked, Classifier};

/// Index into [`Trace::procs`].
pub type ProcId = usize;
/// Index into [`Trace::threads`].
pub type ThreadId = usize;

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
    /// Thread-group id of the task that ended the block; 0 when unknown or when the wakeup
    /// came from interrupt context.
    pub waker_tgid: u32,
    /// `comm` of the waker when it is a process-context task outside the traced tree.
    pub waker_comm: Option<Arc<str>>,
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
    /// Interned waker `comm`s.
    comms: HashMap<[u8; 16], Arc<str>>,
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
            comms: HashMap::new(),
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
        let waker_comm = self.intern_comm(&r.waker_comm);
        let what = self.classifier.classify_block(
            hdr.tgid,
            &BlockInfo {
                sys: &r.sys,
                block_state: r.block_state,
                ready: (r.flags & EPF_READY != 0).then_some(&r.ready),
                fault: (r.flags & EPF_FAULT != 0).then_some(&r.fault),
                waker: waker_comm.as_ref(),
            },
        );
        let block = Block {
            what,
            waker_tgid: r.waker_tgid,
            waker_comm,
        };
        self.push_block(thread, block_ts, wake_ts, block);
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
                    run_ns: state.seg.run_ns + run,
                    rq_ns: state.seg.rq_ns + rq,
                    ..state.seg
                }
            };
            match state.state {
                ST_RUNNING => self.push_mixed(thread, &open(true), end),
                ST_RUNNABLE => self.push_mixed(thread, &open(false), end),
                ST_BLOCKED | ST_WOKEN => {
                    self.push_mixed(thread, &state.seg, state.block_ts);
                    let tgid = self.procs[proc].key.pid;
                    let waker_comm = self.intern_comm(&state.waker_comm);
                    let what = self.classifier.classify_block(
                        tgid,
                        &BlockInfo {
                            sys: &state.sys,
                            block_state: state.block_state,
                            ready: (state.has_ready != 0).then_some(&state.ready),
                            fault: (state.in_fault != 0).then_some(&state.fault),
                            waker: waker_comm.as_ref(),
                        },
                    );
                    let wake = if state.state == ST_WOKEN {
                        state.wake_ts.clamp(state.block_ts, end.max(state.block_ts))
                    } else {
                        end
                    };
                    let block = Block {
                        what,
                        waker_tgid: state.waker_tgid,
                        waker_comm,
                    };
                    self.push_block(thread, state.block_ts, wake, block);
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

    fn push_block(&mut self, thread: ThreadId, start: u64, end: u64, block: Block) {
        self.push(thread, start, end, SegKind::Blocked(Box::new(block)));
    }

    /// The `comm` in a NUL-padded kernel buffer, interned; `None` when empty.
    fn intern_comm(&mut self, raw: &[u8; 16]) -> Option<Arc<str>> {
        if raw[0] == 0 {
            return None;
        }
        let comm = self
            .comms
            .entry(*raw)
            .or_insert_with(|| Arc::from(String::from_utf8_lossy(cstr(raw)).as_ref()));
        Some(Arc::clone(comm))
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
