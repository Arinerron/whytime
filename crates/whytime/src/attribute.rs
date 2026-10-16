//! Critical-path attribution: every nanosecond of the window goes to exactly one span.
//!
//! The walk follows the wrapped command's main thread through the window. On-CPU time of the
//! command's own process (any thread) is `cpu`; on-CPU time of a descendant process is
//! `child` ("waiting on child: <comm>"); preempted and woken-not-yet-running time is
//! `runqueue`; blocked time goes to the class of what it blocked on, unless another tracked
//! task explains the block. Then the walk follows that task over the same interval, applying
//! the same rules recursively, so the followed task's own blocks keep their class (a lock
//! holder's sleep is `sleep`):
//!
//! - `futex`, `ipc` (pipes, local sockets) and `poll` blocks woken by a tracked thread: that
//!   thread (the lock holder, the writer, the readiness source), in any tracked process,
//!   including other threads of the same one. A `futex` or `poll` wait that ended without a
//!   tracked waker (a timeout) and was retried at once is part of the next wait and takes
//!   its waker (`Walker::retried_waker`);
//! - waiting for a child (`wait4`/`waitid`): the child process that ended the wait (the
//!   waker when it is a child, else the child that exited last inside the block, else the
//!   youngest child still alive at its end), along its main thread;
//! - a `clone`/`clone3`/`vfork` block ended by a child (`CLONE_VFORK`, as `posix_spawn`
//!   uses): that child, which runs in its parent's memory until it execs or exits.
//!
//! Time a followed task does not cover (before its birth, after its death) stays with the
//! waiting block. A waker of 0 (unknown, or raised from interrupt context) is never followed.
//! Neither is a task already being walked further out (mutual waits) nor anything deeper than
//! [`MAX_DEPTH`]: the block then keeps its own class.
//!
//! The walk produces [`Span`]s that partition the window in time order; report lines sum
//! them by class and subject. A subject naming a process is its `comm`, unless processes
//! with different arguments share that `comm` on the path: then each is named by the
//! shortest suffix of its arguments that tells them apart (`sort -R`, `sort -n`; see
//! [`tell_apart`]). Runqueue lines say who held the CPU meanwhile ([`Line::held_by`]).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Serialize;

use crate::classify::{Class, Subject};
use crate::timeline::{Block, HolderId, ProcId, Seg, SegKind, ThreadId, Trace};

/// Deepest follow; deeper blocks keep their own class.
const MAX_DEPTH: u32 = 64;

/// A wait retried after less than `1 / RETRY_CPU_DIVISOR` of it on-CPU continues it.
const RETRY_CPU_DIVISOR: u64 = 8;

/// Most argument variants of one `comm` named apart; more (a build's many compiler runs)
/// stay one line.
const MAX_VARIANTS: usize = 4;

/// Longest argument suffix in a variant's name, in characters.
const MAX_SUFFIX_CHARS: usize = 40;

/// One report line before rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// Resource class.
    pub class: Class,
    /// What within the class: a comm, directory, `ip:port`, or syscall.
    pub subject: String,
    /// Nanoseconds attributed.
    pub ns: u64,
    /// Distinct sockets behind a `net` line.
    pub connections: Option<usize>,
    /// `runqueue` lines: who held the CPU meanwhile, largest first. Time without a recorded
    /// holder is in none of them.
    pub held_by: Vec<Held>,
}

/// A task that held a CPU the critical path waited for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Held {
    /// The process's `comm` for a traced holder; else the holding thread's, `idle` for an
    /// idle CPU.
    pub comm: String,
    /// Thread-group id; 0 for an idle CPU.
    pub tgid: u32,
    /// Nanoseconds of the line.
    pub ns: u64,
}

/// One stretch of the critical path: `[start, end)` of the window, explained by `thread`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    /// Start, `CLOCK_MONOTONIC` nanoseconds.
    pub start: u64,
    /// End, exclusive.
    pub end: u64,
    /// Resource class.
    pub class: Class,
    /// What within the class, as in [`Line::subject`].
    pub subject: String,
    /// Process of `thread`.
    pub proc: ProcId,
    /// Thread whose timeline the stretch comes from.
    pub thread: ThreadId,
    /// Follows from the wrapped command's main line to `thread` (0: the main line itself).
    pub depth: u32,
    /// `runqueue` spans: the task the kernel saw holding the CPU, when recorded.
    pub holder: Option<HolderId>,
}

/// The attributed window.
#[derive(Debug)]
pub struct Attribution {
    /// Lines, largest first: the spans summed by class and subject, so their `ns` sum to the
    /// window length.
    pub lines: Vec<Line>,
    /// The critical path in time order: each span starts where the previous one ends, from
    /// the window's start to its end. Adjacent stretches with equal fields are one span.
    /// Within a mixed segment, whose on-CPU and preempted time interleave in unknown order,
    /// the on-CPU part comes first.
    pub spans: Vec<Span>,
}

impl Attribution {
    /// Processes the critical path passed through.
    pub fn critical(&self) -> HashSet<ProcId> {
        self.spans.iter().map(|span| span.proc).collect()
    }
}

/// Attributes `[start, end)` of the root process `root`.
pub fn attribute(trace: &Trace, root: ProcId, start: u64, end: u64) -> Attribution {
    let mut walker = Walker {
        trace,
        root,
        by_tgid: HashMap::new(),
        by_tid: HashMap::new(),
        parents: vec![None; trace.procs.len()],
        pieces: Vec::new(),
        sockets: HashMap::new(),
        stack: Vec::new(),
        retries: HashMap::new(),
    };
    for (id, proc) in trace.procs.iter().enumerate() {
        walker.by_tgid.entry(proc.key.pid).or_default().push(id);
        for &child in &proc.children {
            walker.parents[child] = Some(id);
        }
    }
    for (id, thread) in trace.threads.iter().enumerate() {
        walker.by_tid.entry(thread.tid).or_default().push(id);
    }
    walker.walk_proc(root, start, end, 0);
    let pieces = std::mem::take(&mut walker.pieces);

    let names = names(trace, &pieces);
    let mut spans: Vec<Span> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        let subject = match piece.subject {
            Named::Text(text) => text,
            Named::Image(p, i) => names[&(p, i)].clone(),
        };
        // Images named alike join again (one process's consecutive programs, say).
        if let Some(last) = spans.last_mut()
            && (last.class, last.proc, last.thread, last.depth, last.holder)
                == (piece.class, piece.at.proc, piece.at.thread, piece.at.depth, piece.holder)
            && last.subject == subject
        {
            last.end = piece.end;
            continue;
        }
        spans.push(Span {
            start: piece.start,
            end: piece.end,
            class: piece.class,
            subject,
            proc: piece.at.proc,
            thread: piece.at.thread,
            depth: piece.at.depth,
            holder: piece.holder,
        });
    }

    let mut totals: HashMap<(Class, &str), (u64, HashMap<(u32, Arc<str>), u64>)> =
        HashMap::new();
    for span in &spans {
        let len = span.end - span.start;
        let (ns, holders) = totals.entry((span.class, &span.subject)).or_default();
        *ns += len;
        if let Some(holder) = span.holder {
            *holders.entry(walker.holder_name(holder, span.start)).or_default() += len;
        }
    }
    let mut lines: Vec<Line> = totals
        .into_iter()
        .map(|((class, subject), (ns, holders))| {
            let mut held_by: Vec<Held> = holders
                .into_iter()
                .map(|((tgid, comm), ns)| Held {
                    comm: comm.to_string(),
                    tgid,
                    ns,
                })
                .collect();
            held_by.sort_by(|a, b| {
                b.ns.cmp(&a.ns)
                    .then_with(|| (&a.comm, a.tgid).cmp(&(&b.comm, b.tgid)))
            });
            Line {
                class,
                subject: subject.to_owned(),
                ns,
                connections: walker
                    .sockets
                    .get(subject)
                    .map(HashSet::len)
                    .filter(|_| class == Class::Net),
                held_by,
            }
        })
        .collect();
    lines.sort_by(|a, b| {
        b.ns.cmp(&a.ns)
            .then_with(|| (a.class, &a.subject).cmp(&(b.class, &b.subject)))
    });
    Attribution { lines, spans }
}

/// Names for the process images that name spans: each one's `comm`, unless processes with
/// different arguments share it ([`tell_apart`]).
fn names(trace: &Trace, pieces: &[Piece]) -> HashMap<(ProcId, usize), String> {
    let images: HashSet<(ProcId, usize)> = pieces
        .iter()
        .filter_map(|piece| match piece.subject {
            Named::Image(p, i) => Some((p, i)),
            Named::Text(_) => None,
        })
        .collect();
    let mut by_comm: HashMap<&str, Vec<(ProcId, usize)>> = HashMap::new();
    for &(p, i) in &images {
        by_comm
            .entry(&trace.procs[p].images[i].comm)
            .or_default()
            .push((p, i));
    }
    let mut names = HashMap::with_capacity(images.len());
    for (comm, group) in by_comm {
        let told = tell_apart(trace, comm, &group);
        names.extend(group.into_iter().zip(told));
    }
    names
}

/// What tells an image's process apart from others with the same `comm`.
#[derive(PartialEq, Eq, Hash)]
enum Key<'a> {
    /// Its arguments after `argv[0]`.
    Args(Vec<Cow<'a, str>>),
    /// Its argument bytes, cut short in kernel: equal ones may differ beyond the cut (or be
    /// a fork that has not exec'd yet, which inherited its parent's).
    Cut(&'a [u8]),
    /// Unknown arguments: the pid alone.
    Pid(u32),
}

/// Names for `group`, images that all have `comm`. Images of one process, or whose argument
/// lists (after `argv[0]`) are all equal, are just `comm`; so are more than
/// [`MAX_VARIANTS`] variants. Otherwise each is `comm` plus the shortest suffix of its
/// arguments that tells the variants apart (one length for all, at most
/// [`MAX_SUFFIX_CHARS`] shown), or `comm[pid]` (the lowest pid of its variant) when its
/// arguments are unknown or were cut short in kernel, or its suffix would read like another
/// variant's.
fn tell_apart(trace: &Trace, comm: &str, group: &[(ProcId, usize)]) -> Vec<String> {
    let plain = || vec![comm.to_owned(); group.len()];
    if group.iter().all(|&(p, _)| p == group[0].0) {
        return plain();
    }
    let keys: Vec<Key<'_>> = group
        .iter()
        .map(|&(p, i)| {
            let image = &trace.procs[p].images[i];
            if image.argv.is_empty() {
                Key::Pid(trace.procs[p].key.pid)
            } else if image.argv_truncated {
                Key::Cut(&image.argv)
            } else {
                Key::Args(image.args().map(String::from_utf8_lossy).collect())
            }
        })
        .collect();
    let mut lowest: HashMap<&Key<'_>, u32> = HashMap::new();
    for (key, &(p, _)) in keys.iter().zip(group) {
        let pid = trace.procs[p].key.pid;
        lowest.entry(key).and_modify(|low| *low = pid.min(*low)).or_insert(pid);
    }
    if lowest.len() < 2 || lowest.len() > MAX_VARIANTS {
        return plain();
    }
    let lists: Vec<&[Cow<'_, str>]> = lowest
        .keys()
        .filter_map(|key| match key {
            Key::Args(args) => Some(args.as_slice()),
            Key::Cut(_) | Key::Pid(_) => None,
        })
        .collect();
    let longest = lists.iter().map(|args| args.len()).max().unwrap_or(0);
    let suffix = |args: &[Cow<'_, str>], k: usize| args.len().saturating_sub(k);
    let k = (1..=longest)
        .find(|&k| {
            let mut seen = HashSet::new();
            lists.iter().all(|args| seen.insert(&args[suffix(args, k)..]))
        })
        .unwrap_or(longest);
    let by_pid = |key: &Key<'_>| format!("{comm}[{}]", lowest[key]);
    let mut names: Vec<String> = keys
        .iter()
        .map(|key| match key {
            Key::Args(args) => variant(comm, &args[suffix(args, k)..], suffix(args, k) > 0),
            Key::Cut(_) | Key::Pid(_) => by_pid(key),
        })
        .collect();
    // Suffixes cut to the same characters: those variants fall back to the pid.
    let mut owner: HashMap<&str, &Key<'_>> = HashMap::new();
    let mut clashes = HashSet::new();
    for (name, key) in names.iter().zip(&keys) {
        if *owner.entry(name).or_insert(key) != key {
            clashes.insert(name.clone());
        }
    }
    for (name, key) in names.iter_mut().zip(&keys) {
        if clashes.contains(name) {
            *name = by_pid(key);
        }
    }
    names
}

/// `comm` and the argument suffix `shown`; `elided` when arguments before it are left out.
fn variant(comm: &str, shown: &[Cow<'_, str>], elided: bool) -> String {
    if shown.is_empty() {
        return comm.to_owned();
    }
    let tail = shown.join(" ");
    let chars = tail.chars().count();
    if chars > MAX_SUFFIX_CHARS {
        let kept: String = tail.chars().skip(chars - MAX_SUFFIX_CHARS).collect();
        format!("{comm} …{kept}")
    } else if elided {
        format!("{comm} … {tail}")
    } else {
        format!("{comm} {tail}")
    }
}

/// The thread a span's time comes from.
#[derive(Clone, Copy, PartialEq, Eq)]
struct At {
    proc: ProcId,
    thread: ThreadId,
    depth: u32,
}

/// A span's subject as the walk forms it.
#[derive(Clone, PartialEq, Eq)]
enum Named {
    /// Final text.
    Text(String),
    /// The `comm` of image `.1` of process `.0`, named once every image on the path is known
    /// ([`names`]).
    Image(ProcId, usize),
}

/// A [`Span`] whose subject is not final yet.
struct Piece {
    start: u64,
    end: u64,
    class: Class,
    subject: Named,
    at: At,
    holder: Option<HolderId>,
}

/// What explains a block.
#[derive(Clone, Copy)]
enum Target {
    /// One thread over the block: a futex, pipe or readiness waker.
    Thread(ThreadId),
    /// A process along its main line: a child waited for.
    Proc(ProcId),
}

struct Walker<'a> {
    trace: &'a Trace,
    /// The wrapped command: on-CPU time is `cpu` in it, `child` anywhere else.
    root: ProcId,
    /// Every process lifetime that had a given tgid.
    by_tgid: HashMap<u32, Vec<ProcId>>,
    /// Every thread that had a given tid.
    by_tid: HashMap<u32, Vec<ThreadId>>,
    /// Parent of each process, when it was traced.
    parents: Vec<Option<ProcId>>,
    pieces: Vec<Piece>,
    /// Distinct socket inodes per `net` subject.
    sockets: HashMap<String, HashSet<u64>>,
    /// Threads being walked, outermost first. Each is blocked over the interval walked inside
    /// it, so following one again would loop (A waits on B while B waits on A).
    stack: Vec<ThreadId>,
    /// Waker of each retried wait looked up so far, by thread and segment index.
    retries: HashMap<(ThreadId, usize), Option<ThreadId>>,
}

impl Walker<'_> {
    /// Appends `[start, end)`, merged into the previous piece when every field matches.
    fn emit(&mut self, at: At, start: u64, end: u64, class: Class, subject: Named) {
        self.emit_held(at, start, end, (class, subject), None);
    }

    /// [`emit`](Self::emit) with the CPU holder of a `runqueue` stretch.
    fn emit_held(
        &mut self,
        at: At,
        start: u64,
        end: u64,
        (class, subject): (Class, Named),
        holder: Option<HolderId>,
    ) {
        if start >= end {
            return;
        }
        debug_assert!(self.pieces.last().is_none_or(|last| last.end == start));
        if let Some(last) = self.pieces.last_mut()
            && (last.class, last.at, last.holder) == (class, at, holder)
            && last.subject == subject
        {
            last.end = end;
            return;
        }
        self.pieces.push(Piece {
            start,
            end,
            class,
            subject,
            at,
            holder,
        });
    }

    /// Time no record accounts for (lost records, or past the last sweep).
    fn untraced(&mut self, at: At, from: u64, to: u64) {
        if from < to {
            self.emit(at, from, to, Class::Other, Named::Text("untraced".to_owned()));
        }
    }

    /// The holder `id` as `(tgid, comm)` at `ts`: a traced process by its own `comm`.
    fn holder_name(&self, id: HolderId, ts: u64) -> (u32, Arc<str>) {
        let holder = self.trace.holder(id);
        let procs = &self.trace.procs;
        let comm = self
            .process_at(holder.tgid, ts)
            .filter(|&p| procs[p].death.is_none_or(|death| death >= ts))
            .map_or(&holder.comm, |p| procs[p].comm_at(ts));
        (holder.tgid, Arc::clone(comm))
    }

    /// Walks `[a, b)` of process `p` (which has a thread) along its main line, `depth`
    /// follows below the wrapped command's.
    fn walk_proc(&mut self, p: ProcId, a: u64, b: u64, depth: u32) {
        let mut cursor = a;
        let mut last = self.trace.procs[p].threads[0];
        for (thread, from, to) in self.main_line(p) {
            let (lo, hi) = (from.max(cursor), to.min(b));
            if lo >= hi {
                continue;
            }
            self.untraced(At { proc: p, thread: last, depth }, cursor, lo);
            self.walk_thread(thread, lo, hi, depth);
            (cursor, last) = (hi, thread);
        }
        self.untraced(At { proc: p, thread: last, depth }, cursor, b);
    }

    /// Walks `[a, b)` of thread `t`.
    fn walk_thread(&mut self, t: ThreadId, a: u64, b: u64, depth: u32) {
        let thread = &self.trace.threads[t];
        let at = At {
            proc: thread.proc,
            thread: t,
            depth,
        };
        self.stack.push(t);
        let mut cursor = a;
        let segs = &thread.segs;
        let first = segs.partition_point(|s| s.end <= a);
        for (index, seg) in segs.iter().enumerate().skip(first) {
            if seg.start >= b {
                break;
            }
            let (s0, s1) = (seg.start.max(cursor), seg.end.min(b));
            if s0 >= s1 {
                continue;
            }
            self.untraced(at, cursor, s0);
            self.segment(at, index, s0, s1);
            cursor = s1;
        }
        self.untraced(at, cursor, b);
        self.stack.pop();
    }

    /// The thread that stands for the process at each moment: the original leader while it
    /// lives, then whichever thread alive at that point lives longest (the one that took over
    /// the leader's identity in a multithreaded exec, or the last to exit).
    fn main_line(&self, p: ProcId) -> Vec<(ThreadId, u64, u64)> {
        let proc = &self.trace.procs[p];
        let end = proc.death.unwrap_or(u64::MAX);
        let lives = |t: ThreadId| {
            let thread = &self.trace.threads[t];
            (thread.birth, thread.death.unwrap_or(u64::MAX).min(end))
        };
        let mut line = Vec::new();
        let mut cursor = proc.birth;
        let mut current = proc.threads.first().copied();
        while let Some(thread) = current {
            let (_, death) = lives(thread);
            if death > cursor {
                line.push((thread, cursor, death));
                cursor = death;
            }
            if cursor >= end {
                break;
            }
            current = proc
                .threads
                .iter()
                .copied()
                .filter(|&t| t != thread && !line.iter().any(|&(seen, ..)| seen == t))
                .filter(|&t| {
                    let (birth, death) = lives(t);
                    birth <= cursor && death > cursor
                })
                .max_by_key(|&t| lives(t).1);
        }
        line
    }

    fn segment(&mut self, at: At, index: usize, s0: u64, s1: u64) {
        let trace = self.trace;
        let seg = &trace.threads[at.thread].segs[index];
        let image = Named::Image(at.proc, trace.procs[at.proc].image_at(s0));
        let len = s1 - s0;
        match &seg.kind {
            &SegKind::Mixed { run, rq, holder } => {
                let cpu = if run + rq == 0 {
                    len
                } else {
                    u64::try_from(u128::from(len) * u128::from(run) / u128::from(run + rq))
                        .unwrap_or(len)
                };
                let class = if at.proc == self.root {
                    Class::Cpu
                } else {
                    Class::Child
                };
                if cpu < len {
                    self.emit(at, s0, s0 + cpu, class, image.clone());
                    // Preempted: blame the longest preemption's holder for all of it.
                    self.emit_held(at, s0 + cpu, s1, (Class::Runqueue, image), holder);
                } else {
                    self.emit(at, s0, s1, class, image);
                }
            }
            &SegKind::Runq(holder) => {
                self.emit_held(at, s0, s1, (Class::Runqueue, image), holder);
            }
            SegKind::Blocked(block) => self.blocked(at, index, block, s0, s1),
        }
    }

    /// Attributes `[s0, s1)` of `block`, segment `index` of `at`'s thread, to the task that
    /// explains it, if one is known.
    fn blocked(&mut self, at: At, index: usize, block: &Block, s0: u64, s1: u64) {
        let trace = self.trace;
        let seg = &trace.threads[at.thread].segs[index];
        let latest = |p: ProcId| Named::Image(p, trace.procs[p].images.len() - 1);
        let explained = match block.what.class {
            Class::Child => {
                let Some(child) = self.child_for(at.proc, seg, block.waker_tgid) else {
                    let unknown = Named::Text("unknown child".to_owned());
                    self.emit(at, s0, s1, Class::Child, unknown);
                    return;
                };
                Some((Target::Proc(child), (Class::Child, latest(child))))
            }
            class @ (Class::Futex | Class::Ipc | Class::Poll) => {
                let waker = match self.thread_at(block.waker_tid, block.waker_tgid, seg.end) {
                    None if class != Class::Ipc => self.retried_waker(at.thread, index, class),
                    waker => waker,
                };
                waker.map(|waker| (Target::Thread(waker), self.own_line(at, block, s0)))
            }
            _ if spawns(&block.what.subject) => self
                .process_at(block.waker_tgid, seg.end)
                .filter(|&child| self.parents[child] == Some(at.proc))
                .map(|child| (Target::Proc(child), (Class::Child, latest(child)))),
            _ => None,
        };
        match explained {
            Some((target, waiting)) => self.follow(at, target, s0, s1, waiting),
            None => {
                let (class, subject) = self.own_line(at, block, s0);
                if let (Some(socket), Named::Text(text)) = (block.what.socket, &subject) {
                    self.sockets
                        .entry(text.clone())
                        .or_default()
                        .insert(socket);
                }
                self.emit(at, s0, s1, class, subject);
            }
        }
    }

    /// Explains `[s0, s1)` of a block at `at` by walking `target` over it. Time outside the
    /// target's life goes to `waiting` (class and subject), and so does all of it when the
    /// target is already being walked or the walk is [`MAX_DEPTH`] deep.
    fn follow(&mut self, at: At, target: Target, s0: u64, s1: u64, waiting: (Class, Named)) {
        let trace = self.trace;
        let (birth, death, busy) = match target {
            Target::Thread(t) => {
                let thread = &trace.threads[t];
                let proc_death = trace.procs[thread.proc].death;
                let death = thread.death.into_iter().chain(proc_death).min();
                (thread.birth, death, self.stack.contains(&t))
            }
            Target::Proc(q) => {
                let proc = &trace.procs[q];
                let busy = proc.threads.is_empty()
                    || proc.threads.iter().any(|t| self.stack.contains(t));
                (proc.birth, proc.death, busy)
            }
        };
        let (lo, hi) = (s0.max(birth), s1.min(death.unwrap_or(u64::MAX)));
        let (class, subject) = waiting;
        if busy || at.depth >= MAX_DEPTH || lo >= hi {
            self.emit(at, s0, s1, class, subject);
            return;
        }
        if s0 < lo {
            self.emit(at, s0, lo, class, subject.clone());
        }
        match target {
            Target::Thread(t) => self.walk_thread(t, lo, hi, at.depth + 1),
            Target::Proc(q) => self.walk_proc(q, lo, hi, at.depth + 1),
        }
        self.emit(at, hi, s1, class, subject);
    }

    /// A block's own class and subject: the classified subject, or the blocked process.
    fn own_line(&self, at: At, block: &Block, ts: u64) -> (Class, Named) {
        let subject = match &block.what.subject {
            Subject::Process => Named::Image(at.proc, self.trace.procs[at.proc].image_at(ts)),
            other => Named::Text(other.to_string()),
        };
        (block.what.class, subject)
    }

    /// The child of `p` whose state change ended the wait `seg`.
    fn child_for(&self, p: ProcId, seg: &Seg, waker_tgid: u32) -> Option<ProcId> {
        let procs = &self.trace.procs;
        if let Some(waker) = self.process_at(waker_tgid, seg.end)
            && self.parents[waker] == Some(p)
        {
            return Some(waker);
        }
        let children = &procs[p].children;
        let exited = children
            .iter()
            .copied()
            .filter(|&c| {
                procs[c]
                    .death
                    .is_some_and(|d| d >= seg.start && d <= seg.end)
            })
            .max_by_key(|&c| procs[c].death);
        exited.or_else(|| {
            children
                .iter()
                .copied()
                .filter(|&c| {
                    procs[c].birth <= seg.end && procs[c].death.is_none_or(|d| d > seg.end)
                })
                .max_by_key(|&c| procs[c].birth)
        })
    }

    /// The latest process with thread-group id `tgid` born by `ts`, dead or alive: a process
    /// can wake others while it exits (its parent, a pipe's reader), after its exit record.
    fn process_at(&self, tgid: u32, ts: u64) -> Option<ProcId> {
        if tgid == 0 {
            return None;
        }
        let procs = &self.trace.procs;
        self.by_tgid
            .get(&tgid)?
            .iter()
            .copied()
            .rev()
            .find(|&id| procs[id].birth <= ts)
    }

    /// The latest thread `tid` of process `tgid` born by `ts`, dead or alive (an exiting
    /// thread wakes its joiner).
    fn thread_at(&self, tid: u32, tgid: u32, ts: u64) -> Option<ThreadId> {
        if tid == 0 {
            return None;
        }
        let threads = &self.trace.threads;
        let thread = self
            .by_tid
            .get(&tid)?
            .iter()
            .copied()
            .rev()
            .find(|&t| threads[t].birth <= ts)?;
        (self.trace.procs[threads[thread].proc].key.pid == tgid).then_some(thread)
    }

    /// The waker of a retried wait. A `futex` or `poll` wait that no tracked thread ended (a
    /// timeout, typically) is one wait with the thread's next wait of the same `class` when
    /// the thread ran less than 1/[`RETRY_CPU_DIVISOR`] of the first in between: it
    /// re-checked and waited again (a timed condition wait, Python's GIL). The first wait of
    /// such a chain that a tracked thread ended names the waker of all of them.
    fn retried_waker(&mut self, t: ThreadId, index: usize, class: Class) -> Option<ThreadId> {
        if let Some(&waker) = self.retries.get(&(t, index)) {
            return waker;
        }
        let segs = &self.trace.threads[t].segs;
        let mut chain = vec![index];
        let mut wait = segs[index].end - segs[index].start;
        let mut ran = 0_u64;
        let mut waker = None;
        for (i, seg) in segs.iter().enumerate().skip(index + 1) {
            match &seg.kind {
                SegKind::Mixed { run, .. } => {
                    ran += run;
                    if ran.saturating_mul(RETRY_CPU_DIVISOR) >= wait {
                        break;
                    }
                }
                SegKind::Runq(_) => {}
                SegKind::Blocked(block) if block.what.class == class => {
                    waker = self.thread_at(block.waker_tid, block.waker_tgid, seg.end);
                    if waker.is_some() {
                        break;
                    }
                    if let Some(&known) = self.retries.get(&(t, i)) {
                        waker = known;
                        break;
                    }
                    chain.push(i);
                    (wait, ran) = (seg.end - seg.start, 0);
                }
                SegKind::Blocked(_) => break,
            }
        }
        for i in chain {
            self.retries.insert((t, i), waker);
        }
        waker
    }
}

/// Whether a block in this syscall can be a parent waiting for its `CLONE_VFORK` child.
fn spawns(subject: &Subject) -> bool {
    matches!(subject, Subject::Syscall("clone" | "clone3" | "vfork"))
}

#[cfg(test)]
mod tests {
    use libc::{SYS_nanosleep, SYS_wait4};
    use procctx::ProcKey;

    use super::*;
    use crate::classify::Blocked;
    use crate::testkit::{episode, exec, exit, feed, fork, seg, sys, trace};
    use crate::timeline::{Image, Proc, Thread};

    /// A program `comm` with arguments `argv` (space-separated; none when empty), exec'd at
    /// `from`.
    fn image(from: u64, comm: &str, argv: &str) -> Image {
        let words = argv.split(' ').filter(|arg| !arg.is_empty());
        let argv: Vec<u8> = words.flat_map(|arg| arg.bytes().chain([0])).collect();
        Image {
            from,
            comm: Arc::from(comm),
            argv: Arc::from(argv),
            argv_truncated: false,
            exec: true,
        }
    }

    /// Adds process `pid` running `comm` (argv `[comm]`) alive over `life`, `[birth, death)`.
    fn proc(
        t: &mut Trace,
        pid: u32,
        comm: &str,
        life: (u64, u64),
        parent: Option<ProcId>,
    ) -> ProcId {
        let id = t.procs.len();
        t.procs.push(Proc {
            key: ProcKey { pid, start: 0 },
            birth: life.0,
            death: Some(life.1),
            images: vec![image(life.0, comm, comm)],
            threads: Vec::new(),
            children: Vec::new(),
            cpu_ns: 0,
        });
        if let Some(parent) = parent {
            t.procs[parent].children.push(id);
        }
        id
    }

    /// Adds thread `tid` living exactly over `segs`.
    fn thread(t: &mut Trace, proc: ProcId, tid: u32, segs: Vec<Seg>) -> ThreadId {
        let id = t.threads.len();
        t.threads.push(Thread {
            tid,
            proc,
            birth: segs[0].start,
            death: segs.last().map(|s| s.end),
            segs,
        });
        t.procs[proc].threads.push(id);
        id
    }

    fn run(start: u64, end: u64) -> Seg {
        let kind = SegKind::Mixed {
            run: end - start,
            rq: 0,
            holder: None,
        };
        Seg { start, end, kind }
    }

    fn runq(start: u64, end: u64) -> Seg {
        let kind = SegKind::Runq(None);
        Seg { start, end, kind }
    }

    /// A block of `class` ended by thread `waker.0` of process `waker.1`.
    fn block(start: u64, end: u64, class: Class, subject: Subject, waker: (u32, u32)) -> Seg {
        let block = Block {
            what: Blocked {
                class,
                subject,
                socket: None,
            },
            waker_tid: waker.0,
            waker_tgid: waker.1,
            waker_comm: None,
            syscall: None,
        };
        let kind = SegKind::Blocked(Box::new(block));
        Seg { start, end, kind }
    }

    fn futex(start: u64, end: u64, waker: (u32, u32)) -> Seg {
        block(start, end, Class::Futex, Subject::Process, waker)
    }

    /// Checks that the spans tile `[start, end)` and the lines add up to it, and returns the
    /// lines as `(class, subject, ns)`.
    fn tiled(a: &Attribution, start: u64, end: u64) -> Vec<(Class, &str, u64)> {
        let mut cursor = start;
        for span in &a.spans {
            assert_eq!(span.start, cursor, "gap or overlap before {span:?}");
            assert!(span.end > span.start, "empty {span:?}");
            cursor = span.end;
        }
        assert_eq!(cursor, end);
        assert_eq!(a.lines.iter().map(|l| l.ns).sum::<u64>(), end - start);
        let mut lines: Vec<_> = a
            .lines
            .iter()
            .map(|l| (l.class, l.subject.as_str(), l.ns))
            .collect();
        lines.sort_unstable();
        lines
    }

    #[test]
    fn a_lock_held_across_a_sleep_is_the_holders_sleep() {
        let mut t = trace(1);
        let app = proc(&mut t, 10, "app", (0, 100), None);
        let main = vec![run(0, 10), futex(10, 90, (11, 10)), runq(90, 92), run(92, 100)];
        thread(&mut t, app, 10, main);
        let sleep = block(5, 88, Class::Sleep, Subject::Process, (0, 0));
        let holder = thread(&mut t, app, 11, vec![run(0, 5), sleep, runq(88, 89), run(89, 95)]);

        let a = attribute(&t, app, 0, 100);
        let lines = tiled(&a, 0, 100);
        assert_eq!(
            lines,
            [
                (Class::Cpu, "app", 19),
                (Class::Runqueue, "app", 3),
                (Class::Sleep, "app", 78),
            ]
        );
        let slept = a.spans.iter().find(|s| s.class == Class::Sleep).unwrap();
        assert_eq!((slept.thread, slept.depth, slept.start, slept.end), (holder, 1, 10, 88));
    }

    #[test]
    fn mutual_waits_terminate_in_the_waiting_class() {
        // Three threads each "woken" by the next, in a ring: no task explains the time.
        let mut t = trace(1);
        let app = proc(&mut t, 10, "app", (0, 100), None);
        thread(&mut t, app, 10, vec![futex(0, 100, (11, 10))]);
        thread(&mut t, app, 11, vec![futex(0, 100, (12, 10))]);
        let last = thread(&mut t, app, 12, vec![futex(0, 100, (10, 10))]);

        let a = attribute(&t, app, 0, 100);
        assert_eq!(tiled(&a, 0, 100), [(Class::Futex, "app", 100)]);
        assert_eq!((a.spans[0].thread, a.spans[0].depth), (last, 2));
    }

    #[test]
    fn descendants_compute_as_child_and_the_command_as_cpu() {
        // sh waits for cc; cc computes, then reads a pipe that another thread of sh fills.
        let mut t = trace(1);
        let sh = proc(&mut t, 10, "sh", (0, 100), None);
        let cc = proc(&mut t, 20, "cc", (0, 100), Some(sh));
        let wait = block(0, 100, Class::Child, Subject::Process, (20, 20));
        thread(&mut t, sh, 10, vec![wait]);
        thread(&mut t, sh, 11, vec![run(0, 100)]);
        let pipe = block(50, 100, Class::Ipc, Subject::Process, (11, 10));
        thread(&mut t, cc, 20, vec![run(0, 50), pipe]);

        let a = attribute(&t, sh, 0, 100);
        let lines = tiled(&a, 0, 100);
        assert_eq!(lines, [(Class::Cpu, "sh", 50), (Class::Child, "cc", 50)]);
        assert_eq!(a.critical(), HashSet::from([sh, cc]));
    }

    #[test]
    fn a_vfork_parent_waits_on_the_child_until_its_exec() {
        let mut t = trace(1);
        let py = proc(&mut t, 10, "py", (0, 100), None);
        let spawn = block(5, 60, Class::Other, Subject::Syscall("clone3"), (20, 20));
        thread(&mut t, py, 10, vec![run(0, 5), spawn, run(60, 100)]);
        let child = proc(&mut t, 20, "py", (4, 90), Some(py));
        t.procs[child].images.push(image(60, "true", "true"));
        thread(&mut t, child, 20, vec![run(4, 60), run(60, 90)]);

        let a = attribute(&t, py, 0, 100);
        let lines = tiled(&a, 0, 100);
        assert_eq!(lines, [(Class::Cpu, "py", 45), (Class::Child, "py", 55)]);
    }

    #[test]
    fn time_outside_the_wakers_life_keeps_the_blocks_class() {
        // The waker thread starts after the wait began and is followed only from its birth.
        let mut t = trace(1);
        let app = proc(&mut t, 10, "app", (0, 100), None);
        thread(&mut t, app, 10, vec![futex(0, 100, (11, 10))]);
        thread(&mut t, app, 11, vec![run(30, 100)]);

        let a = attribute(&t, app, 0, 100);
        let lines = tiled(&a, 0, 100);
        assert_eq!(lines, [(Class::Cpu, "app", 70), (Class::Futex, "app", 30)]);
    }

    #[test]
    fn timed_out_waits_retried_at_once_belong_to_the_wake_that_ends_them() {
        // Two waits time out (no waker), each re-checked in 1 ns; the third is ended by the
        // worker, which computed all along.
        let mut t = trace(1);
        let app = proc(&mut t, 10, "app", (0, 110), None);
        let main = vec![
            futex(0, 40, (0, 0)),
            run(40, 41),
            futex(41, 80, (0, 0)),
            run(80, 81),
            futex(81, 100, (11, 10)),
            run(100, 110),
        ];
        thread(&mut t, app, 10, main);
        thread(&mut t, app, 11, vec![run(0, 100)]);

        let a = attribute(&t, app, 0, 110);
        assert_eq!(tiled(&a, 0, 110), [(Class::Cpu, "app", 110)]);
    }

    #[test]
    fn work_between_waits_ends_the_retry() {
        // The first wait times out and the thread works for most of its length before
        // waiting again: the first wait stays unexplained.
        let mut t = trace(1);
        let app = proc(&mut t, 10, "app", (0, 100), None);
        let main = vec![futex(0, 40, (0, 0)), run(40, 70), futex(70, 100, (11, 10))];
        thread(&mut t, app, 10, main);
        let sleep = block(0, 100, Class::Sleep, Subject::Process, (0, 0));
        thread(&mut t, app, 11, vec![sleep]);

        let a = attribute(&t, app, 0, 100);
        let lines = tiled(&a, 0, 100);
        assert_eq!(
            lines,
            [
                (Class::Cpu, "app", 30),
                (Class::Sleep, "app", 30),
                (Class::Futex, "app", 40),
            ]
        );
    }

    /// Nanoseconds of the line `(class, subject)`.
    fn ns(attribution: &Attribution, class: Class, subject: &str) -> u64 {
        attribution
            .lines
            .iter()
            .filter(|line| line.class == class && line.subject == subject)
            .map(|line| line.ns)
            .sum()
    }

    fn total(attribution: &Attribution) -> u64 {
        attribution.lines.iter().map(|line| line.ns).sum()
    }

    #[test]
    fn lines_partition_the_window_and_clip_mixed_segments_proportionally() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        let sleep = sys(SYS_nanosleep);
        feed(&mut t, &episode(100, 100, seg(1_000, 300, 100), sleep, [1_400, 2_000, 2_100]));
        feed(&mut t, &exit(3_000, 100, 100, seg(2_100, 900, 0), 0, true));

        let whole = attribute(&t, 0, 1_000, 3_000);
        assert_eq!(total(&whole), 2_000);
        assert_eq!(ns(&whole, Class::Cpu, "app"), 1_200);
        assert_eq!(ns(&whole, Class::Runqueue, "app"), 200);
        assert_eq!(ns(&whole, Class::Sleep, "app"), 600);

        // Half of the first segment: on-CPU and preempted keep their 3:1 ratio.
        let clipped = attribute(&t, 0, 1_200, 2_050);
        assert_eq!(total(&clipped), 850);
        assert_eq!(ns(&clipped, Class::Cpu, "app"), 150);
        assert_eq!(ns(&clipped, Class::Runqueue, "app"), 50 + 50);
        assert_eq!(ns(&clipped, Class::Sleep, "app"), 600);
    }

    #[test]
    fn a_wait_is_explained_by_the_child_that_woke_it() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "sh", seg(1_000, 0, 0)));
        feed(&mut t, &fork(1_100, 100, 100, 200, 200));
        feed(&mut t, &fork(1_200, 100, 100, 300, 300));
        feed(&mut t, &exec(1_300, 200, 200, "woke", seg(1_100, 200, 0)));
        feed(&mut t, &exec(1_300, 300, 300, "younger", seg(1_200, 100, 0)));
        // Both children outlive the wait; without the waker, the younger one would explain it.
        let mut wait = episode(100, 100, seg(1_000, 300, 0), sys(SYS_wait4), [1_300, 5_000, 5_000]);
        wait.waker_tid = 200;
        wait.waker_tgid = 200;
        feed(&mut t, &wait);
        feed(&mut t, &exit(6_000, 200, 200, seg(1_300, 4_700, 0), 0, true));
        feed(&mut t, &exit(7_000, 300, 300, seg(1_300, 5_700, 0), 0, true));
        feed(&mut t, &exit(8_000, 100, 100, seg(5_000, 3_000, 0), 0, true));

        let a = attribute(&t, 0, 1_000, 8_000);
        assert_eq!(total(&a), 7_000);
        assert_eq!(ns(&a, Class::Child, "woke"), 3_700);
        assert_eq!(ns(&a, Class::Child, "younger"), 0);
        assert_eq!(ns(&a, Class::Cpu, "sh"), 300 + 3_000);
    }

    #[test]
    fn time_no_record_covers_is_other_untraced() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        let sleep = sys(SYS_nanosleep);
        feed(&mut t, &episode(100, 100, seg(1_000, 100, 0), sleep, [1_100, 1_500, 1_500]));
        // The episode covering [1500, 2500) was lost.
        feed(&mut t, &episode(100, 100, seg(2_500, 100, 0), sleep, [2_600, 3_000, 3_000]));
        feed(&mut t, &exit(4_000, 100, 100, seg(3_000, 1_000, 0), 0, true));

        let a = attribute(&t, 0, 1_000, 4_000);
        assert_eq!(total(&a), 3_000);
        assert_eq!(ns(&a, Class::Other, "untraced"), 1_000);
        assert_eq!(ns(&a, Class::Cpu, "app"), 1_200);
        assert_eq!(ns(&a, Class::Sleep, "app"), 800);
        // Past the last record of the process, too.
        let longer = attribute(&t, 0, 1_000, 4_500);
        assert_eq!(ns(&longer, Class::Other, "untraced"), 1_500);
    }

    #[test]
    fn each_program_of_an_exec_chain_is_named_by_its_own_comm() {
        // `make` runs a `bash` wrapper that execs `git`, and waits for it.
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "make", seg(1_000, 0, 0)));
        feed(&mut t, &fork(1_100, 100, 100, 200, 200));
        feed(&mut t, &exec(1_300, 200, 200, "bash", seg(1_100, 200, 0)));
        feed(&mut t, &exec(3_300, 200, 200, "git", seg(1_300, 2_000, 0)));
        feed(&mut t, &exit(8_000, 200, 200, seg(3_300, 4_700, 0), 0, true));
        let wait = sys(SYS_wait4);
        feed(&mut t, &episode(100, 100, seg(1_000, 100, 0), wait, [1_100, 9_000, 9_000]));
        feed(&mut t, &exit(10_000, 100, 100, seg(9_000, 1_000, 0), 0, true));

        let a = attribute(&t, 0, 1_000, 10_000);
        assert_eq!(total(&a), 9_000);
        assert_eq!(ns(&a, Class::Cpu, "make"), 100 + 1_000);
        // Before its exec the child still carries its parent's comm.
        assert_eq!(ns(&a, Class::Child, "make"), 200);
        assert_eq!(ns(&a, Class::Child, "bash"), 2_000);
        // git's own CPU, then the wait after it exited, until make ran again.
        assert_eq!(ns(&a, Class::Child, "git"), 4_700 + 1_000);
    }

    /// A child wait of the root's main thread over `[start, end)`, ended by process `pid`.
    fn wait(start: u64, end: u64, pid: u32) -> Seg {
        block(start, end, Class::Child, Subject::Process, (pid, pid))
    }

    #[test]
    fn processes_sharing_a_comm_are_told_apart_by_their_arguments() {
        // sh runs `sort -R`, `sort -n` and `sort -R` again, one after another; tail, alone
        // with its comm, keeps it.
        let mut t = trace(1);
        let sh = proc(&mut t, 10, "sh", (0, 100), None);
        let waits = vec![wait(0, 30, 20), wait(30, 60, 30), wait(60, 90, 40), wait(90, 100, 50)];
        thread(&mut t, sh, 10, waits);
        for (pid, argv, life) in [
            (20, "sort -R", (0, 30)),
            (30, "sort -n", (30, 60)),
            (40, "sort -R", (60, 90)),
            (50, "tail -1", (90, 100)),
        ] {
            let comm = &argv[..4];
            let p = proc(&mut t, pid, comm, life, Some(sh));
            t.procs[p].images[0] = image(life.0, comm, argv);
            thread(&mut t, p, pid, vec![run(life.0, life.1)]);
        }

        let a = attribute(&t, sh, 0, 100);
        let lines = tiled(&a, 0, 100);
        assert_eq!(
            lines,
            [
                (Class::Child, "sort -R", 60),
                (Class::Child, "sort -n", 30),
                (Class::Child, "tail", 10),
            ]
        );
    }

    #[test]
    fn told_apart_names_use_one_shortest_suffix_or_the_pid() {
        let mut t = trace(1);
        let mut make = |pid: u32, argv: &str| {
            let p = proc(&mut t, pid, "make", (0, 1), None);
            t.procs[p].images[0] = image(0, "make", argv);
            (p, 0)
        };
        // The last argument is common: two are needed, the one before them elided.
        let sub = [make(1, "make -C lib all"), make(2, "make -C app all")];
        let unknown = make(3, "");
        let long = make(4, &format!("make {}", "x".repeat(50)));
        let fleet: Vec<_> = (5..10).map(|pid| make(pid, &format!("make t{pid}"))).collect();
        let same = [make(10, "make -j4"), make(11, "make -j4")];
        // Arguments cut short in kernel: a fork inherits the same bytes as its parent's.
        let cut = [make(13, "make -f a"), make(12, "make -f a"), make(14, "make -f b")];
        for &(p, i) in &cut {
            t.procs[p].images[i].argv_truncated = true;
        }

        assert_eq!(tell_apart(&t, "make", &sub), ["make … lib all", "make … app all"]);
        // Unknown arguments: the pid; a suffix past MAX_SUFFIX_CHARS keeps its end.
        assert_eq!(
            tell_apart(&t, "make", &[sub[0], unknown, long]),
            [
                "make … all".to_owned(),
                "make[3]".to_owned(),
                format!("make …{}", "x".repeat(MAX_SUFFIX_CHARS)),
            ]
        );
        // More variants than MAX_VARIANTS, or none: the comm alone.
        assert!(tell_apart(&t, "make", &fleet).iter().all(|name| name == "make"));
        assert_eq!(tell_apart(&t, "make", &same), ["make", "make"]);
        assert_eq!(tell_apart(&t, "make", &cut[..2]), ["make", "make"]);
        assert_eq!(tell_apart(&t, "make", &cut), ["make[12]", "make[12]", "make[14]"]);
        // Two programs of one process are never split.
        let p = sub[0].0;
        t.procs[p].images.push(image(5, "make", "make install"));
        assert_eq!(tell_apart(&t, "make", &[(p, 0), (p, 1)]), ["make", "make"]);
    }

    #[test]
    fn runqueue_lines_name_who_held_the_cpu() {
        let mut t = trace(100);
        feed(&mut t, &exec(1_000, 100, 100, "app", seg(1_000, 0, 0)));
        feed(&mut t, &fork(1_100, 100, 100, 200, 200));
        feed(&mut t, &exec(1_100, 200, 200, "worker", seg(1_100, 0, 0)));
        let comm = |name: &str| {
            let mut raw = [0; 16];
            raw[..name.len()].copy_from_slice(name.as_bytes());
            raw
        };
        // Preempted 100 of 400 ns by an untraced chrome, then after a sleep 100 ns behind a
        // thread of the traced worker, whose own thread name the kernel reported.
        let mut ran = seg(1_000, 300, 100);
        (ran.preempt_max_ns, ran.preempt_tgid, ran.preempt_comm) = (100, 999, comm("chrome"));
        let mut slept = episode(100, 100, ran, sys(SYS_nanosleep), [1_400, 2_000, 2_100]);
        (slept.run_holder_tgid, slept.run_holder_comm) = (200, comm("wthread"));
        feed(&mut t, &slept);
        feed(&mut t, &exit(3_000, 100, 100, seg(2_100, 900, 0), 0, true));

        let a = attribute(&t, 0, 1_000, 3_000);
        let runqueue = a.lines.iter().find(|l| l.class == Class::Runqueue).unwrap();
        assert_eq!(runqueue.ns, 200);
        let held: Vec<_> = runqueue
            .held_by
            .iter()
            .map(|held| (held.comm.as_str(), held.tgid, held.ns))
            .collect();
        assert_eq!(held, [("chrome", 999, 100), ("worker", 200, 100)]);
        let others = a.lines.iter().filter(|l| l.class != Class::Runqueue);
        assert!(others.into_iter().all(|l| l.held_by.is_empty()));
    }
}
