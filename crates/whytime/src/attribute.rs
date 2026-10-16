//! Critical-path attribution: every nanosecond of the window goes to exactly one line.
//!
//! The walk follows the wrapped command's main thread through the window. On-CPU time of the
//! command's own process is `cpu`; preempted and woken-not-yet-running time is `runqueue`;
//! blocked time goes to the class of what it blocked on. Two kinds of block are explained by
//! another process instead, by descending into it for the same interval:
//!
//! - waiting for a child (`wait4`/`waitid`): the child that ended the wait (the waker when it
//!   is a child, else the child that exited last inside the block, else the youngest child
//!   still alive at its end);
//! - waiting on a pipe or local socket woken by another tracked process: that process.
//!
//! Inside a descendant the same rules apply recursively, except that its on-CPU time is
//! reported as `child` ("waiting on child: <comm>"): the command was waiting while a
//! descendant computed. Time a descendant does not cover (before its fork, after its exit)
//! stays with the waiting process's class. Futex waits are not followed (the lock holder is
//! not known), so a lock held across a sleep shows as `futex`, not `sleep`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::classify::{Class, Subject};
use crate::timeline::{ProcId, Seg, SegKind, ThreadId, Trace};

/// Deepest descent followed; deeper blocks are reported as their own class.
const MAX_DEPTH: u32 = 64;

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
}

/// The attributed window.
#[derive(Debug)]
pub struct Attribution {
    /// Lines, largest first; their `ns` sum to the window length.
    pub lines: Vec<Line>,
    /// Processes the walk passed through.
    pub critical: HashSet<ProcId>,
}

/// Attributes `[start, end)` of the root process `root`.
pub fn attribute(trace: &Trace, root: ProcId, start: u64, end: u64) -> Attribution {
    let mut walker = Walker {
        trace,
        by_tgid: HashMap::new(),
        acc: HashMap::new(),
        sockets: HashMap::new(),
        critical: HashSet::new(),
    };
    for (id, proc) in trace.procs.iter().enumerate() {
        walker.by_tgid.entry(proc.key.pid).or_default().push(id);
    }
    walker.walk(root, start, end, 0);

    let Walker { acc, sockets, critical, .. } = walker;
    let mut lines: Vec<Line> = acc
        .into_iter()
        .map(|((class, subject), ns)| {
            let connections = sockets.get(&subject).map(HashSet::len).filter(|_| class == Class::Net);
            Line {
                class,
                subject,
                ns,
                connections,
            }
        })
        .collect();
    lines.sort_by(|a, b| b.ns.cmp(&a.ns).then_with(|| (a.class, &a.subject).cmp(&(b.class, &b.subject))));
    Attribution { lines, critical }
}

struct Walker<'a> {
    trace: &'a Trace,
    /// Every process lifetime that had a given tgid.
    by_tgid: HashMap<u32, Vec<ProcId>>,
    acc: HashMap<(Class, String), u64>,
    /// Distinct socket inodes per `net` subject.
    sockets: HashMap<String, HashSet<u64>>,
    critical: HashSet<ProcId>,
}

impl Walker<'_> {
    fn add(&mut self, class: Class, subject: String, ns: u64) {
        if ns > 0 {
            *self.acc.entry((class, subject)).or_default() += ns;
        }
    }

    /// Attributes `[a, b)` of process `p`, `depth` descents below the wrapped command.
    fn walk(&mut self, p: ProcId, a: u64, b: u64, depth: u32) {
        if a >= b {
            return;
        }
        self.critical.insert(p);
        let trace = self.trace;
        let mut cursor = a;
        for (thread, from, to) in self.main_line(p) {
            let (lo, hi) = (a.max(from), b.min(to));
            if lo >= hi {
                continue;
            }
            let segs = &trace.threads[thread].segs;
            let first = segs.partition_point(|s| s.end <= lo);
            for seg in &segs[first..] {
                if seg.start >= hi {
                    break;
                }
                let (s0, s1) = (seg.start.max(lo).max(cursor), seg.end.min(hi));
                if s0 >= s1 {
                    continue;
                }
                self.untraced(cursor, s0);
                self.segment(p, seg, s0, s1, depth);
                cursor = s1;
            }
        }
        self.untraced(cursor, b);
    }

    /// Time no thread of a process accounts for (lost records, or past the last sweep).
    fn untraced(&mut self, from: u64, to: u64) {
        if to > from {
            self.add(Class::Other, "untraced".to_owned(), to - from);
        }
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

    fn segment(&mut self, p: ProcId, seg: &Seg, s0: u64, s1: u64, depth: u32) {
        let trace = self.trace;
        let comm = || trace.procs[p].comm_at(s0).to_string();
        let len = s1 - s0;
        match &seg.kind {
            SegKind::Mixed { run, rq } => {
                let cpu = if run + rq == 0 {
                    len
                } else {
                    u64::try_from(u128::from(len) * u128::from(*run) / u128::from(run + rq))
                        .unwrap_or(len)
                };
                let class = if depth == 0 { Class::Cpu } else { Class::Child };
                let comm = comm();
                self.add(Class::Runqueue, comm.clone(), len - cpu);
                self.add(class, comm, cpu);
            }
            SegKind::Runq => self.add(Class::Runqueue, comm(), len),
            SegKind::Blocked(block) => match block.what.class {
                Class::Child => match self.child_for(p, seg, block.waker_tgid) {
                    Some(child) if depth < MAX_DEPTH => self.descend(child, s0, s1, depth, Class::Child),
                    Some(child) => {
                        let subject = trace.procs[child].comm().to_string();
                        self.add(Class::Child, subject, len);
                    }
                    None => self.add(Class::Child, "unknown child".to_owned(), len),
                },
                Class::Ipc if depth < MAX_DEPTH => match self.process_at(block.waker_tgid, seg.end) {
                    Some(waker) if waker != p => self.descend(waker, s0, s1, depth, Class::Ipc),
                    _ => self.add(Class::Ipc, comm(), len),
                },
                class => {
                    let subject = match &block.what.subject {
                        Subject::Process => comm(),
                        other => other.to_string(),
                    };
                    if let Some(socket) = block.what.socket {
                        self.sockets.entry(subject.clone()).or_default().insert(socket);
                    }
                    self.add(class, subject, len);
                }
            },
        }
    }

    /// Explains `[s0, s1)` by process `q`; the parts outside its lifetime stay `class`,
    /// subject `q`'s comm.
    fn descend(&mut self, q: ProcId, s0: u64, s1: u64, depth: u32, class: Class) {
        let proc = &self.trace.procs[q];
        let lo = s0.max(proc.birth);
        let hi = s1.min(proc.death.unwrap_or(u64::MAX));
        let subject: Arc<str> = Arc::clone(proc.comm());
        if lo >= hi {
            self.add(class, subject.to_string(), s1 - s0);
            return;
        }
        self.add(class, subject.to_string(), (lo - s0) + (s1 - hi));
        self.walk(q, lo, hi, depth + 1);
    }

    /// The child of `p` whose state change ended the wait `seg`.
    fn child_for(&self, p: ProcId, seg: &Seg, waker_tgid: u32) -> Option<ProcId> {
        let procs = &self.trace.procs;
        let children = &procs[p].children;
        if let Some(waker) = self.process_at(waker_tgid, seg.end)
            && children.contains(&waker)
        {
            return Some(waker);
        }
        let exited = children
            .iter()
            .copied()
            .filter(|&c| procs[c].death.is_some_and(|d| d >= seg.start && d <= seg.end))
            .max_by_key(|&c| procs[c].death);
        exited.or_else(|| {
            children
                .iter()
                .copied()
                .filter(|&c| procs[c].birth <= seg.end && procs[c].death.is_none_or(|d| d > seg.end))
                .max_by_key(|&c| procs[c].birth)
        })
    }

    /// The process with thread-group id `tgid` alive at `ts`.
    fn process_at(&self, tgid: u32, ts: u64) -> Option<ProcId> {
        if tgid == 0 {
            return None;
        }
        self.by_tgid.get(&tgid)?.iter().copied().rev().find(|&id| {
            let proc = &self.trace.procs[id];
            proc.birth <= ts && proc.death.is_none_or(|d| d >= ts)
        })
    }
}
