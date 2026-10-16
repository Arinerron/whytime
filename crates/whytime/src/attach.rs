//! Attach mode: `whytime -p PID` observes a running process and its descendants.
//!
//! The kernel side normally learns about a process tree from its forks. Here the tree
//! already exists, so user space seeds what the forks would have created:
//!
//! 1. every process of the tree goes into `tracked` ([`track_tree`]); from then on the
//!    kernel side tracks their new children itself;
//! 2. every thread of those processes gets a `tasks` entry built from `/proc`
//!    ([`snapshot`](crate::snapshot)), after the processes are tracked, so no new thread is
//!    missed;
//! 3. the trace gets the same processes and threads, rooted at the target, and the window
//!    starts. With `--record`, these [`ProcSeed`]s go to the trace file's seed frame, so a
//!    replay starts from the same state without `/proc`.
//!
//! Both inserts use `BPF_NOEXIST`: whatever the kernel side created meanwhile (a fork, an
//! exec) wins, and the trace learns about those tasks from their records. The window ends
//! when the target's thread group exits, `--duration` elapses, or SIGINT/SIGTERM/SIGHUP
//! arrives. The target is never signalled, and whytime exits 0 after reporting.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStringExt as _;
use std::time::Duration;

use anyhow::Context as _;
use procctx::{ProcFs, ProcKey, ProcSource as _, StartClock, StatLine};

use crate::classify::Classifier;
use crate::cli::RunArgs;
use crate::record::{self, Header, Recorder};
use crate::report::{self, Attached, EndedBy};
use crate::snapshot::{self, Snapshot};
use crate::sys::SyscallTable;
use crate::timeline::{ProcSeed, Trace, proc_table};
use crate::tracer::Tracer;
use crate::{EXIT_SETUP, Epoll, monotonic_ns};

/// PID cannot be attached to: it does not exist, is a thread, whytime itself, ...
const EXIT_ATTACH: i32 = 1;
/// `/proc` scans of the tree before giving up on it settling.
const MAX_SCANS: usize = 32;
/// `CAP_SYS_PTRACE`, which lifts the same-owner rule (as for ptrace).
const CAP_SYS_PTRACE: u32 = 19;

/// Attaches to `pid`, observes and reports; returns whytime's exit code.
pub fn run(pid: u32, args: &RunArgs) -> i32 {
    let target = match Target::open(pid) {
        Ok(target) => target,
        Err(refusal) => {
            refusal.print();
            return EXIT_ATTACH;
        }
    };
    let tool = crate::doctor::tool();
    if !crate::preflight(&tool) {
        return EXIT_SETUP;
    }
    match Session::start(target, args) {
        Ok(Some(session)) => session.finish(args),
        Ok(None) => {
            eprintln!("whytime: process {pid} exited while whytime attached to it");
            EXIT_ATTACH
        }
        Err(err) => crate::start_failed(&err, &tool),
    }
}

/// Why `-p PID` was refused, with a fix when there is one.
#[derive(Debug)]
struct Refusal {
    why: String,
    fix: Option<String>,
}

impl Refusal {
    fn new(why: impl Into<String>) -> Self {
        Self {
            why: why.into(),
            fix: None,
        }
    }

    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    /// Prints it like a doctor diagnosis.
    fn print(&self) {
        eprintln!("whytime: {}", self.why);
        if let Some(fix) = &self.fix {
            eprintln!("      fix:    {fix}");
        }
    }
}

/// The process attached to.
#[derive(Debug)]
struct Target {
    pid: u32,
    /// Readable once its thread group has exited.
    pidfd: OwnedFd,
}

impl Target {
    /// Checks that `pid` is a live process whytime may observe, and holds on to it.
    ///
    /// whytime itself is refused (it would trace its own event loop), and so is pid 1:
    /// every process descends from init, so attaching would trace the whole system with
    /// init's event loop as the critical path. Without root, the target must belong to the
    /// invoking user (all of real, effective and saved uid and gid), as for ptrace, unless
    /// whytime has `CAP_SYS_PTRACE`: file capabilities must not let users observe each
    /// other's processes.
    fn open(pid: u32) -> Result<Self, Refusal> {
        if pid == std::process::id() {
            return Err(Refusal::new(format!("pid {pid} is whytime itself")));
        }
        if pid == 1 {
            return Err(Refusal::new(
                "pid 1 is init: every process descends from it, so attaching would trace the \
                 whole system",
            )
            .fix("whytime -p \"$(systemctl show -p MainPID --value UNIT)\""));
        }
        let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
            Ok(status) => status,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(Refusal::new(format!("no process {pid}")));
            }
            Err(err) => return Err(Refusal::new(format!("reading /proc/{pid}/status: {err}"))),
        };
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        let ids = |name: &str| -> Vec<u32> {
            field(name).map_or_else(Vec::new, |ids| {
                ids.split_ascii_whitespace()
                    .filter_map(|id| id.parse().ok())
                    .collect()
            })
        };
        let tgid = field("Tgid:").and_then(|tgid| tgid.parse::<u32>().ok());
        if let Some(tgid) = tgid
            && tgid != pid
        {
            return Err(
                Refusal::new(format!("{pid} is a thread of process {tgid}"))
                    .fix(format!("whytime -p {tgid}")),
            );
        }
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let (uids, gids) = (ids("Uid:"), ids("Gid:"));
        let same = |ids: &[u32], own: u32| ids.iter().take(3).all(|&id| id == own);
        let owned = same(&uids, uid) && same(&gids, gid);
        if uid != 0 && !owned && !has_sys_ptrace() {
            let owner = uids.first().map_or_else(|| "?".to_owned(), u32::to_string);
            return Err(Refusal::new(format!(
                "process {pid} belongs to uid {owner}: without root, whytime attaches only to \
                 your own processes"
            ))
            .fix(format!("sudo whytime -p {pid}")));
        }
        let stat = fs::read(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|line| StatLine::parse(pid, &line).ok());
        let Some(stat) = stat else {
            return Err(Refusal::new(format!("no process {pid}")));
        };
        if snapshot::exited(&stat) {
            return Err(Refusal::new(format!(
                "process {pid} has already exited (a zombie waiting for its parent)"
            )));
        }
        let pidfd = pidfd_open(pid).map_err(|err| match err.raw_os_error() {
            Some(libc::ESRCH) => Refusal::new(format!("no process {pid}")),
            _ => Refusal::new(format!("pidfd_open({pid}): {err}")),
        })?;
        Ok(Self { pid, pidfd })
    }
}

/// Whether whytime's effective capabilities include `CAP_SYS_PTRACE`.
fn has_sys_ptrace() -> bool {
    fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))
            .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
            .is_some_and(|caps| caps & (1 << CAP_SYS_PTRACE) != 0)
    })
}

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags; the result is a new descriptor or -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw = RawFd::try_from(raw).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: `raw` is a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// A process of the target's tree that attach added to `tracked`.
#[derive(Debug)]
struct Member {
    pid: u32,
    ppid: u32,
    start_ticks: u64,
    comm: Box<str>,
}

/// The target's command line for the report: its arguments, or its `comm` if it has none
/// (a kernel thread, or one that cleared them).
fn command(seed: &ProcSeed) -> Vec<OsString> {
    let mut argv: Vec<OsString> = seed
        .argv
        .split(|&b| b == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| OsString::from_vec(arg.to_vec()))
        .collect();
    if argv.is_empty() {
        argv.push(OsString::from(&seed.comm));
    }
    argv
}

/// An attached target being observed.
struct Session {
    tracer: Tracer,
    /// The run's context (target, command line, unreadable count); recorded as the trace
    /// file's header.
    header: Header,
    target: Target,
    signals: OwnedFd,
    trace: Trace,
    recorder: Option<Recorder>,
}

/// How the observation ended.
enum End {
    /// The target exited; noticed at this time (the exit record has the exact one).
    Exit(u64),
    /// The `--duration` deadline passed.
    Deadline(u64),
    /// SIGINT, SIGTERM or SIGHUP arrived at this time.
    Interrupt(u64),
}

impl Session {
    /// Loads the programs, seeds the tree and starts the window; `None` when the target
    /// exited before any of it was seeded.
    fn start(target: Target, args: &RunArgs) -> anyhow::Result<Option<Self>> {
        let creds = crate::sudo_credentials()?;
        let home = crate::home_dir(creds.as_ref().map(|creds| creds.uid));
        let syscalls = SyscallTable::new();
        let (mut tracer, probes) = crate::load(&syscalls)?;
        let ticks_per_sec = crate::ticks_per_sec()?;
        let recorder = crate::recorder(args, creds.as_ref())?;
        // From here on, Ctrl-C ends the observation instead of killing whytime.
        let signals = take_signals().context("setting up signal handling")?;

        let members = track_tree(&mut tracer, target.pid)?;
        let mut snapshot = Snapshot::new(&syscalls);
        let clock = StartClock::BootNs { ticks_per_sec };
        let seeds = seed_threads(&mut tracer, members, &mut snapshot, clock)?;
        let Some(root) = seeds.iter().find(|seed| seed.key.pid == target.pid) else {
            return Ok(None);
        };
        let header = Header {
            arch: std::env::consts::ARCH.to_owned(),
            command: command(root),
            root_pid: target.pid,
            home: home.clone(),
            probes,
            ticks_per_sec,
            attached: Some(Attached {
                pid: target.pid,
                unreadable: snapshot.unreadable,
            }),
        };

        let mut trace = Trace::new(
            target.pid,
            Classifier::new(syscalls, home, crate::files(recorder.as_ref())),
            proc_table(ticks_per_sec),
        );
        let start = monotonic_ns();
        trace.seed(&seeds, start);
        if let Some(recorder) = &recorder {
            recorder.header(&header);
            recorder.seed(&seeds, start);
        }
        Ok(Some(Self {
            tracer,
            header,
            target,
            signals,
            trace,
            recorder,
        }))
    }

    /// Observes until the window ends, reports, and returns 0.
    fn finish(mut self, args: &RunArgs) -> i32 {
        let end = match self.observe(args.duration) {
            Ok(end) => end,
            Err(err) => {
                eprintln!("whytime: tracing failed: {err:#}");
                return EXIT_SETUP;
            }
        };
        let Self {
            tracer,
            header,
            mut trace,
            recorder,
            ..
        } = self;
        let maps = crate::collect(tracer, &mut trace, recorder.as_ref());
        let (end, ended_by) = match (end, trace.window.exit) {
            // The target exited first; its record was still in flight.
            (End::Deadline(at) | End::Interrupt(at), Some(exit)) if exit <= at => {
                (exit, EndedBy::Exit)
            }
            (End::Exit(seen), exit) => (exit.unwrap_or(seen), EndedBy::Exit),
            (End::Deadline(deadline), _) => (deadline, EndedBy::Duration),
            (End::Interrupt(at), _) => (at, EndedBy::Interrupt),
        };
        let tasks = maps.tasks();
        trace.sweep(&tasks, end);
        let exit_code = trace
            .root
            .filter(|_| ended_by == EndedBy::Exit)
            .and_then(|root| trace.table.get_key(trace.procs[root].key))
            .and_then(|info| info.exit?.code)
            .map(report::exit_code);
        let end = record::End {
            start: trace.window.start,
            end,
            ended_by,
            exit_code,
            dropped: maps.dropped(),
        };
        drop(maps);
        crate::save(recorder.as_ref(), args, &tasks, &end);
        crate::report(&trace, end.end, crate::meta(&header, &end), args.json);
        0
    }

    /// Feeds records to the trace until the target exits, the deadline passes, or a
    /// terminating signal arrives.
    fn observe(&mut self, duration: Option<Duration>) -> io::Result<End> {
        const RING: u64 = 0;
        const TARGET: u64 = 1;
        const SIGNALS: u64 = 2;
        let epoll = Epoll::new()?;
        epoll.add(self.tracer.ring_fd(), RING)?;
        epoll.add(self.target.pidfd.as_raw_fd(), TARGET)?;
        epoll.add(self.signals.as_raw_fd(), SIGNALS)?;
        let deadline = duration.zip(self.trace.window.start).map(|(d, start)| {
            start.saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        });
        loop {
            let trace = &mut self.trace;
            let recorder = self.recorder.as_ref();
            self.tracer.drain(|record| crate::ingest(trace, recorder, record));
            let now = monotonic_ns();
            if trace.window.exit.is_some() {
                return Ok(End::Exit(now));
            }
            if let Some(deadline) = deadline
                && now >= deadline
            {
                return Ok(End::Deadline(deadline));
            }
            for token in epoll.wait(crate::wait_timeout(deadline, now))? {
                match token {
                    TARGET => return Ok(End::Exit(monotonic_ns())),
                    SIGNALS => return Ok(End::Interrupt(monotonic_ns())),
                    _ => {}
                }
            }
        }
    }
}

/// Routes SIGINT, SIGTERM and SIGHUP to a signalfd: they end the observation. Blocked
/// signals are queued even when inherited as ignored (as in a shell's background job).
fn take_signals() -> io::Result<OwnedFd> {
    // SAFETY: plain signal-mask calls with valid pointers.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaddset(&raw mut set, signal);
        }
        if libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::signalfd(-1, &raw const set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Adds the target and its descendants (by `/proc` parent links; whytime itself excluded)
/// to `tracked`, re-scanning until a scan finds no process it can add. A descendant the
/// kernel side already tracks was forked by a tracked process: its fork record is queued,
/// and the trace learns about it from there.
///
/// Why this terminates with nothing missed: a process still untracked after a scan was
/// forked by an untracked parent before that parent's insert, so the next scan sees it
/// (unless it exited, or was reparented away from the tree because its parent exited). A
/// scan that adds nothing shows every live member was tracked before the scan, so all
/// later forks are tracked in kernel. Each round only chases forks that raced the
/// previous one, so a busy tree settles in a few scans.
fn track_tree(tracer: &mut Tracer, root: u32) -> anyhow::Result<Vec<Member>> {
    let procfs = ProcFs::new();
    let me = std::process::id();
    let mut known = HashSet::new();
    let mut members = Vec::new();
    for _ in 0..MAX_SCANS {
        let mut added = false;
        for stat in descendants(&procfs, root, me)? {
            if snapshot::exited(&stat) || !known.insert(stat.pid) {
                continue;
            }
            if tracer.track_existing(stat.pid)? {
                added = true;
                members.push(Member {
                    pid: stat.pid,
                    ppid: stat.ppid,
                    start_ticks: stat.start_ticks,
                    comm: stat.comm,
                });
            }
        }
        if !added {
            return Ok(members);
        }
    }
    log::warn!(
        "the process tree was still changing after {MAX_SCANS} scans; processes it forked \
         meanwhile may be missing"
    );
    Ok(members)
}

/// `root` and its descendants, parents before children, without `exclude` and its subtree.
fn descendants(procfs: &ProcFs, root: u32, exclude: u32) -> anyhow::Result<Vec<StatLine>> {
    let mut tree = Vec::new();
    let mut children: HashMap<u32, Vec<StatLine>> = HashMap::new();
    for pid in procfs.list_pids().context("listing /proc")? {
        if pid == exclude {
            continue;
        }
        // Gone since the listing.
        let Ok(stat) = procfs.stat(pid) else {
            continue;
        };
        if pid == root {
            tree.push(stat);
        } else {
            children.entry(stat.ppid).or_default().push(stat);
        }
    }
    let mut next = 0;
    while let Some(proc) = tree.get(next) {
        if let Some(kids) = children.remove(&proc.pid) {
            tree.extend(kids);
        }
        next += 1;
    }
    Ok(tree)
}

/// Creates the `tasks` entries of every thread of `members` from `/proc`, and describes
/// each member for the trace (its key in `clock`). A thread whose entry the kernel side
/// created first is left to its records; one that exited before its entry existed loses
/// it again (no exit record would remove it). A member that turns out gone is untracked,
/// and dropped if none of its threads got an entry.
fn seed_threads(
    tracer: &mut Tracer,
    members: Vec<Member>,
    snapshot: &mut Snapshot<'_>,
    clock: StartClock,
) -> anyhow::Result<Vec<ProcSeed>> {
    let mut seeds = Vec::with_capacity(members.len());
    for member in members {
        let birth = monotonic_ns();
        let mut threads = Vec::new();
        for tid in snapshot::threads(member.pid) {
            let Some(existing) = snapshot.thread(member.pid, tid) else {
                continue;
            };
            let now = monotonic_ns();
            let state = snapshot::task_state(member.pid, now, &existing.activity);
            if !tracer.seed_task(tid, &state)? {
                continue;
            }
            if snapshot::thread_alive(member.pid, tid, existing.start_ticks) {
                threads.push((tid, now));
            } else {
                tracer.forget_task(tid);
            }
        }
        if !snapshot::process_alive(member.pid, member.start_ticks) {
            tracer.untrack(member.pid);
            if threads.is_empty() {
                continue;
            }
        }
        seeds.push(ProcSeed {
            key: ProcKey {
                pid: member.pid,
                // The tick-precise start; procctx converts /proc times the same way.
                start: clock.ticks_to_start(member.start_ticks),
            },
            ppid: member.ppid,
            comm: member.comm.into_string(),
            argv: fs::read(format!("/proc/{}/cmdline", member.pid)).unwrap_or_default(),
            birth,
            threads,
        });
    }
    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;
    use crate::testkit::{exec, exit, feed, fork, seg, trace};

    #[test]
    fn seeded_tasks_are_not_duplicated_by_racing_forks_and_keep_their_proc_key() {
        // testkit's trace compares starts at 100 ticks per second.
        let clock = StartClock::BootNs {
            ticks_per_sec: NonZeroU64::new(100).unwrap(),
        };
        let mut trace = trace(100);
        // /proc start times have tick precision; the kernel's are exact.
        let key = ProcKey {
            pid: 100,
            start: clock.ticks_to_start(500),
        };
        let exact_start = key.start - 3_000_000;
        trace.seed(
            &[ProcSeed {
                key,
                ppid: 1,
                comm: "sh".to_owned(),
                argv: b"sh\0-c\0exec app".to_vec(),
                birth: 1_000,
                threads: vec![(100, 1_000), (101, 1_010)],
            }],
            2_000,
        );

        // A thread forked while attach seeded it: /proc already showed it.
        let mut forked = fork(1_005, 100, 100, 101, 100);
        forked.child_start = exact_start + 1;
        feed(&mut trace, &forked);
        assert_eq!(trace.procs.len(), 1);
        assert_eq!(trace.procs[0].threads.len(), 2);

        // The target execs and exits: one procctx lifetime under the /proc key.
        let mut execed = exec(3_000, 100, 100, "app", seg(1_000, 0, 0));
        execed.start = exact_start;
        execed.ppid = 1;
        execed.argv[..8].copy_from_slice(b"app\0--x\0");
        execed.argv_len = 8;
        feed(&mut trace, &execed);
        let mut exited = exit(4_000, 100, 100, seg(3_000, 0, 0), 3 << 8, true);
        exited.start = exact_start;
        feed(&mut trace, &exited);
        assert_eq!(trace.root, Some(0));
        assert_eq!(trace.procs[0].key, key);
        assert_eq!(trace.window.start, Some(2_000));
        assert_eq!(trace.window.exit, Some(4_000));
        let info = trace.table.get_key(key).unwrap();
        let argv: Vec<_> = info.argv.iter().map(|arg| arg.to_string_lossy()).collect();
        assert_eq!(argv, ["app", "--x"]);
        assert_eq!(info.exit.and_then(|exit| exit.code), Some(3 << 8));
    }
}
