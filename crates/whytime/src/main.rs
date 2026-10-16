//! `whytime`: explains where a command's wall-clock time went.
//!
//! Wrap mode loads the BPF programs, forks COMMAND parked on a pipe, adds it to the tracked
//! set, releases it, and turns the record stream into per-thread timelines until COMMAND
//! exits (or `--duration` elapses). Attach mode (`-p PID`, [`attach`]) seeds the same state
//! for a running process tree from `/proc` instead. The timelines are then attributed along
//! the critical path and reported on stderr. In either mode `--record FILE` also saves every
//! input of the report to a trace file, which `whytime report FILE` replays ([`record`]).
//! See `AGENTS.md` for the model and its limits.

mod attach;
mod attribute;
mod classify;
mod cli;
mod doctor;
mod logger;
mod percpu;
mod record;
mod report;
mod snapshot;
mod spawn;
mod sys;
#[cfg(test)]
mod testkit;
mod timeline;
mod tracer;

use std::ffi::{CStr, CString, OsStr};
use std::io::{self, Write as _};
use std::num::NonZeroU64;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use bpfdoctor::{Doctor, RealEnv, ids_for_errno};
use clap::{CommandFactory as _, Parser as _};
use whytime_abi::TaskState;

use crate::classify::{Classifier, FdTarget, ProcFd};
use crate::cli::{Cli, RunArgs, Sub};
use crate::record::{End, Header, Logged, Probes, Recorder};
use crate::report::{EndedBy, Meta, Report};
use crate::spawn::{Child, Credentials, StartError};
use crate::sys::SyscallTable;
use crate::timeline::{Trace, proc_table};
use crate::tracer::Tracer;

/// whytime could not start tracing (or failed before COMMAND ran).
const EXIT_SETUP: i32 = 125;
/// `whytime report`: the trace file cannot be replayed.
const EXIT_REPLAY: i32 = 2;

fn main() -> ExitCode {
    logger::init();
    let cli = Cli::parse();
    let code = match cli.sub {
        Some(Sub::Doctor { json }) => doctor::run(json).unwrap_or_else(|err| {
            eprintln!("whytime: {err}");
            EXIT_SETUP
        }),
        Some(Sub::Report { file, json }) => replay(&file, json),
        Some(Sub::Completions { shell }) => {
            // Buffered: clap_complete panics on write errors (e.g. a closed pipe).
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "whytime", &mut script);
            match io::stdout().write_all(&script) {
                Ok(()) => 0,
                Err(err) => {
                    eprintln!("whytime: writing completions: {err}");
                    1
                }
            }
        }
        None => match cli.run.pid {
            Some(pid) => attach::run(pid, &cli.run),
            None => wrap(&cli.run),
        },
    };
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}

/// Runs and reports COMMAND; returns the exit code.
fn wrap(args: &RunArgs) -> i32 {
    let tool = doctor::tool();
    if !preflight(&tool) {
        return EXIT_SETUP;
    }
    match Session::start(args) {
        Ok(Started::Running(session)) => session.finish(args),
        Ok(Started::Failed(code)) => code,
        Err(err) => start_failed(&err, &tool),
    }
}

/// Runs the bpfdoctor preflight; on failure prints the diagnosis and returns false.
fn preflight(tool: &bpfdoctor::Tool) -> bool {
    let preflight = Doctor::preflight().run(&RealEnv, tool);
    if preflight.has_fail() {
        doctor::print(&preflight);
        eprintln!("whytime: cannot trace on this system (details: whytime doctor)");
        return false;
    }
    true
}

/// Reports a failure to start tracing, with the doctor checks its errno points at; returns
/// [`EXIT_SETUP`].
fn start_failed(err: &anyhow::Error, tool: &bpfdoctor::Tool) -> i32 {
    eprintln!("whytime: {}", doctor::describe(err));
    let ids = tracer::errno(err).map_or(&[][..], ids_for_errno);
    if !ids.is_empty() {
        let report = doctor::full().run_ids(&RealEnv, tool, ids);
        if report
            .checks
            .iter()
            .any(|c| c.status != bpfdoctor::Status::Pass)
        {
            doctor::print(&report);
        }
    }
    EXIT_SETUP
}

/// Loads and attaches the programs; says which optional program sets are attached, warning
/// about the others.
fn load(syscalls: &SyscallTable) -> anyhow::Result<(Tracer, Probes)> {
    let loaded = Tracer::load(syscalls)?;
    if let Err(err) = &loaded.syscalls {
        log::warn!("syscall tracepoints unavailable ({err:#}); blocked time will not be classified");
    }
    if let Err(err) = &loaded.readiness {
        log::warn!(
            "poll/epoll readiness probes unavailable ({err:#}); poll waits will not be \
             attributed to the ready descriptor"
        );
    }
    if let Err(err) = &loaded.faults {
        log::warn!(
            "page-fault probes unavailable ({err:#}); blocks in page faults will not be \
             reported as fault"
        );
    }
    let probes = Probes {
        syscalls: loaded.syscalls.is_ok(),
        readiness: loaded.readiness.is_ok(),
        faults: loaded.faults.is_ok(),
    };
    Ok((loaded.tracer, probes))
}

/// Kernel `USER_HZ`, the unit of `/proc` start times.
fn ticks_per_sec() -> anyhow::Result<NonZeroU64> {
    // Not ProcFs::clock_ticks_per_sec: /proc/self/auxv is unreadable when whytime runs
    // with file capabilities (non-dumpable), while the in-memory auxv always works.
    // SAFETY: getauxval only reads the process's saved auxiliary vector.
    let ticks = unsafe { libc::getauxval(libc::AT_CLKTCK) };
    NonZeroU64::new(ticks).context("AT_CLKTCK missing from auxv")
}

/// A traced COMMAND that has exec'd.
struct Session {
    tracer: Tracer,
    /// The run's context; recorded as the trace file's header.
    header: Header,
    command: Wrapped,
    trace: Trace,
    recorder: Option<Recorder>,
}

/// The running COMMAND and the signals whytime forwards to it.
struct Wrapped {
    child: Child,
    signals: OwnedFd,
}

enum Started {
    Running(Box<Session>),
    /// COMMAND never ran; exit with this code.
    Failed(i32),
}

/// How the observation window ended.
enum Outcome {
    /// COMMAND exited with this code.
    Exited(i32),
    /// The `--duration` deadline (monotonic ns) passed.
    Deadline(u64),
}

impl Session {
    fn start(args: &RunArgs) -> anyhow::Result<Started> {
        let creds = sudo_credentials()?;
        let home = home_dir(creds.as_ref().map(|c| c.uid));
        if creds.is_some() {
            restore_user_env(home.as_deref());
        }
        let syscalls = SyscallTable::new();
        let (mut tracer, probes) = load(&syscalls)?;
        let ticks_per_sec = ticks_per_sec()?;
        let recorder = recorder(args, creds.as_ref())?;

        let signals = take_signals().context("setting up signal handling")?;
        let mut child = Child::spawn(&args.command, creds.as_ref()).context("forking")?;
        // Dropping `child` before release makes it exit 125 without running COMMAND.
        tracer.track(child.pid())?;
        let program = args.command[0].to_string_lossy().into_owned();
        match child.release() {
            Ok(()) => {}
            Err(StartError::Exec(err)) => {
                eprintln!("whytime: {program}: {err}");
                return Ok(Started::Failed(child.wait().unwrap_or(127)));
            }
            Err(StartError::Setup(err)) => {
                eprintln!("whytime: dropping privileges to the invoking user: {err}");
                let _ = child.wait();
                return Ok(Started::Failed(EXIT_SETUP));
            }
        }
        let header = Header {
            arch: std::env::consts::ARCH.to_owned(),
            command: args.command.clone(),
            root_pid: child.pid(),
            home: home.clone(),
            probes,
            ticks_per_sec,
            attached: None,
        };
        if let Some(recorder) = &recorder {
            recorder.header(&header);
        }
        let trace = Trace::new(
            child.pid(),
            Classifier::new(syscalls, home, files(recorder.as_ref())),
            proc_table(ticks_per_sec),
        );
        Ok(Started::Running(Box::new(Self {
            tracer,
            header,
            command: Wrapped { child, signals },
            trace,
            recorder,
        })))
    }

    /// Observes until the window ends, reports, and returns COMMAND's exit code.
    fn finish(mut self, args: &RunArgs) -> i32 {
        let outcome = match self.observe(args.duration) {
            Ok(outcome) => outcome,
            Err(err) => {
                eprintln!("whytime: tracing failed: {err:#}");
                return self.command.wait_forwarding();
            }
        };
        let (end, ended_by, exit_code) = match outcome {
            Outcome::Exited(code) => (
                self.trace.window.exit.unwrap_or_else(monotonic_ns),
                EndedBy::Exit,
                Some(code),
            ),
            Outcome::Deadline(deadline) => (deadline, EndedBy::Duration, None),
        };

        // Detach first so the task states stop changing, then collect what is in flight.
        let Self {
            tracer,
            header,
            command,
            mut trace,
            recorder,
        } = self;
        let maps = collect(tracer, &mut trace, recorder.as_ref());
        let tasks = maps.tasks();
        trace.sweep(&tasks, end);
        let end = End {
            start: trace.window.start,
            end,
            ended_by,
            exit_code,
            dropped: maps.dropped(),

        };
        drop(maps);
        save(recorder.as_ref(), args, &tasks, &end);

        report(&trace, end.end, meta(&header, &end), args.json);
        match outcome {
            Outcome::Exited(code) => code,
            Outcome::Deadline(_) => command.wait_forwarding(),
        }
    }

    /// Feeds records to the trace until COMMAND exits or the deadline passes, forwarding
    /// SIGTERM and SIGHUP.
    fn observe(&mut self, duration: Option<Duration>) -> io::Result<Outcome> {
        const RING: u64 = 0;
        const CHILD: u64 = 1;
        const SIGNALS: u64 = 2;
        let epoll = Epoll::new()?;
        epoll.add(self.tracer.ring_fd(), RING)?;
        epoll.add(self.command.child.pidfd(), CHILD)?;
        epoll.add(self.command.signals.as_raw_fd(), SIGNALS)?;
        let duration_ns = duration.map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        loop {
            let trace = &mut self.trace;
            let recorder = self.recorder.as_ref();
            self.tracer.drain(|record| ingest(trace, recorder, record));
            let deadline = duration_ns
                .zip(trace.window.start)
                .map(|(d, start)| start.saturating_add(d));
            let now = monotonic_ns();
            if let Some(deadline) = deadline
                && now >= deadline
            {
                return Ok(Outcome::Deadline(deadline));
            }
            let timeout = wait_timeout(deadline, now);
            for token in epoll.wait(timeout)? {
                match token {
                    CHILD => return self.command.child.wait().map(Outcome::Exited),
                    SIGNALS => self.command.forward_signals(),
                    _ => {}
                }
            }
        }
    }
}

/// With `--record FILE`, creates the trace file, owned by the invoking user under sudo.
/// Called before anything is observed, so a bad path fails fast.
fn recorder(args: &RunArgs, creds: Option<&Credentials>) -> anyhow::Result<Option<Recorder>> {
    args.record
        .as_deref()
        .map(|path| {
            Recorder::create(path, creds.map(|c| (c.uid, c.gid)))
                .with_context(|| format!("creating the trace file {}", path.display()))
        })
        .transpose()
}

/// The classifier's descriptor lookups: `/proc`, each answer recorded when `--record` is on.
fn files(recorder: Option<&Recorder>) -> Box<dyn FdTarget> {
    match recorder {
        Some(recorder) => Box::new(Logged::new(ProcFd, recorder.clone())),
        None => Box::new(ProcFd),
    }
}

/// Applies one ring buffer record, recording it first when `--record` is on.
fn ingest(trace: &mut Trace, recorder: Option<&Recorder>, record: &[u8]) {
    if let Some(recorder) = recorder {
        recorder.record(record);
    }
    trace.ingest(record);
}

/// With `--record`, writes the final sweep and the end frame. A write error is printed now,
/// before the report, which must stay last on stderr.
fn save(recorder: Option<&Recorder>, args: &RunArgs, tasks: &[(u32, TaskState)], end: &End) {
    if let (Some(recorder), Some(path)) = (recorder, &args.record)
        && let Err(err) = recorder.finish(tasks, end)
    {
        eprintln!("whytime: writing the trace file {}: {err}", path.display());
    }
}

/// The report's inputs besides the trace, from the header and end frames: the same for a
/// live run and its replay.
fn meta(header: &Header, end: &End) -> Meta {
    Meta {
        command: header
            .command
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
        wall_ns: 0,
        ended_by: end.ended_by,
        exit_code: end.exit_code,
        dropped: end.dropped,
        syscalls: header.probes.syscalls,
        readiness: header.probes.readiness,
        faults: header.probes.faults,
        attached: header.attached,
    }
}

/// Attributes the window `[exec, end)` and writes the report to stderr.
fn report(trace: &Trace, end: u64, meta: Meta, json: bool) {
    let mut err = io::stderr().lock();
    if let Err(e) = write_report(&mut err, trace, end, meta, json).and_then(|()| err.flush()) {
        log::error!("writing the report: {e}");
    }
}

/// Attributes the window `[exec, end)` and writes the report to `w`. `meta.wall_ns` is
/// filled in here.
fn write_report(
    w: &mut dyn io::Write,
    trace: &Trace,
    end: u64,
    mut meta: Meta,
    json: bool,
) -> io::Result<()> {
    let (Some(root), Some(start)) = (trace.root, trace.window.start) else {
        return writeln!(
            w,
            "whytime: the command's exec was not observed ({} records lost); no report",
            meta.dropped
        );
    };
    let end = end.max(start);
    meta.wall_ns = end - start;
    let report = Report::new(trace, attribute::attribute(trace, root, start, end), meta);
    if json {
        report.render_json(w)
    } else {
        report.render_human(w)
    }
}

/// `whytime report FILE`: replays a trace file and prints its report; returns the exit code.
fn replay(path: &Path, json: bool) -> i32 {
    let replayed = std::fs::read(path)
        .map_err(|err| err.to_string())
        .and_then(|bytes| record::replay(&bytes).map_err(|err| err.to_string()));
    match replayed {
        Ok(replay) => {
            let meta = meta(&replay.header, &replay.end);
            report(&replay.trace, replay.end.end, meta, json);
            0
        }
        Err(err) => {
            eprintln!("whytime: {}: {err}", path.display());
            EXIT_REPLAY
        }
    }
}

/// Detaches every program (the task states stop changing), then feeds the records still in
/// flight to `trace` (and the trace file); the returned maps hold what the final sweep needs.
fn collect(tracer: Tracer, trace: &mut Trace, recorder: Option<&Recorder>) -> tracer::Maps {
    let mut maps = tracer.detach();
    // Programs still running on other CPUs commit within microseconds.
    std::thread::sleep(Duration::from_millis(2));
    maps.drain(|record| ingest(trace, recorder, record));
    maps
}

/// Milliseconds from `now` until `deadline` (rounded up) for `epoll_wait`; -1 for none.
fn wait_timeout(deadline: Option<u64>, now: u64) -> i32 {
    deadline.map_or(-1, |deadline| {
        i32::try_from(deadline.saturating_sub(now).div_ceil(1_000_000)).unwrap_or(i32::MAX)
    })
}

impl Wrapped {
    /// Waits for COMMAND, still forwarding signals.
    fn wait_forwarding(&self) -> i32 {
        const CHILD: u64 = 1;
        const SIGNALS: u64 = 2;
        let wait = || -> io::Result<i32> {
            let epoll = Epoll::new()?;
            epoll.add(self.child.pidfd(), CHILD)?;
            epoll.add(self.signals.as_raw_fd(), SIGNALS)?;
            loop {
                for token in epoll.wait(-1)? {
                    match token {
                        CHILD => return self.child.wait(),
                        _ => self.forward_signals(),
                    }
                }
            }
        };
        wait().unwrap_or_else(|err| {
            eprintln!("whytime: waiting for the command: {err}");
            EXIT_SETUP
        })
    }

    fn forward_signals(&self) {
        loop {
            // SAFETY: signalfd_siginfo is plain data; read fills it or fails.
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let size = size_of::<libc::signalfd_siginfo>();
            // SAFETY: reading one record into `info` from our non-blocking signalfd.
            let n = unsafe { libc::read(self.signals.as_raw_fd(), (&raw mut info).cast(), size) };
            if usize::try_from(n).ok() != Some(size) {
                return;
            }
            if let Ok(signal) = i32::try_from(info.ssi_signo) {
                self.child.signal(signal);
            }
        }
    }
}

/// Ignores SIGINT/SIGQUIT (the terminal delivers them to COMMAND, and whytime must survive
/// to report) and routes SIGTERM/SIGHUP to a signalfd so they can be forwarded.
fn take_signals() -> io::Result<OwnedFd> {
    // SAFETY: plain signal-disposition and mask calls with valid pointers.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGTERM);
        libc::sigaddset(&raw mut set, libc::SIGHUP);
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

/// Under `sudo`, the invoking user's credentials: COMMAND runs as them, not as root.
fn sudo_credentials() -> anyhow::Result<Option<Credentials>> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let id = |key: &str| std::env::var(key).ok().and_then(|v| v.parse::<u32>().ok());
    let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) else {
        return Ok(None);
    };
    if uid == 0 {
        return Ok(None);
    }
    let groups = match std::env::var_os("SUDO_USER") {
        Some(user) => group_list(&user, gid).context("looking up the invoking user's groups")?,
        None => vec![gid],
    };
    Ok(Some(Credentials { uid, gid, groups }))
}

fn group_list(user: &OsStr, gid: libc::gid_t) -> io::Result<Vec<libc::gid_t>> {
    let name =
        CString::new(user.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut groups = vec![0; 64];
    loop {
        let mut n = libc::c_int::try_from(groups.len()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `groups` holds `n` entries; getgrouplist writes at most that many and
        // stores the required count in `n`.
        let rc = unsafe { libc::getgrouplist(name.as_ptr(), gid, groups.as_mut_ptr(), &raw mut n) };
        let n = usize::try_from(n).unwrap_or(0);
        if rc >= 0 {
            groups.truncate(n);
            return Ok(groups);
        }
        if n <= groups.len() {
            return Err(io::Error::other("getgrouplist failed"));
        }
        groups.resize(n, 0);
    }
}

/// Points `HOME`, `USER` and `LOGNAME` back at the invoking user, whom COMMAND runs as under
/// sudo (sudo set them to root's). COMMAND inherits whytime's environment.
fn restore_user_env(home: Option<&std::path::Path>) {
    let user = std::env::var_os("SUDO_USER");
    // SAFETY: whytime is single-threaded here (before any thread is spawned), so nothing
    // reads the environment concurrently.
    unsafe {
        if let Some(home) = home {
            std::env::set_var("HOME", home);
        }
        if let Some(user) = user {
            std::env::set_var("USER", &user);
            std::env::set_var("LOGNAME", &user);
        }
    }
}

/// Home directory of `uid` (default: the current user), for `~` in paths.
fn home_dir(uid: Option<libc::uid_t>) -> Option<PathBuf> {
    // SAFETY: getuid has no preconditions.
    let uid = uid.unwrap_or_else(|| unsafe { libc::getuid() });
    // SAFETY: passwd is plain data; getpwuid_r fills it with pointers into `buf`.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the sizes given.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc == 0 && !result.is_null() && !pwd.pw_dir.is_null() {
        // SAFETY: pw_dir points at a NUL-terminated string inside `buf`.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        return Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())));
    }
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `CLOCK_MONOTONIC` in nanoseconds: the clock of `bpf_ktime_get_ns`.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

/// A minimal level-triggered epoll set.
struct Epoll(OwnedFd);

impl Epoll {
    fn new() -> io::Result<Self> {
        // SAFETY: epoll_create1 returns a new descriptor or -1.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh descriptor we own.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    fn add(&self, fd: RawFd, token: u64) -> io::Result<()> {
        let mut event = libc::epoll_event {
            events: u32::try_from(libc::EPOLLIN).unwrap_or(1),
            u64: token,
        };
        // SAFETY: registering a valid descriptor with a valid event.
        if unsafe { libc::epoll_ctl(self.0.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &raw mut event) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Tokens of the ready descriptors; empty on timeout or interruption.
    fn wait(&self, timeout_ms: i32) -> io::Result<Vec<u64>> {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        // SAFETY: `events` has room for the 4 entries we pass.
        let n = unsafe { libc::epoll_wait(self.0.as_raw_fd(), events.as_mut_ptr(), 4, timeout_ms) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(Vec::new())
            } else {
                Err(err)
            };
        }
        Ok(events[..usize::try_from(n).unwrap_or(0)]
            .iter()
            .map(|e| e.u64)
            .collect())
    }
}
