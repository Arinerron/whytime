//! `whytime`: explains where a command's wall-clock time went.
//!
//! Wrap mode loads the BPF programs, forks COMMAND parked on a pipe, adds it to the tracked
//! set, releases it, and turns the record stream into per-thread timelines until COMMAND
//! exits (or `--duration` elapses). The timelines are then attributed along the critical path
//! and reported on stderr. See `AGENTS.md` for the model and its limits.

mod attribute;
mod classify;
mod cli;
mod doctor;
mod logger;
mod report;
mod spawn;
mod sys;
mod timeline;
mod tracer;

use std::ffi::{CStr, CString, OsStr};
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use bpfdoctor::{Doctor, RealEnv, ids_for_errno};
use clap::Parser as _;
use procctx::{Config, ProcFs, ProcTable, StartClock};

use crate::classify::Classifier;
use crate::cli::{Cli, RunArgs, Sub};
use crate::report::{EndedBy, Meta, Report};
use crate::spawn::{Child, Credentials, StartError};
use crate::sys::SyscallTable;
use crate::timeline::Trace;
use crate::tracer::Tracer;

/// whytime could not start tracing (or failed before COMMAND ran).
const EXIT_SETUP: i32 = 125;

fn main() -> ExitCode {
    logger::init();
    let cli = Cli::parse();
    let code = match cli.sub {
        Some(Sub::Doctor { json }) => doctor::run(json).unwrap_or_else(|err| {
            eprintln!("whytime: {err}");
            EXIT_SETUP
        }),
        None => wrap(&cli.run),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}

/// Runs and reports COMMAND; returns the exit code.
fn wrap(args: &RunArgs) -> i32 {
    let tool = doctor::tool();
    let preflight = Doctor::preflight().run(&RealEnv, &tool);
    if preflight.has_fail() {
        doctor::print(&preflight);
        eprintln!("whytime: cannot trace on this system (details: whytime doctor)");
        return EXIT_SETUP;
    }
    match Session::start(args) {
        Ok(Started::Running(session)) => session.finish(args),
        Ok(Started::Failed(code)) => code,
        Err(err) => {
            eprintln!("whytime: {}", doctor::describe(&err));
            let ids = tracer::errno(&err).map_or(&[][..], ids_for_errno);
            if !ids.is_empty() {
                let report = doctor::full().run_ids(&RealEnv, &tool, ids);
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
    }
}

/// A traced COMMAND that has exec'd.
struct Session {
    tracer: Tracer,
    syscalls: bool,
    command: Wrapped,
    trace: Trace,
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
        let loaded = Tracer::load(&syscalls)?;
        if let Err(err) = &loaded.syscalls {
            log::warn!(
                "syscall tracepoints unavailable ({err:#}); blocked time will not be classified"
            );
        }
        let mut tracer = loaded.tracer;
        // Not ProcFs::clock_ticks_per_sec: /proc/self/auxv is unreadable when whytime runs
        // with file capabilities (non-dumpable), while the in-memory auxv always works.
        // SAFETY: getauxval only reads the process's saved auxiliary vector.
        let ticks = unsafe { libc::getauxval(libc::AT_CLKTCK) };
        let ticks_per_sec =
            std::num::NonZeroU64::new(ticks).context("AT_CLKTCK missing from auxv")?;
        let procfs = ProcFs::new();
        let table = ProcTable::new(
            procfs,
            Config {
                start_clock: StartClock::BootNs { ticks_per_sec },
                read_environ: false,
                ..Config::default()
            },
        );

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
        let trace = Trace::new(child.pid(), Classifier::new(syscalls, home), table);
        Ok(Started::Running(Box::new(Self {
            tracer,
            syscalls: loaded.syscalls.is_ok(),
            command: Wrapped { child, signals },
            trace,
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
            syscalls,
            command,
            mut trace,
        } = self;
        let mut maps = tracer.detach();
        // Programs still running on other CPUs commit within microseconds.
        std::thread::sleep(Duration::from_millis(2));
        maps.drain(|record| trace.ingest(record));
        trace.sweep(&maps.tasks(), end);
        let meta = Meta {
            command: args
                .command
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
            wall_ns: 0,
            ended_by,
            exit_code,
            dropped: maps.dropped(),
            syscalls,
        };
        drop(maps);

        report(&trace, end, meta, args.json);
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
            self.tracer.drain(|record| trace.ingest(record));
            let deadline = duration_ns
                .zip(trace.window.start)
                .map(|(d, start)| start.saturating_add(d));
            let now = monotonic_ns();
            if let Some(deadline) = deadline
                && now >= deadline
            {
                return Ok(Outcome::Deadline(deadline));
            }
            let timeout = deadline.map_or(-1, |deadline| {
                i32::try_from((deadline - now).div_ceil(1_000_000)).unwrap_or(i32::MAX)
            });
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

/// Attributes the window `[exec, end)` and writes the report to stderr. `meta.wall_ns` is
/// filled in here.
fn report(trace: &Trace, end: u64, mut meta: Meta, json: bool) {
    let (Some(root), Some(start)) = (trace.root, trace.window.start) else {
        eprintln!(
            "whytime: the command's exec was not observed ({} records lost); no report",
            meta.dropped
        );
        return;
    };
    let end = end.max(start);
    meta.wall_ns = end - start;
    let report = Report::new(trace, attribute::attribute(trace, root, start, end), meta);
    let mut err = io::stderr().lock();
    let written = if json {
        report.render_json(&mut err)
    } else {
        report.render_human(&mut err)
    };
    if let Err(e) = written.and_then(|()| err.flush()) {
        log::error!("writing the report: {e}");
    }
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
