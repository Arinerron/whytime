//! Starting the wrapped command so that tracing covers it from its first instruction.
//!
//! The child is forked, then parks on a pipe until the parent has added its pid to the
//! tracked set; released, it drops to the invoking user (under sudo), restores default signal
//! handling and execs. A second, close-on-exec pipe reports a failed exec back to the parent.
//! Everything the child does after fork is async-signal-safe: all allocation happens before.

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::ptr;

/// Signals whytime handles itself; the child gets their defaults back before exec.
pub const RESET_SIGNALS: [libc::c_int; 5] = [
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGPIPE,
];

/// Credentials the child switches to before exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    /// User id.
    pub uid: libc::uid_t,
    /// Primary group id.
    pub gid: libc::gid_t,
    /// Supplementary groups.
    pub groups: Vec<libc::gid_t>,
}

/// Why the command did not start.
#[derive(Debug)]
pub enum StartError {
    /// Dropping privileges failed in the child.
    Setup(io::Error),
    /// `execvp` failed.
    Exec(io::Error),
}

/// A forked child, parked before exec.
#[derive(Debug)]
pub struct Child {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    go: OwnedFd,
    status: OwnedFd,
}

/// Stage byte the child writes before an errno.
const STAGE_SETUP: u8 = 0;
const STAGE_EXEC: u8 = 1;

impl Child {
    /// Forks the child for `argv`, parked until [`release`](Self::release).
    pub fn spawn(argv: &[OsString], creds: Option<&Credentials>) -> io::Result<Self> {
        let args: Vec<CString> = argv
            .iter()
            .map(|arg| CString::new(arg.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput)))
            .collect::<io::Result<_>>()?;
        let mut arg_ptrs: Vec<*const libc::c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        arg_ptrs.push(ptr::null());
        let (go_read, go_write) = pipe()?;
        let (status_read, status_write) = pipe()?;

        // SAFETY: whytime is single-threaded here, and the child only calls
        // async-signal-safe functions on memory prepared above before it execs or exits.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            // SAFETY: in the child; see `child_main`.
            unsafe { child_main(go_read.as_raw_fd(), status_write.as_raw_fd(), &arg_ptrs, creds) }
        }
        drop((go_read, status_write));
        // SAFETY: pidfd_open takes a pid and flags; the result is a new descriptor or -1.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: reaping our own child.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, ptr::null_mut(), 0);
            }
            return Err(err);
        }
        // SAFETY: `raw` is a fresh descriptor we own.
        let pidfd = unsafe { OwnedFd::from_raw_fd(RawFd::try_from(raw).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?) };
        Ok(Self {
            pid,
            pidfd,
            go: go_write,
            status: status_read,
        })
    }

    /// Process id.
    pub fn pid(&self) -> u32 {
        self.pid.unsigned_abs()
    }

    /// Lets the child exec and reports whether it did. On failure the child has exited and
    /// must still be reaped with [`wait`](Self::wait).
    pub fn release(&mut self) -> Result<(), StartError> {
        let go = [1_u8];
        // SAFETY: writing one byte from a valid buffer to our pipe.
        if unsafe { libc::write(self.go.as_raw_fd(), go.as_ptr().cast(), 1) } != 1 {
            return Err(StartError::Setup(io::Error::last_os_error()));
        }
        let mut msg = [0_u8; 5];
        let n = read_full(self.status.as_raw_fd(), &mut msg);
        if n < msg.len() {
            // Pipe closed by the successful exec (close-on-exec).
            return Ok(());
        }
        let err = io::Error::from_raw_os_error(i32::from_ne_bytes([msg[1], msg[2], msg[3], msg[4]]));
        Err(if msg[0] == STAGE_EXEC {
            StartError::Exec(err)
        } else {
            StartError::Setup(err)
        })
    }

    /// The pidfd: readable once the child has exited.
    pub fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }

    /// Sends `signal` to the child.
    pub fn signal(&self, signal: libc::c_int) {
        // SAFETY: pidfd_send_signal on our own pidfd; the pidfd cannot hit a recycled pid.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }

    /// Waits for the child to exit; returns the shell-convention exit code.
    pub fn wait(&self) -> io::Result<i32> {
        let mut status = 0;
        loop {
            // SAFETY: waiting for our own child with a valid status pointer.
            if unsafe { libc::waitpid(self.pid, &raw mut status, 0) } >= 0 {
                return Ok(crate::report::exit_code(status));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

/// The child between fork and exec. Never returns.
///
/// # Safety
///
/// Must only be called in a freshly forked child of a single-threaded process.
unsafe fn child_main(go: RawFd, status: RawFd, argv: &[*const libc::c_char], creds: Option<&Credentials>) -> ! {
    // SAFETY: only async-signal-safe calls on valid, pre-allocated memory.
    unsafe {
        let mut byte = 0_u8;
        if libc::read(go, (&raw mut byte).cast(), 1) != 1 {
            // The parent gave up before releasing us.
            libc::_exit(125);
        }
        if let Some(creds) = creds
            && (libc::setgroups(creds.groups.len(), creds.groups.as_ptr()) != 0
                || libc::setgid(creds.gid) != 0
                || libc::setuid(creds.uid) != 0)
        {
            report_and_exit(status, STAGE_SETUP, 125);
        }
        for signal in RESET_SIGNALS {
            libc::signal(signal, libc::SIG_DFL);
        }
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, ptr::null_mut());
        libc::execvp(argv[0], argv.as_ptr());
        let code = if *libc::__errno_location() == libc::ENOENT { 127 } else { 126 };
        report_and_exit(status, STAGE_EXEC, code);
    }
}

/// Writes `stage` and the current errno to the status pipe, then exits with `code`.
///
/// # Safety
///
/// Child-only; async-signal-safe.
unsafe fn report_and_exit(status: RawFd, stage: u8, code: libc::c_int) -> ! {
    // SAFETY: errno location is thread-local and valid; the buffer is on the stack.
    unsafe {
        let errno = (*libc::__errno_location()).to_ne_bytes();
        let msg = [stage, errno[0], errno[1], errno[2], errno[3]];
        libc::write(status, msg.as_ptr().cast(), msg.len());
        libc::_exit(code)
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 writes two descriptors into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh and owned by us.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Reads until `buf` is full or EOF; returns the bytes read.
fn read_full(fd: RawFd, buf: &mut [u8]) -> usize {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: reading into the unfilled tail of `buf`.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        match n {
            0 => break,
            n if n > 0 => done += n.unsigned_abs(),
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
            _ => break,
        }
    }
    done
}
