//! Starting the wrapped command so that tracing covers it from its first instruction, and
//! creating files as the invoking user.
//!
//! The child is forked, then parks on a pipe until the parent has added its pid to the
//! tracked set; released, it drops to the invoking user (under sudo), restores the signal
//! dispositions whytime inherited and execs. A second, close-on-exec pipe reports a failed
//! exec back to the parent. Everything the child does after fork is async-signal-safe: all
//! allocation happens before.

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

/// A signal and the disposition (`SIG_DFL` or `SIG_IGN`) the child sets before exec.
pub type Disposition = (libc::c_int, libc::sighandler_t);

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
    /// Forks the child for `argv`, parked until [`release`](Self::release); it sets
    /// `signals` before exec.
    pub fn spawn(
        argv: &[OsString],
        creds: Option<&Credentials>,
        signals: &[Disposition],
    ) -> io::Result<Self> {
        let cargs: Vec<CString> = argv
            .iter()
            .map(|arg| {
                CString::new(arg.as_bytes())
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
            })
            .collect::<io::Result<_>>()?;
        let mut arg_ptrs: Vec<*const libc::c_char> = cargs.iter().map(|a| a.as_ptr()).collect();
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
            unsafe {
                child_main(
                    go_read.as_raw_fd(),
                    status_write.as_raw_fd(),
                    &arg_ptrs,
                    creds,
                    signals,
                )
            }
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
        let pidfd = unsafe {
            OwnedFd::from_raw_fd(
                RawFd::try_from(raw).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
            )
        };
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
        let err =
            io::Error::from_raw_os_error(i32::from_ne_bytes([msg[1], msg[2], msg[3], msg[4]]));
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
unsafe fn child_main(
    go: RawFd,
    status: RawFd,
    argv: &[*const libc::c_char],
    creds: Option<&Credentials>,
    signals: &[Disposition],
) -> ! {
    // SAFETY: only async-signal-safe calls on valid, pre-allocated memory.
    unsafe {
        let mut byte = 0_u8;
        if libc::read(go, (&raw mut byte).cast(), 1) != 1 {
            // The parent gave up before releasing us.
            libc::_exit(125);
        }
        if let Some(creds) = creds
            && !become_user(creds)
        {
            report_and_exit(status, STAGE_SETUP, 125);
        }
        for &(signal, disposition) in signals {
            libc::signal(signal, disposition);
        }
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut empty);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const empty, ptr::null_mut());
        libc::execvp(argv[0], argv.as_ptr());
        let code = if *libc::__errno_location() == libc::ENOENT {
            127
        } else {
            126
        };
        report_and_exit(status, STAGE_EXEC, code);
    }
}

/// Switches to `creds` for good (groups, gid, then uid); false on failure, with errno set.
///
/// # Safety
///
/// Child-only (after fork, before exec or exit); async-signal-safe.
unsafe fn become_user(creds: &Credentials) -> bool {
    // SAFETY: plain credential syscalls; `groups` holds `len()` entries.
    unsafe {
        libc::setgroups(creds.groups.len(), creds.groups.as_ptr()) == 0
            && libc::setgid(creds.gid) == 0
            && libc::setuid(creds.uid) == 0
    }
}

/// Creates (or truncates) `path` for writing as `creds`' user: a short-lived child drops to
/// those credentials and opens it, so every permission check (each directory and symlink on
/// the way, the file itself) is that user's and a new file is theirs; the descriptor comes
/// back over a socket (`SCM_RIGHTS`). whytime, root under sudo, never opens it itself.
pub fn create_as(path: &Path, creds: &Credentials) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut fds = [0; 2];
    // SAFETY: socketpair writes two descriptors into `fds`.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are fresh and owned by us.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: the child only makes async-signal-safe calls on memory prepared above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: in the child.
        unsafe { open_child(theirs.as_raw_fd(), &path, creds) }
    }
    drop(theirs);
    let received = receive_fd(&ours);
    // SAFETY: reaping our own child, which exits right after sending.
    while unsafe { libc::waitpid(pid, ptr::null_mut(), 0) } < 0
        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
    {}
    received.map(File::from)
}

/// [`create_as`]'s child: becomes the user, opens `path` and sends back the errno (0 on
/// success) with the descriptor attached. Never returns.
///
/// # Safety
///
/// Child-only; async-signal-safe.
unsafe fn open_child(socket: RawFd, path: &CString, creds: &Credentials) -> ! {
    // SAFETY: async-signal-safe calls on valid memory; the cmsg buffer is sized by
    // CMSG_SPACE for one descriptor and aligned for `cmsghdr`.
    unsafe {
        // The user's process holds nothing of whytime's (BPF objects, other outputs).
        let keep = socket.unsigned_abs();
        libc::syscall(libc::SYS_close_range, 3_u32, keep.saturating_sub(1), 0_u32);
        libc::syscall(libc::SYS_close_range, keep + 1, u32::MAX, 0_u32);
        let fd = if become_user(creds) {
            libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o666,
            )
        } else {
            -1
        };
        let errno: libc::c_int = if fd < 0 { *libc::__errno_location() } else { 0 };
        let mut payload = errno.to_ne_bytes();
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        let mut control = CmsgBuf([0; CMSG_BYTES]);
        if fd >= 0 {
            msg.msg_control = control.0.as_mut_ptr().cast();
            msg.msg_controllen = CMSG_BYTES as _;
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        }
        let sent = libc::sendmsg(socket, &raw const msg, libc::MSG_NOSIGNAL);
        libc::_exit(i32::from(sent < 0))
    }
}

/// Control buffer bytes for one descriptor.
// SAFETY: CMSG_SPACE is arithmetic on its argument.
const CMSG_BYTES: usize = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;

/// A control message buffer aligned for `cmsghdr`.
#[repr(C, align(8))]
struct CmsgBuf([u8; CMSG_BYTES]);

/// Receives [`open_child`]'s message: the descriptor, or the error it got.
fn receive_fd(socket: &OwnedFd) -> io::Result<OwnedFd> {
    let mut payload = [0_u8; 4];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = CmsgBuf([0; CMSG_BYTES]);
    // SAFETY: msghdr is plain data; the pointers below stay valid during recvmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = CMSG_BYTES as _;
    let n = loop {
        // SAFETY: receiving into the buffers described by `msg`.
        let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break n;
        }
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CMSG_FIRSTHDR/CMSG_DATA walk the control buffer recvmsg filled.
    let fd = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        (!cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS)
            .then(|| OwnedFd::from_raw_fd(ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>())))
    };
    match (n, fd) {
        (4, Some(fd)) => Ok(fd),
        (4, None) => Err(io::Error::from_raw_os_error(i32::from_ne_bytes(payload))),
        _ => Err(io::Error::other("the process opening the file as the invoking user failed")),
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
