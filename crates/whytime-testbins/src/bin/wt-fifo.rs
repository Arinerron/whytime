//! `wt-fifo read FIFO FILE N` waits N times for another process: in even rounds with `poll`
//! on an inotify watch of FILE, in odd rounds in a blocking one-byte `read` of FIFO.
//! `wt-fifo write FIFO FILE N MS` names itself `wt-fifo-writer`, waits up to a minute for a
//! reader to open FIFO, then N times sleeps MS milliseconds and appends a byte to FILE (even
//! rounds) or writes one to FIFO (odd rounds). Started outside the traced tree, the writer is
//! the out-of-tree waker of every wait of the reader. FILE must exist.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn main() {
    let usage = "wt-fifo read FIFO FILE N | wt-fifo write FIFO FILE N MS";
    let mode: String = whytime_testbins::arg(1, usage);
    let fifo: PathBuf = whytime_testbins::arg(2, usage);
    let file: PathBuf = whytime_testbins::arg(3, usage);
    let rounds: u32 = whytime_testbins::arg(4, usage);
    match mode.as_str() {
        "read" => read(&fifo, &file, rounds),
        "write" => {
            let interval = whytime_testbins::millis(whytime_testbins::arg(5, usage));
            write(&fifo, &file, rounds, interval);
        }
        _ => {
            eprintln!("usage: {usage}");
            std::process::exit(2);
        }
    }
}

/// The reader: `rounds` waits, alternating inotify `poll` and FIFO `read`.
fn read(fifo: &Path, file: &Path, rounds: u32) {
    // Watch first: the writer starts only once FIFO is open for reading.
    let mut watch = inotify_modify(file);
    let mut fifo = File::open(fifo).unwrap_or_else(|e| panic!("open {}: {e}", fifo.display()));
    let mut events = [0_u8; 4096];
    let mut byte = [0_u8];
    for round in 0..rounds {
        if round % 2 == 0 {
            let mut pfd = libc::pollfd {
                fd: watch.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is one valid pollfd for the duration of the call.
            let ready = unsafe { libc::poll(&raw mut pfd, 1, -1) };
            assert_eq!(ready, 1, "poll: {}", io::Error::last_os_error());
            let read = watch.read(&mut events).expect("read inotify");
            assert!(read > 0, "empty inotify read");
        } else {
            fifo.read_exact(&mut byte).expect("read fifo");
        }
    }
}

/// An inotify descriptor watching `path` for `IN_MODIFY`.
fn inotify_modify(path: &Path) -> File {
    let name = CString::new(path.as_os_str().as_bytes()).expect("path without NUL");
    // SAFETY: inotify_init1 has no memory arguments; the new descriptor is owned by the
    // returned File only.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    assert!(fd >= 0, "inotify_init1: {}", io::Error::last_os_error());
    // SAFETY: `fd` is a fresh descriptor nothing else owns.
    let watch = unsafe { File::from_raw_fd(fd) };
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let added = unsafe { libc::inotify_add_watch(fd, name.as_ptr(), libc::IN_MODIFY) };
    assert!(added >= 0, "inotify_add_watch {}: {}", path.display(), io::Error::last_os_error());
    watch
}

/// The writer: one event per round, alternating an append to `file` and a FIFO write.
fn write(fifo: &Path, file: &Path, rounds: u32, interval: Duration) {
    // SAFETY: PR_SET_NAME reads a NUL-terminated string of at most 16 bytes.
    unsafe { libc::prctl(libc::PR_SET_NAME, c"wt-fifo-writer".as_ptr()) };
    let mut fifo = open_writer(fifo);
    let mut file = OpenOptions::new()
        .append(true)
        .open(file)
        .unwrap_or_else(|e| panic!("open {}: {e}", file.display()));
    for round in 0..rounds {
        std::thread::sleep(interval);
        if round % 2 == 0 {
            file.write_all(b"x").expect("append");
        } else {
            fifo.write_all(b"x").expect("write fifo");
        }
    }
}

/// Opens `path` for writing once a reader has it open (a non-blocking open fails with ENXIO
/// until then).
fn open_writer(path: &Path) -> File {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(fifo) => return fifo,
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("open {}: {e}", path.display()),
        }
    }
}
