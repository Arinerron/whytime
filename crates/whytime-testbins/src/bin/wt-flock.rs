//! `wt-flock DIR MS`: a short-lived process blocks on a `flock` that a sibling holds for MS
//! milliseconds, in the fresh directory DIR.
//!
//! The parent creates DIR and `DIR/lock`, starts a holder (`wt-flock hold FILE MS`: takes the
//! lock, reports it on stdout, sleeps MS, unlocks, exits at EOF on stdin) and then a waiter
//! (`wt-flock wait FILE`: blocks in `flock`, exits as soon as it gets the lock). Once
//! `/proc/<waiter>/syscall` shows the waiter asleep in `flock`, the parent renames DIR to
//! `DIR.moved`, so only a path captured when the waiter blocked still names DIR. It then waits
//! for the waiter, lets the holder exit, and removes everything. The holder outlives the waiter
//! so the waiter is the only child that exits during the parent's wait.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const USAGE: &str = "wt-flock DIR MS";

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("hold") => hold(),
        Some("wait") => {
            let file: PathBuf = whytime_testbins::arg(2, USAGE);
            lock(&open(&file));
        }
        _ => run(),
    }
}

/// `flock(LOCK_EX)` on `file`, blocking until it is granted.
fn lock(file: &File) {
    flock(file, libc::LOCK_EX);
}

fn flock(file: &File, op: libc::c_int) {
    // SAFETY: plain syscall on a descriptor `file` owns.
    let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
    assert_eq!(rc, 0, "flock: {}", std::io::Error::last_os_error());
}

fn open(path: &Path) -> File {
    File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()))
}

/// Holder: takes the lock, tells the parent, keeps it for MS milliseconds, then lingers until
/// the parent closes its stdin.
fn hold() {
    let file: PathBuf = whytime_testbins::arg(2, USAGE);
    let ms: u64 = whytime_testbins::arg(3, USAGE);
    let file = open(&file);
    lock(&file);
    let mut stdout = std::io::stdout();
    stdout.write_all(b"1").expect("write");
    stdout.flush().expect("flush");
    std::thread::sleep(whytime_testbins::millis(ms));
    flock(&file, libc::LOCK_UN);
    std::io::copy(&mut std::io::stdin(), &mut std::io::sink()).expect("read stdin");
}

fn run() {
    let dir: PathBuf = whytime_testbins::arg(1, USAGE);
    let ms: u64 = whytime_testbins::arg(2, USAGE);
    let exe = std::env::current_exe().expect("current_exe");
    std::fs::create_dir(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let file = dir.join("lock");
    File::create(&file).unwrap_or_else(|e| panic!("create {}: {e}", file.display()));

    let mut holder = Command::new(&exe)
        .arg("hold")
        .arg(&file)
        .arg(ms.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn holder");
    let mut held = [0_u8; 1];
    holder
        .stdout
        .take()
        .expect("holder stdout")
        .read_exact(&mut held)
        .expect("holder did not take the lock");
    let mut waiter = Command::new(&exe)
        .arg("wait")
        .arg(&file)
        .spawn()
        .expect("spawn waiter");

    wait_in_flock(waiter.id());
    let mut moved = dir.clone().into_os_string();
    moved.push(".moved");
    let moved = PathBuf::from(moved);
    std::fs::rename(&dir, &moved).expect("rename");
    assert!(waiter.wait().expect("wait waiter").success(), "waiter failed");
    drop(holder.stdin.take());
    assert!(holder.wait().expect("wait holder").success(), "holder failed");
    std::fs::remove_file(moved.join("lock")).expect("remove lock");
    std::fs::remove_dir(&moved).expect("remove dir");
}

/// Returns once `pid` is switched out inside `flock`.
fn wait_in_flock(pid: u32) {
    let path = format!("/proc/{pid}/syscall");
    let flock = libc::SYS_flock.to_string();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = std::fs::read_to_string(&path).unwrap_or_default();
        if now.split_whitespace().next() == Some(flock.as_str()) {
            return;
        }
        assert!(Instant::now() < deadline, "waiter never blocked in flock");
        std::thread::sleep(Duration::from_millis(1));
    }
}
