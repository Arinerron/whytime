//! `wt-vfork MS`: starts a child the way `posix_spawn` does, with `clone(CLONE_VM |
//! CLONE_VFORK)`, so the parent blocks in `clone` until the child execs. The child spins on
//! the CPU for MS milliseconds first, then execs `wt-sleep 0` (from the same directory); the
//! parent waits for it.

use std::ffi::{CString, c_char, c_int, c_void};
use std::hint::black_box;
use std::os::unix::ffi::OsStrExt as _;
use std::time::{Duration, Instant};

/// Everything the child uses, prepared before the clone: it shares the parent's memory and
/// must not allocate.
struct Spawn {
    burn: Duration,
    path: *const c_char,
    argv: *const *const c_char,
}

/// The child: spin, then exec.
extern "C" fn child(arg: *mut c_void) -> c_int {
    // SAFETY: `arg` is the parent's `Spawn`; the parent stays suspended in `clone` until this
    // child execs or exits.
    let spawn = unsafe { &*arg.cast::<Spawn>() };
    let until = Instant::now() + spawn.burn;
    let mut x = 0_u64;
    while Instant::now() < until {
        for i in 0..10_000 {
            x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
        }
    }
    black_box(x);
    // SAFETY: `path` and `argv` are NUL-terminated and outlive the exec.
    unsafe {
        libc::execv(spawn.path, spawn.argv);
        libc::_exit(127)
    }
}

fn main() {
    let ms = whytime_testbins::arg(1, "wt-vfork MS");
    let exe = std::env::current_exe().expect("current_exe");
    let sleep = exe.with_file_name("wt-sleep");
    let path = CString::new(sleep.as_os_str().as_bytes()).expect("NUL in path");
    let argv = [path.as_ptr(), c"0".as_ptr(), std::ptr::null()];
    let spawn = Spawn {
        burn: whytime_testbins::millis(ms),
        path: path.as_ptr(),
        argv: argv.as_ptr(),
    };
    let mut stack = vec![0_u8; 256 * 1024];
    // The stack grows down from its end; clone aligns it.
    let top = stack.as_mut_ptr().wrapping_add(stack.len()).cast::<c_void>();
    let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
    // SAFETY: `child` runs on its own stack and only reads `spawn`, which outlives it.
    let pid = unsafe { libc::clone(child, top, flags, (&raw const spawn).cast_mut().cast()) };
    assert!(pid > 0, "clone: {}", std::io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: plain waitpid on our own child.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(waited, pid, "waitpid: {}", std::io::Error::last_os_error());
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child failed: status {status:#x}"
    );
}
