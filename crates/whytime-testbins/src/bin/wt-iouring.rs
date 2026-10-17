//! `wt-iouring CODE`: sets up an io_uring with a submission-queue polling thread (`iou-sqp`, a
//! thread of this process the kernel creates without `sched_process_fork`), then exits with
//! CODE. The polling thread exits on its own after the group exit, often last of all. Exits
//! 77 when io_uring is unavailable (`kernel.io_uring_disabled`, seccomp, old kernel).

/// `IORING_SETUP_SQPOLL`.
const SETUP_SQPOLL: u32 = 1 << 1;

fn main() {
    let code: i32 = whytime_testbins::arg(1, "wt-iouring CODE");
    // struct io_uring_params: 120 bytes, `flags` the third u32.
    let mut params = [0_u32; 30];
    params[2] = SETUP_SQPOLL;
    // SAFETY: io_uring_setup reads and fills `params`, a zeroed io_uring_params.
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 4, params.as_mut_ptr()) };
    if fd < 0 {
        eprintln!("io_uring_setup: {}", std::io::Error::last_os_error());
        std::process::exit(77);
    }
    std::process::exit(code);
}
