//! `wt-poll ADDR N`: N times, connects to ADDR, waits until the reply is readable (with
//! `epoll_wait` and `poll` in turn), then reads until the server closes.

use std::io::{self, Read as _};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd as _, RawFd};

fn main() {
    let usage = "wt-poll ADDR N";
    let addr: SocketAddr = whytime_testbins::arg(1, usage);
    let rounds: u32 = whytime_testbins::arg(2, usage);
    let mut reply = Vec::new();
    for round in 0..rounds {
        let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
        if round % 2 == 0 {
            epoll_readable(stream.as_raw_fd());
        } else {
            poll_readable(stream.as_raw_fd());
        }
        reply.clear();
        stream.read_to_end(&mut reply).expect("read");
    }
}

/// Blocks in `epoll_wait` until `fd` is readable.
fn epoll_readable(fd: RawFd) {
    // SAFETY: plain syscalls on a descriptor created and closed here, and on `fd`, which the
    // caller keeps open; `event` outlives both calls that use it.
    unsafe {
        let ep = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        assert!(ep >= 0, "epoll_create1: {}", io::Error::last_os_error());
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN.cast_unsigned(),
            u64: 0,
        };
        let added = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &raw mut event);
        assert_eq!(added, 0, "epoll_ctl: {}", io::Error::last_os_error());
        let ready = libc::epoll_wait(ep, &raw mut event, 1, -1);
        assert_eq!(ready, 1, "epoll_wait: {}", io::Error::last_os_error());
        libc::close(ep);
    }
}

/// Blocks in `poll` until `fd` is readable.
fn poll_readable(fd: RawFd) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is one valid pollfd for the duration of the call.
    let ready = unsafe { libc::poll(&raw mut pfd, 1, -1) };
    assert_eq!(ready, 1, "poll: {}", io::Error::last_os_error());
}
