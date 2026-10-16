//! The syscalls whytime understands: what blocking in each one means, and which ones the BPF
//! program should describe the file descriptor (or `connect` target) of.
//!
//! Numbers come from `libc`, so the table follows the build target's syscall ABI; the kernel
//! side only sees the `SYSF_*` bits user space writes into its `sys_flags` array.

use libc::c_long;
use whytime_abi::{SYS_TABLE_LEN, SYSF_FD0, SYSF_SOCKADDR};

/// What a thread blocked in a syscall is waiting for, before looking at its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// I/O on argument 0, classified by the descriptor's type; `write` marks syscalls that
    /// wait for durability when the file was opened `O_DSYNC`/`O_SYNC`.
    FdIo {
        /// The syscall writes data.
        write: bool,
    },
    /// `connect`: the target address is read from user memory.
    Connect,
    /// Explicit durability barrier (`fsync`, `fdatasync`, `sync_file_range`, ...).
    Fsync,
    /// Path-based filesystem work (`openat`, `statx`, `unlinkat`, ...).
    PathFs,
    /// Timer sleep.
    Sleep,
    /// Futex wait (locks, condition variables, thread joins).
    Futex,
    /// Waiting for a child to change state.
    Wait,
    /// Readiness multiplexing (`poll`, `select`, `epoll_wait`).
    Poll,
    /// Waiting for a signal.
    Signal,
    /// Known, but not a class of its own.
    Other,
}

impl Kind {
    /// `sys_flags` bits for the BPF program.
    fn bpf_flags(self) -> u32 {
        match self {
            Self::FdIo { .. } | Self::Fsync => SYSF_FD0,
            Self::Connect => SYSF_FD0 | SYSF_SOCKADDR,
            Self::PathFs
            | Self::Sleep
            | Self::Futex
            | Self::Wait
            | Self::Poll
            | Self::Signal
            | Self::Other => 0,
        }
    }
}

const READ: Kind = Kind::FdIo { write: false };
const WRITE: Kind = Kind::FdIo { write: true };

/// Syscalls with a meaning on every architecture.
const COMMON: &[(c_long, &str, Kind)] = &[
    (libc::SYS_read, "read", READ),
    (libc::SYS_readv, "readv", READ),
    (libc::SYS_pread64, "pread64", READ),
    (libc::SYS_preadv, "preadv", READ),
    (libc::SYS_preadv2, "preadv2", READ),
    (libc::SYS_recvfrom, "recvfrom", READ),
    (libc::SYS_recvmsg, "recvmsg", READ),
    (libc::SYS_recvmmsg, "recvmmsg", READ),
    (libc::SYS_accept, "accept", READ),
    (libc::SYS_accept4, "accept4", READ),
    (libc::SYS_getdents64, "getdents64", READ),
    (libc::SYS_splice, "splice", READ),
    (libc::SYS_flock, "flock", READ),
    (libc::SYS_fcntl, "fcntl", READ),
    (libc::SYS_ioctl, "ioctl", READ),
    (libc::SYS_write, "write", WRITE),
    (libc::SYS_writev, "writev", WRITE),
    (libc::SYS_pwrite64, "pwrite64", WRITE),
    (libc::SYS_pwritev, "pwritev", WRITE),
    (libc::SYS_pwritev2, "pwritev2", WRITE),
    (libc::SYS_sendto, "sendto", WRITE),
    (libc::SYS_sendmsg, "sendmsg", WRITE),
    (libc::SYS_sendmmsg, "sendmmsg", WRITE),
    (libc::SYS_sendfile, "sendfile", WRITE),
    (libc::SYS_copy_file_range, "copy_file_range", WRITE),
    (libc::SYS_fallocate, "fallocate", WRITE),
    (libc::SYS_ftruncate, "ftruncate", WRITE),
    (libc::SYS_connect, "connect", Kind::Connect),
    (libc::SYS_fsync, "fsync", Kind::Fsync),
    (libc::SYS_fdatasync, "fdatasync", Kind::Fsync),
    (libc::SYS_sync_file_range, "sync_file_range", Kind::Fsync),
    (libc::SYS_syncfs, "syncfs", Kind::Fsync),
    (libc::SYS_sync, "sync", Kind::Fsync),
    (libc::SYS_msync, "msync", Kind::Fsync),
    (libc::SYS_openat, "openat", Kind::PathFs),
    (libc::SYS_openat2, "openat2", Kind::PathFs),
    (libc::SYS_newfstatat, "newfstatat", Kind::PathFs),
    (libc::SYS_statx, "statx", Kind::PathFs),
    (libc::SYS_faccessat, "faccessat", Kind::PathFs),
    (libc::SYS_faccessat2, "faccessat2", Kind::PathFs),
    (libc::SYS_unlinkat, "unlinkat", Kind::PathFs),
    (libc::SYS_renameat, "renameat", Kind::PathFs),
    (libc::SYS_renameat2, "renameat2", Kind::PathFs),
    (libc::SYS_mkdirat, "mkdirat", Kind::PathFs),
    (libc::SYS_readlinkat, "readlinkat", Kind::PathFs),
    (libc::SYS_truncate, "truncate", Kind::PathFs),
    (libc::SYS_execve, "execve", Kind::PathFs),
    (libc::SYS_execveat, "execveat", Kind::PathFs),
    (libc::SYS_nanosleep, "nanosleep", Kind::Sleep),
    (libc::SYS_clock_nanosleep, "clock_nanosleep", Kind::Sleep),
    (libc::SYS_futex, "futex", Kind::Futex),
    (libc::SYS_futex_waitv, "futex_waitv", Kind::Futex),
    (libc::SYS_wait4, "wait4", Kind::Wait),
    (libc::SYS_waitid, "waitid", Kind::Wait),
    (libc::SYS_ppoll, "ppoll", Kind::Poll),
    (libc::SYS_pselect6, "pselect6", Kind::Poll),
    (libc::SYS_epoll_pwait, "epoll_pwait", Kind::Poll),
    (libc::SYS_epoll_pwait2, "epoll_pwait2", Kind::Poll),
    (libc::SYS_rt_sigsuspend, "rt_sigsuspend", Kind::Signal),
    (libc::SYS_rt_sigtimedwait, "rt_sigtimedwait", Kind::Signal),
    (libc::SYS_clone, "clone", Kind::Other),
    (libc::SYS_clone3, "clone3", Kind::Other),
    (libc::SYS_mmap, "mmap", Kind::Other),
    (libc::SYS_munmap, "munmap", Kind::Other),
    (libc::SYS_mprotect, "mprotect", Kind::Other),
    (libc::SYS_madvise, "madvise", Kind::Other),
    (libc::SYS_exit_group, "exit_group", Kind::Other),
    (libc::SYS_io_uring_enter, "io_uring_enter", Kind::Other),
    (libc::SYS_io_getevents, "io_getevents", Kind::Other),
];

/// Legacy syscalls that only some architectures (x86-64 among them) still have.
#[cfg(target_arch = "x86_64")]
const LEGACY: &[(c_long, &str, Kind)] = &[
    (libc::SYS_open, "open", Kind::PathFs),
    (libc::SYS_creat, "creat", Kind::PathFs),
    (libc::SYS_stat, "stat", Kind::PathFs),
    (libc::SYS_lstat, "lstat", Kind::PathFs),
    (libc::SYS_access, "access", Kind::PathFs),
    (libc::SYS_unlink, "unlink", Kind::PathFs),
    (libc::SYS_rename, "rename", Kind::PathFs),
    (libc::SYS_mkdir, "mkdir", Kind::PathFs),
    (libc::SYS_rmdir, "rmdir", Kind::PathFs),
    (libc::SYS_readlink, "readlink", Kind::PathFs),
    (libc::SYS_poll, "poll", Kind::Poll),
    (libc::SYS_select, "select", Kind::Poll),
    (libc::SYS_epoll_wait, "epoll_wait", Kind::Poll),
    (libc::SYS_pause, "pause", Kind::Signal),
    (libc::SYS_vfork, "vfork", Kind::Other),
];
#[cfg(not(target_arch = "x86_64"))]
const LEGACY: &[(c_long, &str, Kind)] = &[];

/// One known syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syscall {
    /// Kernel name, without the `sys_` prefix.
    pub name: &'static str,
    /// What blocking in it means.
    pub kind: Kind,
}

/// Known syscalls indexed by number.
#[derive(Debug)]
pub struct SyscallTable {
    by_nr: Vec<Option<Syscall>>,
}

impl SyscallTable {
    /// The table for the build target.
    pub fn new() -> Self {
        let mut by_nr = vec![None; SYS_TABLE_LEN as usize];
        for &(nr, name, kind) in COMMON.iter().chain(LEGACY) {
            if let Some(slot) = usize::try_from(nr).ok().and_then(|nr| by_nr.get_mut(nr)) {
                *slot = Some(Syscall { name, kind });
            }
        }
        Self { by_nr }
    }

    /// The syscall numbered `nr`, if whytime knows it.
    pub fn get(&self, nr: i32) -> Option<Syscall> {
        usize::try_from(nr)
            .ok()
            .and_then(|nr| self.by_nr.get(nr).copied().flatten())
    }

    /// `(nr, SYSF_* bits)` for every syscall the BPF program should describe.
    pub fn bpf_flags(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.by_nr.iter().zip(0_u32..).filter_map(|(entry, nr)| {
            let flags = entry.as_ref()?.kind.bpf_flags();
            (flags != 0).then_some((nr, flags))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_syscalls_are_described_and_connect_reads_its_sockaddr() {
        let table = SyscallTable::new();
        let flags: std::collections::HashMap<u32, u32> = table.bpf_flags().collect();
        let nr = |n: c_long| u32::try_from(n).unwrap();
        assert_eq!(flags[&nr(libc::SYS_read)], SYSF_FD0);
        assert_eq!(flags[&nr(libc::SYS_fdatasync)], SYSF_FD0);
        assert_eq!(flags[&nr(libc::SYS_connect)], SYSF_FD0 | SYSF_SOCKADDR);
        assert!(!flags.contains_key(&nr(libc::SYS_futex)));
        assert!(!flags.contains_key(&nr(libc::SYS_openat)));
    }

    #[test]
    fn unknown_and_out_of_range_numbers_are_none() {
        let table = SyscallTable::new();
        assert_eq!(table.get(-1), None);
        assert_eq!(table.get(i32::MAX), None);
        assert_eq!(
            table
                .get(i32::try_from(libc::SYS_wait4).unwrap())
                .map(|s| s.kind),
            Some(Kind::Wait)
        );
    }
}
