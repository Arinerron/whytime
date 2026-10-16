//! Kernel/user ABI of whytime, single-sourced with [`wire`].
//!
//! The BPF program (`whytime-bpf/bpf/whytime.bpf.c`) includes the C header rendered by
//! [`header`] (feature `std`, used by the build script); the loader decodes ring buffer records
//! and reads the `tasks` map with the same Rust types. Every size, alignment and field offset is
//! pinned by `_Static_assert`s in the header, so drift is a clang error.
//!
//! # Records
//!
//! Every ring buffer record starts with an [`EvHeader`] whose `kind` is one of the `EV_*`
//! constants. Records that close an accounting segment carry a [`CpuSegment`]: the on-CPU and
//! preempted-runqueue nanoseconds the thread accumulated in kernel since `start`, up to the
//! record's own boundary timestamp. Chaining segments, episodes and exits gives a gap-free
//! timeline per thread.

#![no_std]
#![warn(missing_docs)]

wire::wire! {
    /// Common prefix of every ring buffer record.
    pub struct EvHeader {
        /// One of the `EV_*` constants.
        pub kind: u32,
        /// Kernel thread id of the subject task.
        pub tid: u32,
        /// Thread-group id of the subject task.
        pub tgid: u32,
        /// Zero.
        pub _pad: u32,
        /// `bpf_ktime_get_ns()` (`CLOCK_MONOTONIC`) when the record was produced.
        pub ts: u64,
    }

    /// Time a thread spent on-CPU or preempted-but-runnable since `start`.
    pub struct CpuSegment {
        /// Segment start (`CLOCK_MONOTONIC` ns); its end is given by the enclosing record.
        pub start: u64,
        /// On-CPU nanoseconds within the segment.
        pub run_ns: u64,
        /// Nanoseconds runnable but preempted (waiting for a CPU) within the segment.
        pub rq_ns: u64,
    }

    /// The syscall a thread is in, with what the kernel knows about its file descriptor.
    pub struct SysInfo {
        /// Syscall number, or `NR_NONE` outside syscalls.
        pub nr: i32,
        /// First argument when it is a file descriptor, else -1.
        pub fd: i32,
        /// `inode->i_mode & S_IFMT` of the descriptor's file; 0 when unknown.
        pub mode: u32,
        /// `file->f_flags` of the descriptor (`O_DSYNC`, `O_SYNC`, ...).
        pub f_flags: u32,
        /// Inode number of the descriptor's file.
        pub ino: u64,
        /// Kernel `dev_t` (`major << 20 | minor`) of the file's superblock.
        pub dev: u32,
        /// Socket address family (`AF_INET`, `AF_INET6`, `AF_UNIX`); 0 when not a socket.
        pub family: u16,
        /// Peer port in host byte order (`connect` target or the socket's peer).
        pub port: u16,
        /// Peer address: 4 bytes for IPv4, 16 for IPv6, network order.
        pub addr: [u8; 16],
    }

    /// A tracked task forked a process or thread (`sched_process_fork`).
    pub struct ForkRecord {
        /// `tid`/`tgid` are the parent's.
        pub hdr: EvHeader,
        /// Thread id of the new task.
        pub child_tid: u32,
        /// Thread-group id of the new task; equal to `hdr.tgid` for a thread.
        pub child_tgid: u32,
        /// `start_boottime` (ns) of the new task.
        pub child_start: u64,
    }

    /// A tracked task exec'd (`sched_process_exec`).
    pub struct ExecRecord {
        /// `tid` is the post-exec thread id (the thread-group id).
        pub hdr: EvHeader,
        /// Accounting up to the exec; the next segment starts at `hdr.ts`.
        pub seg: CpuSegment,
        /// `start_boottime` (ns) of the thread-group leader: the procctx key start.
        pub start: u64,
        /// Thread-group id of the real parent.
        pub ppid: u32,
        /// Thread id before the exec; differs from `hdr.tid` when a non-leader thread exec'd.
        pub old_tid: u32,
        /// New `comm`.
        pub comm: [u8; 16],
        /// Bytes of `argv` captured (NUL-separated).
        pub argv_len: u32,
        /// Zero.
        pub _pad: u32,
        /// Leading bytes of the new argument vector.
        pub argv: [u8; 256],
    }

    /// One block → wake → run cycle of a tracked thread, emitted when it runs again.
    pub struct EpisodeRecord {
        /// `ts` is the switch-in time that ended the cycle.
        pub hdr: EvHeader,
        /// Accounting up to `block_ts`; the next segment starts at `hdr.ts`.
        pub seg: CpuSegment,
        /// Voluntary switch-out time.
        pub block_ts: u64,
        /// `sched_waking` time; 0 when the wakeup was not observed.
        pub wake_ts: u64,
        /// The syscall the thread blocked in.
        pub sys: SysInfo,
        /// Thread id of the task that woke it (0 when unknown).
        pub waker_tid: u32,
        /// Thread-group id of the task that woke it (0 when unknown).
        pub waker_tgid: u32,
        /// `prev_state` at the switch-out (`TASK_INTERRUPTIBLE`, `TASK_UNINTERRUPTIBLE`, ...).
        pub block_state: u32,
        /// Zero.
        pub _pad: u32,
    }

    /// A tracked thread exited (`sched_process_exit`).
    pub struct ExitRecord {
        /// Header of the exiting thread.
        pub hdr: EvHeader,
        /// Accounting up to the exit.
        pub seg: CpuSegment,
        /// `start_boottime` (ns) of the thread-group leader.
        pub start: u64,
        /// `task->exit_code` (wait status encoding).
        pub code: i32,
        /// 1 when this was the last thread of its group.
        pub group_dead: u32,
    }

    /// Value of the `tasks` map: the in-kernel state of one tracked thread.
    pub struct TaskState {
        /// The open accounting segment.
        pub seg: CpuSegment,
        /// Time of the last state transition (switch-in, switch-out or creation).
        pub last_ts: u64,
        /// Time of the last voluntary switch-out.
        pub block_ts: u64,
        /// Time of the wakeup that ended the current block; 0 while blocked.
        pub wake_ts: u64,
        /// The syscall in flight.
        pub sys: SysInfo,
        /// Thread-group id.
        pub tgid: u32,
        /// One of the `ST_*` constants.
        pub state: u32,
        /// `prev_state` of the last voluntary switch-out.
        pub block_state: u32,
        /// Thread id of the waker of the current block.
        pub waker_tid: u32,
        /// Thread-group id of the waker of the current block.
        pub waker_tgid: u32,
        /// Zero.
        pub _pad: u32,
    }
}

wire::wire_consts! {
    /// Constants shared with the BPF program.
    pub group CONSTS;
    /// [`ForkRecord`].
    pub const EV_FORK: u32 = 1;
    /// [`ExecRecord`].
    pub const EV_EXEC: u32 = 2;
    /// [`EpisodeRecord`].
    pub const EV_EPISODE: u32 = 3;
    /// [`ExitRecord`].
    pub const EV_EXIT: u32 = 4;

    /// [`TaskState::state`]: on a CPU.
    pub const ST_RUNNING: u32 = 1;
    /// Runnable but not on a CPU: new, or preempted.
    pub const ST_RUNNABLE: u32 = 2;
    /// Switched out voluntarily, not yet woken.
    pub const ST_BLOCKED: u32 = 3;
    /// Woken after blocking, waiting for a CPU.
    pub const ST_WOKEN: u32 = 4;

    /// [`SysInfo::nr`] outside syscalls.
    pub const NR_NONE: i32 = -1;

    /// `sys_flags` bit: argument 0 is a file descriptor to describe.
    pub const SYSF_FD0: u32 = 1;
    /// `sys_flags` bit: arguments 1 and 2 are a user `sockaddr` and its length.
    pub const SYSF_SOCKADDR: u32 = 2;
    /// Entries of the `sys_flags` array (syscall numbers above are ignored).
    pub const SYS_TABLE_LEN: u32 = 512;

    /// `stats` slot: ring buffer reservations that failed (records lost).
    pub const STAT_RING_FULL: u32 = 0;
    /// `stats` slot: threads that could not be added to the `tasks` map.
    pub const STAT_TASKS_FULL: u32 = 1;
    /// `stats` slot: processes that could not be added to the `tracked` map.
    pub const STAT_TRACKED_FULL: u32 = 2;
    /// Number of `stats` slots.
    pub const STAT_NR: u32 = 3;

    /// Capacity of the `tasks` map (tracked threads alive at once).
    pub const TASKS_MAX: u32 = 32768;
    /// Capacity of the `tracked` map (tracked processes alive at once).
    pub const TRACKED_MAX: u32 = 16384;
    /// Size of the `events` ring buffer in bytes.
    pub const RINGBUF_BYTES: u32 = 4 << 20;
}

/// The C header for the BPF program: every record, then [`CONSTS`].
#[cfg(feature = "std")]
pub fn header() -> wire::HeaderBuilder {
    let mut header = wire::HeaderBuilder::new("WHYTIME_WIRE_H");
    header
        .structs::<EvHeader>()
        .structs::<CpuSegment>()
        .structs::<SysInfo>()
        .structs::<ForkRecord>()
        .structs::<ExecRecord>()
        .structs::<EpisodeRecord>()
        .structs::<ExitRecord>()
        .structs::<TaskState>()
        .consts(&CONSTS);
    header
}

#[cfg(feature = "user")]
wire::impl_aya_pod!(TaskState);
