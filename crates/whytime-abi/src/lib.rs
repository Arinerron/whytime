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
        /// Longest single runnable-but-preempted stretch within the segment; 0 when none.
        pub preempt_max_ns: u64,
        /// Thread-group id of the CPU holder during that stretch: the task that preempted
        /// this one, or for a new task the one that ran just before its first switch-in.
        pub preempt_tgid: u32,
        /// Zero.
        pub _pad: u32,
        /// `comm` of that CPU holder.
        pub preempt_comm: [u8; 16],
    }

    /// The syscall a thread is in, with what the kernel knows about its file descriptor.
    ///
    /// `nr` is set at `sys_enter`; the other fields only describe this syscall when the
    /// accompanying [`SysDetail::flags`] has `SYSD_DESCRIBED` (the description is taken when
    /// the syscall first blocks).
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

    /// Raw arguments of the syscall in flight and what its first block revealed beyond
    /// [`SysInfo`]: the file's filesystem and its path, captured in kernel.
    pub struct SysDetail {
        /// Arguments 0..3, saved at `sys_enter`.
        pub args: [u64; 3],
        /// `i_sb->s_magic` (low 32 bits) of the descriptor's file; 0 when not described.
        pub magic: u32,
        /// `SYSD_*` bits.
        pub flags: u32,
        /// Bytes of `path` in use.
        pub path_len: u32,
        /// Zero.
        pub _pad: u32,
        /// Name components of the file, leaf first, each NUL-terminated (`lock\0dir\0home\0`
        /// is `/home/dir/lock`). Only whole components are kept.
        pub path: [u8; PATH_BYTES as usize],
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
        /// Thread id of the task that woke it; 0 when unknown or when the wakeup came from
        /// interrupt or softirq context (where the current task is unrelated).
        pub waker_tid: u32,
        /// Thread-group id of the task that woke it; 0 under the same conditions.
        pub waker_tgid: u32,
        /// `prev_state` at the switch-out (`TASK_INTERRUPTIBLE`, `TASK_UNINTERRUPTIBLE`, ...).
        pub block_state: u32,
        /// Zero.
        pub _pad: u32,
        /// Syscall arguments, filesystem and path of the file the thread blocked on.
        pub detail: SysDetail,
        /// `EPF_*` bits.
        pub flags: u32,
        /// Thread-group id of the task that ran on the CPU just before this thread was
        /// switched in (0 for an idle CPU).
        pub run_holder_tgid: u32,
        /// `comm` of that task (`swapper/N` for an idle CPU).
        pub run_holder_comm: [u8; 16],
        /// `comm` of the waker when it is a process-context task outside the traced tree;
        /// empty otherwise.
        pub waker_comm: [u8; 16],
        /// With `EPF_READY`: the file whose readiness ended a poll/select/epoll wait (`nr` is
        /// `NR_NONE`; `fd` is its epoll item's descriptor, or -1 for poll/select).
        pub ready: SysInfo,
        /// With `EPF_FAULT`: the file mapped at the page fault the thread blocked in (`nr` is
        /// `NR_NONE`, `fd` -1); `mode` 0 means anonymous memory.
        pub fault: SysInfo,
        /// User stack at the switch-out (see [`TaskState::user_stack`]).
        pub user_stack: i32,
        /// Kernel stack at the switch-out (see [`TaskState::user_stack`]).
        pub kernel_stack: i32,
        /// Stack generation of `user_stack` and `kernel_stack` (see [`TaskState::stack_gen`]).
        pub stack_gen: u32,
        /// Zero.
        pub _pad2: u32,
        /// `comm` of the thread itself (its name, which may differ from the process's).
        pub comm: [u8; 16],
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
        /// Thread id of the waker of the current block (see [`EpisodeRecord::waker_tid`]).
        pub waker_tid: u32,
        /// Thread-group id of the waker of the current block.
        pub waker_tgid: u32,
        /// Zero.
        pub _pad: u32,
        /// Arguments of the syscall in flight and its block-time description.
        pub detail: SysDetail,
        /// With `has_ready`: the file whose readiness ended the current block.
        pub ready: SysInfo,
        /// The file of the page fault in progress, described when the thread blocks in it;
        /// `mode` 0 means anonymous memory.
        pub fault: SysInfo,
        /// `vma->vm_file` (kernel pointer) of the page fault in progress; 0 for anonymous
        /// memory.
        pub fault_file: u64,
        /// 1 while the thread is inside `handle_mm_fault`.
        pub in_fault: u32,
        /// 1 when `ready` describes the readiness that ended the current block.
        pub has_ready: u32,
        /// Thread-group id of the task that took the CPU at this thread's last preemption.
        pub pend_tgid: u32,
        /// Zero.
        pub _pad2: u32,
        /// `comm` of that task.
        pub pend_comm: [u8; 16],
        /// `comm` of the waker of the current block when it is outside the traced tree.
        pub waker_comm: [u8; 16],
        /// User stack captured at the last voluntary switch-out when stack capture is on:
        /// 0 = none captured, > 0 = stack id + 1 in generation `stack_gen`'s stack map,
        /// `STACK_INLINE` = copied whole into a [`StackRecord`] (the map could not take it),
        /// other < 0 = the negative errno of the capture (`-EFAULT`: empty stack; `-EEXIST`
        /// or `-ENOMEM`: lost, the ring buffer had no room for the copy either).
        pub user_stack: i32,
        /// Kernel stack captured at the same switch-out, encoded like `user_stack`.
        pub kernel_stack: i32,
        /// Stack generation the two stacks were captured in: it selects the stack map
        /// (`stacks0` when even, `stacks1` when odd) their ids belong to.
        pub stack_gen: u32,
        /// Zero.
        pub _pad3: u32,
    }

    /// An on-CPU sample of a tracked thread (`perf_event` CPU-clock sampler, only when stack
    /// capture is on).
    pub struct SampleRecord {
        /// The sampled thread; `ts` is the sample time.
        pub hdr: EvHeader,
        /// User stack, encoded like [`TaskState::user_stack`].
        pub user_stack: i32,
        /// Kernel stack (`-EFAULT`, empty, when the sample hit user mode).
        pub kernel_stack: i32,
        /// Stack generation of the two stacks (see [`TaskState::stack_gen`]).
        pub stack_gen: u32,
        /// Zero.
        pub _pad: u32,
        /// `comm` of the thread.
        pub comm: [u8; 16],
    }

    /// A stack the stack map could not take (bucket collision or full map), copied whole
    /// (stack capture only). Emitted before the record that refers to it with
    /// `STACK_INLINE`, which it is matched with by thread and capture time.
    pub struct StackRecord {
        /// The thread; `ts` is the capture time: the referring record's block time
        /// ([`EpisodeRecord::block_ts`], [`TaskState::block_ts`]) or sample time.
        pub hdr: EvHeader,
        /// 1 for a kernel stack, 0 for a user stack.
        pub kernel: u32,
        /// Addresses in `ips`.
        pub nr: u32,
        /// `nr` addresses, innermost first (`STACK_DEPTH` slots).
        pub ips: [u64; 127],
    }

    /// Bytes a tracked thread received from (or, for varlink, sent to) a resolver socket:
    /// a socket connected to port 53, sent a datagram to port 53, or connected to
    /// systemd-resolved's varlink socket. Emitted at the syscall's exit.
    pub struct DnsRecord {
        /// `ts` is the syscall exit.
        pub hdr: EvHeader,
        /// Inode of the socket: identifies the resolver connection.
        pub ino: u64,
        /// Descriptor the syscall used.
        pub fd: i32,
        /// One of the `DNS_UDP`, `DNS_TCP`, `DNS_VARLINK` constants.
        pub transport: u16,
        /// 1 for bytes sent (varlink requests), 0 for bytes received.
        pub sent: u16,
        /// Bytes the syscall transferred (for `recvmmsg`/`sendmmsg`: of the first message).
        pub total: u32,
        /// Leading bytes captured in `data` (at most `DNS_BYTES`; from the first buffer of a
        /// vector).
        pub len: u32,
        /// The payload's leading bytes.
        pub data: [u8; DNS_BYTES as usize],
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
    /// [`DnsRecord`].
    pub const EV_DNS: u32 = 5;
    /// [`SampleRecord`].
    pub const EV_SAMPLE: u32 = 6;
    /// [`StackRecord`].
    pub const EV_STACK: u32 = 7;

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

    /// [`EpisodeRecord::flags`]: the thread blocked inside a page fault (`fault` is valid).
    pub const EPF_FAULT: u32 = 1;
    /// [`EpisodeRecord::flags`]: `ready` names the file whose readiness ended the block.
    pub const EPF_READY: u32 = 2;

    /// `sys_flags` bit: argument 0 is a file descriptor to describe.
    pub const SYSF_FD0: u32 = 1;
    /// `sys_flags` bit: arguments 1 and 2 are a user `sockaddr` and its length.
    pub const SYSF_SOCKADDR: u32 = 2;
    /// `sys_flags`: the resolver capture operation (`DNSOP_*`) of the syscall sits in the
    /// bits from here up (`sys_flags >> SYSF_DNS_SHIFT`).
    pub const SYSF_DNS_SHIFT: u32 = 8;
    /// `DNSOP_*`: `connect(fd, sockaddr, len)`; a resolver target marks the socket.
    pub const DNSOP_CONNECT: u32 = 1;
    /// `DNSOP_*`: `close(fd)` forgets the socket.
    pub const DNSOP_CLOSE: u32 = 2;
    /// `DNSOP_*`: received into the buffer at argument 1 (`read`, `recvfrom`).
    pub const DNSOP_READ: u32 = 3;
    /// `DNSOP_*`: received into the `iovec` array at argument 1 (`readv`).
    pub const DNSOP_READV: u32 = 4;
    /// `DNSOP_*`: received into the `msghdr` at argument 1 (`recvmsg`).
    pub const DNSOP_RECVMSG: u32 = 5;
    /// `DNSOP_*`: received into the `mmsghdr` array at argument 1 (`recvmmsg`).
    pub const DNSOP_RECVMMSG: u32 = 6;
    /// `DNSOP_*`: sent from the buffer at argument 1 (`write`).
    pub const DNSOP_WRITE: u32 = 7;
    /// `DNSOP_*`: sent from the buffer at argument 1 to the `sockaddr` in arguments 4 and 5
    /// (`sendto`); a resolver target marks the socket.
    pub const DNSOP_SENDTO: u32 = 8;
    /// `DNSOP_*`: sent from the `iovec` array at argument 1 (`writev`).
    pub const DNSOP_WRITEV: u32 = 9;
    /// `DNSOP_*`: sent from the `msghdr` at argument 1 (`sendmsg`); a resolver `msg_name`
    /// marks the socket.
    pub const DNSOP_SENDMSG: u32 = 10;
    /// `DNSOP_*`: sent from the `mmsghdr` array at argument 1 (`sendmmsg`), first message.
    pub const DNSOP_SENDMMSG: u32 = 11;

    /// [`DnsRecord::transport`]: DNS messages over UDP.
    pub const DNS_UDP: u32 = 1;
    /// [`DnsRecord::transport`]: DNS messages over TCP, each after a 2-byte length.
    pub const DNS_TCP: u32 = 2;
    /// [`DnsRecord::transport`]: systemd-resolved varlink (NUL-terminated JSON messages).
    pub const DNS_VARLINK: u32 = 3;
    /// Size of [`DnsRecord::data`].
    pub const DNS_BYTES: u32 = 1024;
    /// Resolver sockets remembered per process.
    pub const DNS_SOCKS: u32 = 8;
    /// Capacity of the `dns_procs` map (processes with resolver sockets open at once).
    pub const DNS_PROCS_MAX: u32 = 1024;
    /// Entries of the `sys_flags` array (syscall numbers above are ignored).
    pub const SYS_TABLE_LEN: u32 = 512;

    /// [`SysDetail::flags`]: the syscall's descriptor was described at its first block, so
    /// [`SysInfo`] (beyond `nr`), `magic` and `path` refer to this syscall.
    pub const SYSD_DESCRIBED: u32 = 1;
    /// [`SysDetail::flags`]: the path walk reached the root of the mount namespace, so
    /// `path` is the whole absolute path.
    pub const SYSD_PATH_ROOTED: u32 = 2;
    /// [`SysDetail::flags`]: the walk stopped early (buffer full, depth limit, unreadable
    /// name); `path` holds only the trailing components. Without either path flag the walk
    /// ended at a pseudo-filesystem root (anonymous inode, pipe, memfd) and `path` is the name.
    pub const SYSD_PATH_TRUNCATED: u32 = 4;
    /// Size of [`SysDetail::path`].
    pub const PATH_BYTES: u32 = 256;
    /// `s_magic` of anonymous inodes (eventfd, timerfd, signalfd, inotify, ...).
    pub const ANON_INODE_FS_MAGIC: u32 = 0x0904_1934;

    /// `stats` slot: ring buffer reservations that failed (records lost).
    pub const STAT_RING_FULL: u32 = 0;
    /// `stats` slot: threads that could not be added to the `tasks` map.
    pub const STAT_TASKS_FULL: u32 = 1;
    /// `stats` slot: processes that could not be added to the `tracked` map.
    pub const STAT_TRACKED_FULL: u32 = 2;
    /// `stats` slot: resolver sockets that could not be remembered (`dns_procs` or the
    /// process's slots full) and resolver payloads that could not be copied.
    pub const STAT_DNS_LOST: u32 = 3;
    /// `stats` slot: stacks the stack map could not take (bucket collision, full map),
    /// copied whole into a [`StackRecord`] instead.
    pub const STAT_STACK_INLINE: u32 = 4;
    /// `stats` slot: stacks lost: the stack map could not take them and the ring buffer had
    /// no room for a copy (the reference keeps the map's `-EEXIST`/`-ENOMEM`).
    pub const STAT_STACK_LOST: u32 = 5;
    /// Number of `stats` slots.
    pub const STAT_NR: u32 = 6;

    /// Capacity of the `tasks` map (tracked threads alive at once).
    pub const TASKS_MAX: u32 = 32768;
    /// Capacity of the `tracked` map (tracked processes alive at once).
    pub const TRACKED_MAX: u32 = 16384;
    /// Size of the `events` ring buffer in bytes.
    pub const RINGBUF_BYTES: u32 = 4 << 20;
    /// Frames kept per stack (stack map value and [`StackRecord::ips`]: this many `u64`
    /// addresses). Equal to the default `kernel.perf_event_max_stack`, which bounds it: with
    /// a lower sysctl the stack maps cannot be created, so stack capture is unavailable (runs
    /// without `--flamegraph`/`--folded` load an object without them).
    pub const STACK_DEPTH: u32 = 127;
    /// Capacity of each of the two stack maps (distinct stacks per generation; each entry
    /// holds `STACK_DEPTH` addresses, ~8 MiB per map).
    pub const STACKS_MAX: u32 = 8192;
    /// Stack reference ([`TaskState::user_stack`]): the stack was copied whole into a
    /// [`StackRecord`]. Below every errno.
    pub const STACK_INLINE: i32 = -4096;
    /// Sampling frequency (Hz) of the on-CPU stack sampler, per CPU.
    pub const SAMPLE_HZ: u32 = 199;
}

/// The C header for the BPF program: every record, then [`CONSTS`].
#[cfg(feature = "std")]
pub fn header() -> wire::HeaderBuilder {
    let mut header = wire::HeaderBuilder::new("WHYTIME_WIRE_H");
    header
        .structs::<EvHeader>()
        .structs::<CpuSegment>()
        .structs::<SysInfo>()
        .structs::<SysDetail>()
        .structs::<ForkRecord>()
        .structs::<ExecRecord>()
        .structs::<EpisodeRecord>()
        .structs::<ExitRecord>()
        .structs::<DnsRecord>()
        .structs::<TaskState>()
        .structs::<SampleRecord>()
        .structs::<StackRecord>()
        .consts(&CONSTS);
    header
}

#[cfg(feature = "user")]
wire::impl_aya_pod!(TaskState);

// `StackRecord::ips` holds a whole stack map value.
const _: () = assert!(STACK_DEPTH == 127);
