//! Synthetic ring buffer records and traces for unit tests.
//!
//! Every record starts from all-zero bytes and sets only what a test names, so fields appended
//! to the ABI later keep a neutral zero without touching the tests. Times are plain
//! nanosecond numbers; a test reads like the kernel's sequence of events.

use std::num::NonZeroU64;
use std::path::PathBuf;

use whytime_abi::{
    CpuSegment, EV_EPISODE, EV_EXEC, EV_EXIT, EV_FORK, EV_SAMPLE, EpisodeRecord, EvHeader,
    ExecRecord, ExitRecord, ForkRecord, NR_NONE, SYSD_DESCRIBED, SampleRecord, SysInfo,
    TaskState,
};
use wire::Pod;

use crate::classify::{Classifier, FdTarget};
use crate::sys::SyscallTable;
use crate::timeline::{self, Trace};

/// An all-zero `T`.
pub fn zeroed<T: Pod>() -> T {
    wire::read(&vec![0; size_of::<T>()]).expect("a buffer of exactly size_of::<T>() bytes")
}

/// [`FdTarget`] that resolves nothing: file subjects fall back to `dev M:m ino N`.
#[derive(Debug)]
pub struct NoFiles;

impl FdTarget for NoFiles {
    fn fd_target(&self, _tgid: u32, _fd: i32, _dev: u32, _ino: u64) -> Option<PathBuf> {
        None
    }

    fn mapped_file(&self, _tgid: u32, _dev: u32, _ino: u64) -> Option<PathBuf> {
        None
    }
}

/// An empty trace of the wrapped command `root_pid`, home `/home/u`, no `/proc` access.
pub fn trace(root_pid: u32) -> Trace {
    let classifier = Classifier::new(
        SyscallTable::new(),
        Some(PathBuf::from("/home/u")),
        Box::new(NoFiles),
    );
    Trace::new(
        root_pid,
        classifier,
        timeline::proc_table(NonZeroU64::new(100).expect("non-zero")),
    )
}

/// Feeds `record` to `trace` as the ring buffer would.
pub fn feed<T: Pod>(trace: &mut Trace, record: &T) {
    trace.ingest(wire::as_bytes(record));
}

/// An accounting segment from `start`: `run` ns on-CPU and `rq` ns preempted.
pub fn seg(start: u64, run: u64, rq: u64) -> CpuSegment {
    let mut seg: CpuSegment = zeroed();
    seg.start = start;
    seg.run_ns = run;
    seg.rq_ns = rq;
    seg
}

/// Syscall `nr` without a descriptor (`fd` -1); `NR_NONE` outside syscalls.
pub fn sys(nr: libc::c_long) -> SysInfo {
    let mut sys: SysInfo = zeroed();
    sys.nr = i32::try_from(nr).unwrap_or(NR_NONE);
    sys.fd = -1;
    sys
}

fn hdr(kind: u32, ts: u64, tid: u32, tgid: u32) -> EvHeader {
    let mut hdr: EvHeader = zeroed();
    hdr.kind = kind;
    hdr.ts = ts;
    hdr.tid = tid;
    hdr.tgid = tgid;
    hdr
}

/// Thread `parent_tid` of `parent_tgid` creates `child_tid` in `child_tgid` (a thread when
/// the tgids match). Like [`exec`], it uses the tgid as the process's `start_boottime`.
pub fn fork(
    ts: u64,
    parent_tid: u32,
    parent_tgid: u32,
    child_tid: u32,
    child_tgid: u32,
) -> ForkRecord {
    let mut r: ForkRecord = zeroed();
    r.hdr = hdr(EV_FORK, ts, parent_tid, parent_tgid);
    r.child_tid = child_tid;
    r.child_tgid = child_tgid;
    r.child_start = u64::from(child_tgid);
    r
}

/// Thread `tid` of `tgid` execs `comm` (argv `[comm]`) at `ts`, after `seg`; the thread then
/// carries the tgid. The leader's `start_boottime` is the tgid, as in [`fork`].
pub fn exec(ts: u64, tid: u32, tgid: u32, comm: &str, seg: CpuSegment) -> ExecRecord {
    let mut r: ExecRecord = zeroed();
    r.hdr = hdr(EV_EXEC, ts, tgid, tgid);
    r.seg = seg;
    r.start = u64::from(tgid);
    r.old_tid = tid;
    r.comm[..comm.len()].copy_from_slice(comm.as_bytes());
    r.argv[..comm.len()].copy_from_slice(comm.as_bytes());
    r.argv_len = u32::try_from(comm.len() + 1).expect("short comm");
    r
}

/// Thread `tid` of `tgid` ran `seg` until `block_ts`, blocked in `sys`, was woken at `wake_ts`
/// (0 = unseen) and ran again at `run_ts`; `times` is `[block_ts, wake_ts, run_ts]`. Inside a
/// syscall the detail is marked described (`sys` is this syscall's) without a captured path,
/// so file subjects come from the trace's [`FdTarget`].
pub fn episode(tid: u32, tgid: u32, seg: CpuSegment, sys: SysInfo, times: [u64; 3]) -> EpisodeRecord {
    let [block_ts, wake_ts, run_ts] = times;
    let mut r: EpisodeRecord = zeroed();
    r.hdr = hdr(EV_EPISODE, run_ts, tid, tgid);
    r.seg = seg;
    r.block_ts = block_ts;
    r.wake_ts = wake_ts;
    r.sys = sys;
    r.block_state = 1;
    if sys.nr != NR_NONE {
        r.detail.flags = SYSD_DESCRIBED;
    }
    r
}

/// Thread `tid` of `tgid` exits at `ts` after `seg`, with wait status `code`; `group_dead`
/// when it is the last thread.
pub fn exit(
    ts: u64,
    tid: u32,
    tgid: u32,
    seg: CpuSegment,
    code: i32,
    group_dead: bool,
) -> ExitRecord {
    let mut r: ExitRecord = zeroed();
    r.hdr = hdr(EV_EXIT, ts, tid, tgid);
    r.seg = seg;
    r.start = u64::from(tgid);
    r.code = code;
    r.group_dead = u32::from(group_dead);
    r
}

/// An on-CPU sample of thread `tid` of `tgid` at `ts` with stack references `stacks`
/// (`[user, kernel]`, encoded as in `TaskState::user_stack`: id + 1).
pub fn sample(ts: u64, tid: u32, tgid: u32, stacks: [i32; 2]) -> SampleRecord {
    let mut r: SampleRecord = zeroed();
    r.hdr = hdr(EV_SAMPLE, ts, tid, tgid);
    [r.user_stack, r.kernel_stack] = stacks;
    r
}

/// The in-kernel state of a thread of `tgid` in state `state` (`ST_*`), outside syscalls,
/// with open segment `seg`.
pub fn task(tgid: u32, state: u32, seg: CpuSegment) -> TaskState {
    let mut t: TaskState = zeroed();
    t.tgid = tgid;
    t.state = state;
    t.seg = seg;
    t.sys = sys(libc::c_long::from(NR_NONE));
    t
}
