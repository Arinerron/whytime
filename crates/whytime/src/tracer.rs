//! Loading and attaching the BPF object, and access to its maps.

use std::io;
use std::os::fd::{AsRawFd as _, RawFd};

use anyhow::Context as _;
use aya::maps::{Array, HashMap, MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::{Program, ProgramError};
use aya::sys::SyscallError;
use aya::{Btf, Ebpf, EbpfLoader, Pod};
use whytime_abi::{STAT_DNS_LOST, STAT_RING_FULL, STAT_TASKS_FULL, STAT_TRACKED_FULL, TaskState};

use crate::sys::SyscallTable;

/// Scheduler and lifecycle programs, `(program, tracepoint)`; whytime cannot run without them.
pub const SCHED: [(&str, &str); 5] = [
    ("on_switch", "sched_switch"),
    ("on_waking", "sched_waking"),
    ("on_fork", "sched_process_fork"),
    ("on_exec", "sched_process_exec"),
    ("on_exit", "sched_process_exit"),
];

/// Syscall programs, `sys_exit` (one of these two) and then `sys_enter`; without them
/// blocks are not classified. `sys_exit` attaches first: on its own it only clears state,
/// while `sys_enter` alone would leave stale syscalls behind. The second exit program,
/// [`DNS`], is tried first; the plain one is the fallback.
pub const SYSCALLS: [(&str, &str); 3] = [
    ("on_sys_exit", "sys_exit"),
    ("on_sys_exit_dns", "sys_exit"),
    ("on_sys_enter", "sys_enter"),
];

/// The resolver capture: the `sys_exit` program that also copies what tracked threads
/// receive from resolver sockets into the ring. Without it network peers stay `ip:port`.
pub const DNS: (&str, &str) = SYSCALLS[1];

/// Readiness programs, `(program, kernel function)` (fentry): which file ended a
/// poll/select or epoll wait. Without them those waits stay class `poll`.
pub const READINESS: [(&str, &str); 2] = [
    ("on_pollwake", "pollwake"),
    ("on_ep_poll_callback", "ep_poll_callback"),
];

/// Page-fault programs (fexit, then fentry, so a half-attached pair only clears the mark).
/// Without them blocks in page faults are not class `fault`.
pub const FAULTS: [(&str, &str); 2] = [
    ("on_fault_exit", "handle_mm_fault"),
    ("on_fault_enter", "handle_mm_fault"),
];

/// `bpf_map_update_elem` flag: fail with `EEXIST` instead of replacing an entry.
const BPF_NOEXIST: u64 = 1;

/// The loaded, attached BPF object.
pub struct Tracer {
    ebpf: Ebpf,
    maps: Maps,
}

/// The maps whytime reads; they outlive the programs (see [`Tracer::detach`]).
pub struct Maps {
    ring: RingBuf<MapData>,
    tasks: HashMap<MapData, u32, TaskState>,
    tracked: HashMap<MapData, u32, u32>,
    stats: PerCpuArray<MapData, u64>,
}

impl std::fmt::Debug for Tracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracer").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Maps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Maps").finish_non_exhaustive()
    }
}

/// A successful load: the scheduler programs are attached; the optional sets may not be.
#[derive(Debug)]
pub struct Loaded {
    /// The tracer.
    pub tracer: Tracer,
    /// Why the syscall programs could not be attached, if they could not.
    pub syscalls: Result<(), anyhow::Error>,
    /// Why the resolver capture could not be attached, if it could not (always an error
    /// when the syscall programs are missing: it needs `sys_enter`).
    pub dns: Result<(), anyhow::Error>,
    /// Why the readiness programs could not be attached, if they could not.
    pub readiness: Result<(), anyhow::Error>,
    /// Why the page-fault programs could not be attached, if they could not.
    pub faults: Result<(), anyhow::Error>,
}

impl Tracer {
    /// Loads the object, fills the syscall table and attaches every program. Fails only if
    /// the object or a scheduler program cannot be loaded or attached; the optional sets
    /// report their own outcome.
    pub fn load(syscalls: &SyscallTable) -> anyhow::Result<Loaded> {
        raise_memlock();
        let btf = Btf::from_sys_fs().context("reading kernel BTF (/sys/kernel/btf/vmlinux)")?;
        log::debug!(
            "loading BPF object: {} bytes, wire abi {:#018x}",
            whytime_bpf::OBJECT.len(),
            whytime_bpf::ABI_HASH
        );
        // 0 (unknown) leaves the waker of interrupt-context wakeups as the interrupted task.
        let preempt_count_from_rq = std::fs::read("/sys/kernel/btf/vmlinux")
            .ok()
            .and_then(|raw| crate::percpu::preempt_count_from_rq(&raw))
            .unwrap_or(0);
        log::debug!("preempt_count is {preempt_count_from_rq:+} bytes from runqueues");
        let mut ebpf = EbpfLoader::new()
            .btf(Some(&btf))
            .override_global("preempt_count_from_rq", &preempt_count_from_rq, true)
            .load(whytime_bpf::OBJECT)
            .context("creating BPF maps")?;

        let mut flags: Array<_, u32> = Array::try_from(map(&mut ebpf, "sys_flags")?)?;
        for (nr, bits) in syscalls.bpf_flags() {
            flags.set(nr, bits, 0).context("filling sys_flags")?;
        }

        attach_all(&mut ebpf, &btf, &SCHED)?;
        // One sys_exit program: the capturing one if the kernel takes it.
        let dns = attach_all(&mut ebpf, &btf, &[DNS]);
        let syscalls = match &dns {
            Ok(()) => attach_all(&mut ebpf, &btf, &[SYSCALLS[2]]),
            Err(_) => attach_all(&mut ebpf, &btf, &[SYSCALLS[0], SYSCALLS[2]]),
        };
        let dns = match (&syscalls, dns) {
            (Err(_), Ok(())) => Err(anyhow::anyhow!("sys_enter is not attached")),
            (_, dns) => dns,
        };
        let readiness = attach_all(&mut ebpf, &btf, &READINESS);
        let faults = attach_all(&mut ebpf, &btf, &FAULTS);

        let maps = Maps {
            ring: RingBuf::try_from(take(&mut ebpf, "events")?)?,
            tasks: HashMap::try_from(take(&mut ebpf, "tasks")?)?,
            tracked: HashMap::try_from(take(&mut ebpf, "tracked")?)?,
            stats: PerCpuArray::try_from(take(&mut ebpf, "stats")?)?,
        };
        Ok(Loaded {
            tracer: Self { ebpf, maps },
            syscalls,
            dns,
            readiness,
            faults,
        })
    }

    /// Starts tracing process `tgid` and every process it forks from now on.
    pub fn track(&mut self, tgid: u32) -> anyhow::Result<()> {
        self.maps
            .tracked
            .insert(tgid, 1, 0)
            .with_context(|| format!("tracking pid {tgid}"))
    }

    /// Starts tracing process `tgid` (attach mode) unless the kernel side already tracks it;
    /// `Ok(false)` means it does: a tracked parent forked it, and its fork record is queued.
    pub fn track_existing(&mut self, tgid: u32) -> anyhow::Result<bool> {
        insert_new(&mut self.maps.tracked, tgid, &1)
            .with_context(|| format!("tracking pid {tgid}"))
    }

    /// Stops tracing `tgid`: it exited before attach created its threads' entries, so no
    /// exit record removes it.
    pub fn untrack(&mut self, tgid: u32) {
        // Absent when its exit did clean up.
        let _ = self.maps.tracked.remove(&tgid);
    }

    /// Creates the `tasks` entry of a thread that existed before attach unless the kernel
    /// side already created one (the thread was just forked, or exec'd); `Ok(false)` means
    /// it did.
    pub fn seed_task(&mut self, tid: u32, state: &TaskState) -> anyhow::Result<bool> {
        insert_new(&mut self.maps.tasks, tid, state)
            .with_context(|| format!("tracking thread {tid}"))
    }

    /// Removes the entry [`seed_task`](Self::seed_task) created for a thread that turned
    /// out to have exited before it.
    pub fn forget_task(&mut self, tid: u32) {
        // Absent when its exit did clean up.
        let _ = self.maps.tasks.remove(&tid);
    }

    /// The ring buffer's pollable descriptor.
    pub fn ring_fd(&self) -> RawFd {
        self.maps.ring.as_raw_fd()
    }

    /// Passes every available record to `f`.
    pub fn drain(&mut self, f: impl FnMut(&[u8])) {
        self.maps.drain(f);
    }

    /// Detaches and unloads every program, keeping the maps for a final drain and sweep.
    pub fn detach(self) -> Maps {
        let Self { ebpf, maps } = self;
        drop(ebpf);
        maps
    }

    /// Program names with their verified instruction counts, for the doctor.
    pub fn program_sizes(&self) -> Vec<(String, u32)> {
        let mut sizes: Vec<_> = self
            .ebpf
            .programs()
            .filter_map(|(name, prog)| {
                let info = prog.info().ok()?;
                Some((
                    name.to_owned(),
                    info.verified_instruction_count().unwrap_or(0),
                ))
            })
            .collect();
        sizes.sort();
        sizes
    }
}

impl Maps {
    /// Passes every available record to `f`.
    pub fn drain(&mut self, mut f: impl FnMut(&[u8])) {
        while let Some(item) = self.ring.next() {
            f(&item);
        }
    }

    /// The in-kernel state of every thread still tracked.
    pub fn tasks(&self) -> Vec<(u32, TaskState)> {
        self.tasks.iter().filter_map(Result::ok).collect()
    }

    /// Records and tasks lost in kernel (ring buffer, `tasks` or `tracked` full; all CPUs).
    pub fn dropped(&self) -> u64 {
        self.stat(&[STAT_RING_FULL, STAT_TASKS_FULL, STAT_TRACKED_FULL])
    }

    /// Resolver sockets the kernel could not remember and resolver payloads it could not
    /// copy (all CPUs).
    pub fn dns_lost(&self) -> u64 {
        self.stat(&[STAT_DNS_LOST])
    }

    /// Sum of `stats` slots over all CPUs.
    fn stat(&self, slots: &[u32]) -> u64 {
        slots
            .iter()
            .filter_map(|slot| self.stats.get(slot, 0).ok())
            .map(|per_cpu| per_cpu.iter().sum::<u64>())
            .sum()
    }
}

fn map<'a>(ebpf: &'a mut Ebpf, name: &str) -> anyhow::Result<&'a mut aya::maps::Map> {
    ebpf.map_mut(name)
        .with_context(|| format!("BPF object has no map {name}"))
}

fn take(ebpf: &mut Ebpf, name: &str) -> anyhow::Result<aya::maps::Map> {
    ebpf.take_map(name)
        .with_context(|| format!("BPF object has no map {name}"))
}

/// Loads and attaches `(program, target)` pairs in order, stopping at the first failure.
fn attach_all(ebpf: &mut Ebpf, btf: &Btf, programs: &[(&str, &str)]) -> anyhow::Result<()> {
    programs
        .iter()
        .try_for_each(|&(prog, target)| attach(ebpf, btf, prog, target))
}

/// Loads `prog` against `target` (a tracepoint for `tp_btf`, a kernel function for
/// `fentry`/`fexit`) and attaches it.
fn attach(ebpf: &mut Ebpf, btf: &Btf, prog: &str, target: &str) -> anyhow::Result<()> {
    macro_rules! load_attach {
        ($program:expr, $kind:literal) => {{
            if let Err(err) = $program.load(target, btf) {
                if let ProgramError::LoadError { verifier_log, .. } = &err {
                    log::debug!("verifier log for {prog}:\n{verifier_log}");
                }
                return Err(err).with_context(|| format!("loading {}/{target}", $kind));
            }
            $program
                .attach()
                .map(drop)
                .with_context(|| format!("attaching {}/{target}", $kind))
        }};
    }
    match ebpf
        .program_mut(prog)
        .with_context(|| format!("BPF object has no program {prog}"))?
    {
        Program::BtfTracePoint(program) => load_attach!(program, "tp_btf"),
        Program::FEntry(program) => load_attach!(program, "fentry"),
        Program::FExit(program) => load_attach!(program, "fexit"),
        _ => anyhow::bail!("BPF program {prog} has an unsupported type"),
    }
}

/// Inserts `key` unless present; `Ok(false)` when it was.
fn insert_new<V: Pod>(
    map: &mut HashMap<MapData, u32, V>,
    key: u32,
    value: &V,
) -> Result<bool, MapError> {
    match map.insert(key, value, BPF_NOEXIST) {
        Ok(()) => Ok(true),
        Err(MapError::SyscallError(SyscallError { io_error, .. }))
            if io_error.raw_os_error() == Some(libc::EEXIST) =>
        {
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

/// Raises the `RLIMIT_MEMLOCK` soft limit to the hard limit. Kernels before 5.11 charge BPF
/// maps against it; later ones use memcg accounting and ignore it.
fn raise_memlock() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for getrlimit/setrlimit to read and write.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) == 0
            && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max;
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) != 0 {
                log::debug!("raising RLIMIT_MEMLOCK: {}", io::Error::last_os_error());
            }
        }
    }
}

/// The errno behind a load or attach failure, if the chain carries one.
pub fn errno(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .find_map(io::Error::raw_os_error)
}
