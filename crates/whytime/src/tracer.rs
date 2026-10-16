//! Loading and attaching the BPF object, and access to its maps.

use std::io;
use std::os::fd::{AsRawFd as _, RawFd};

use anyhow::Context as _;
use aya::maps::{
    Array, ArrayOfMaps, HashMap, MapData, MapError, PerCpuArray, RingBuf, StackTraceMap,
};
use aya::programs::perf_event::{PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent};
use aya::programs::{Program, ProgramError};
use aya::sys::SyscallError;
use aya::{Btf, Ebpf, EbpfLoader, Pod};
use whytime_abi::{
    SAMPLE_HZ, STACK_DEPTH, STACKS_MAX, STAT_DNS_LOST, STAT_RING_FULL, STAT_STACK_INLINE,
    STAT_STACK_LOST, STAT_TASKS_FULL, STAT_TRACKED_FULL, TaskState,
};

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

/// The on-CPU stack sampler (`perf_event`), attached to a CPU-clock event on every online
/// CPU when stack capture is on.
pub const SAMPLER: &str = "on_sample";

/// Test-only override of each stack map's capacity (`WHYTIME_STACK_MAP_ENTRIES`, at most
/// [`STACKS_MAX`]): a tiny map makes most stacks take the STACK record path.
const MAP_ENTRIES_ENV: &str = "WHYTIME_STACK_MAP_ENTRIES";

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
    /// The stack maps, when stack capture is on.
    stacks: Option<StackMaps>,
}

/// The stack capture maps: two stack maps used alternately by generation, the generation
/// the programs store into, and the barrier (see `whytime.bpf.c`).
pub struct StackMaps {
    /// `stacks0` and `stacks1`: generation `g` stores into `maps[g % 2]`.
    maps: [StackTraceMap<MapData>; 2],
    /// `stack_gen`: entry 0 is the current generation.
    generation: Array<MapData, u32>,
    /// `stack_barrier`: an update returns after an RCU grace period.
    barrier: ArrayOfMaps<MapData, Array<MapData, u32>>,
    /// Entries per stack map.
    pub capacity: u32,
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

impl std::fmt::Debug for StackMaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StackMaps")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
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
    /// Stack capture, when requested: why it is unavailable, if it is.
    pub stacks: Option<Result<(), anyhow::Error>>,
}

impl Tracer {
    /// Loads the object, fills the syscall table and attaches every program; with `stacks`,
    /// the object built with stack capture (stack maps, stacks at blocks, the on-CPU
    /// sampler). Fails only if the object or a scheduler program cannot be loaded or
    /// attached; the optional sets report their own outcome. If anything about stack capture
    /// fails, the plain object is loaded instead and `stacks` says why.
    pub fn load(syscalls: &SyscallTable, stacks: bool) -> anyhow::Result<Loaded> {
        raise_memlock();
        let btf = Btf::from_sys_fs().context("reading kernel BTF (/sys/kernel/btf/vmlinux)")?;
        log::debug!("wire abi {:#018x}", whytime_bpf::ABI_HASH);
        // 0 (unknown) leaves the waker of interrupt-context wakeups as the interrupted task.
        let preempt_count_from_rq = std::fs::read("/sys/kernel/btf/vmlinux")
            .ok()
            .and_then(|raw| crate::percpu::preempt_count_from_rq(&raw))
            .unwrap_or(0);
        log::debug!("preempt_count is {preempt_count_from_rq:+} bytes from runqueues");
        if !stacks {
            return Self::load_with(&btf, syscalls, preempt_count_from_rq, false);
        }
        match Self::load_with(&btf, syscalls, preempt_count_from_rq, true) {
            Ok(loaded) => Ok(loaded),
            Err(err) => {
                log::debug!("loading with stack capture failed ({err:#}); loading without");
                let mut loaded = Self::load_with(&btf, syscalls, preempt_count_from_rq, false)?;
                loaded.stacks = Some(Err(err));
                Ok(loaded)
            }
        }
    }

    /// Loads the plain object, or with `stacks` the stack capture one, in which case every
    /// part of stack capture must work too.
    fn load_with(
        btf: &Btf,
        syscalls: &SyscallTable,
        preempt_count_from_rq: i64,
        stacks: bool,
    ) -> anyhow::Result<Loaded> {
        let entries = if stacks {
            check_max_stack()?;
            stack_map_entries()
        } else {
            0
        };
        let object = if stacks {
            whytime_bpf::STACKS_OBJECT
        } else {
            whytime_bpf::OBJECT
        };
        log::debug!("loading BPF object: {} bytes, stack capture {stacks}", object.len());
        let mut loader = EbpfLoader::new();
        loader
            .btf(Some(btf))
            .override_global("preempt_count_from_rq", &preempt_count_from_rq, true);
        if stacks {
            loader
                .map_max_entries("stacks0", entries)
                .map_max_entries("stacks1", entries);
        }
        let mut ebpf = loader.load(object).context("creating BPF maps")?;

        let mut flags: Array<_, u32> = Array::try_from(map(&mut ebpf, "sys_flags")?)?;
        for (nr, bits) in syscalls.bpf_flags() {
            flags.set(nr, bits, 0).context("filling sys_flags")?;
        }

        attach_all(&mut ebpf, btf, &SCHED)?;
        let stack_maps = if stacks {
            attach_sampler(&mut ebpf)?;
            Some(StackMaps {
                maps: [
                    StackTraceMap::try_from(take(&mut ebpf, "stacks0")?)?,
                    StackTraceMap::try_from(take(&mut ebpf, "stacks1")?)?,
                ],
                generation: Array::try_from(take(&mut ebpf, "stack_gen")?)?,
                barrier: ArrayOfMaps::try_from(take(&mut ebpf, "stack_barrier")?)?,
                capacity: entries,
            })
        } else {
            None
        };
        // One sys_exit program: the capturing one if the kernel takes it.
        let dns = attach_all(&mut ebpf, btf, &[DNS]);
        let syscalls = match &dns {
            Ok(()) => attach_all(&mut ebpf, btf, &[SYSCALLS[2]]),
            Err(_) => attach_all(&mut ebpf, btf, &[SYSCALLS[0], SYSCALLS[2]]),
        };
        let dns = match (&syscalls, dns) {
            (Err(_), Ok(())) => Err(anyhow::anyhow!("sys_enter is not attached")),
            (_, dns) => dns,
        };
        let readiness = attach_all(&mut ebpf, btf, &READINESS);
        let faults = attach_all(&mut ebpf, btf, &FAULTS);

        let maps = Maps {
            ring: RingBuf::try_from(take(&mut ebpf, "events")?)?,
            tasks: HashMap::try_from(take(&mut ebpf, "tasks")?)?,
            tracked: HashMap::try_from(take(&mut ebpf, "tracked")?)?,
            stats: PerCpuArray::try_from(take(&mut ebpf, "stats")?)?,
            stacks: stack_maps,
        };
        Ok(Loaded {
            tracer: Self { ebpf, maps },
            syscalls,
            dns,
            readiness,
            faults,
            stacks: stacks.then_some(Ok(())),
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

    /// The in-kernel state of every thread still tracked.
    pub fn tasks(&self) -> Vec<(u32, TaskState)> {
        self.maps.tasks()
    }

    /// The stack maps, when stack capture is on (once): stacks are read from them while the
    /// run goes and after the programs are detached.
    pub fn take_stacks(&mut self) -> Option<StackMaps> {
        self.maps.stacks.take()
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

    /// Stacks lost in kernel (all CPUs): the stack map could not take them and the ring
    /// buffer had no room for a copy; the records that referred to them carry the error.
    pub fn lost_stacks(&self) -> u64 {
        self.stat(&[STAT_STACK_LOST])
    }

    /// Stacks the stack maps could not take, copied into STACK records instead (all CPUs).
    pub fn inline_stacks(&self) -> u64 {
        self.stat(&[STAT_STACK_INLINE])
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

impl StackMaps {
    /// Makes newly started programs store stacks into `generation` (its map must
    /// be empty); [`barrier`](Self::barrier) waits for the ones still on the previous.
    pub fn set_generation(&mut self, generation: u32) -> Result<(), MapError> {
        self.generation.set(0, generation, 0)
    }

    /// Returns once every program running when it was called has finished (an RCU grace
    /// period: a map-in-map update waits for one).
    pub fn barrier(&mut self) -> Result<(), MapError> {
        self.barrier.set(0, &self.generation, 0)
    }

    /// The addresses of stack `id` in `generation`'s map, innermost first; `None`
    /// when it cannot be read.
    pub fn read(&self, generation: u32, id: u32) -> Option<Vec<u64>> {
        match self.maps[slot(generation)].get(&id, 0) {
            Ok(stack) => Some(stack.frames().iter().map(|frame| frame.ip).collect()),
            Err(err) => {
                log::debug!("reading stack {generation}:{id}: {err}");
                None
            }
        }
    }

    /// Empties `generation`'s map; returns how many stacks it removed.
    pub fn clear(&mut self, generation: u32) -> usize {
        let map = &mut self.maps[slot(generation)];
        let ids: Vec<u32> = map.stack_ids().filter_map(Result::ok).collect();
        ids.iter()
            .filter(|id| match map.remove(id) {
                Ok(()) => true,
                Err(err) => {
                    log::debug!("removing stack {generation}:{id}: {err}");
                    false
                }
            })
            .count()
    }
}

/// Index of `generation`'s map among the two stack maps.
pub fn slot(generation: u32) -> usize {
    usize::from(generation % 2 == 1)
}

/// Fails with `EINVAL` (the stack maps' creation error) when `kernel.perf_event_max_stack`
/// is below [`STACK_DEPTH`]: the kernel refuses stack maps holding more frames than it.
fn check_max_stack() -> anyhow::Result<()> {
    const SYSCTL: &str = "/proc/sys/kernel/perf_event_max_stack";
    let Some(max) = std::fs::read_to_string(SYSCTL)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
    else {
        return Ok(());
    };
    if max < STACK_DEPTH {
        return Err(anyhow::Error::new(io::Error::from_raw_os_error(libc::EINVAL)).context(
            format!(
                "kernel.perf_event_max_stack is {max}, below the {STACK_DEPTH} frames per stack \
                 of whytime's stack maps"
            ),
        ));
    }
    Ok(())
}

/// Entries per stack map: [`STACKS_MAX`], or less with [`MAP_ENTRIES_ENV`].
fn stack_map_entries() -> u32 {
    std::env::var(MAP_ENTRIES_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .map_or(STACKS_MAX, |entries| entries.clamp(1, STACKS_MAX))
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

/// Loads the on-CPU sampler and attaches it to a CPU-clock event of [`SAMPLE_HZ`] on every
/// online CPU.
fn attach_sampler(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let Program::PerfEvent(program) = ebpf
        .program_mut(SAMPLER)
        .with_context(|| format!("BPF object has no program {SAMPLER}"))?
    else {
        anyhow::bail!("BPF program {SAMPLER} has an unsupported type");
    };
    if let Err(err) = program.load() {
        if let ProgramError::LoadError { verifier_log, .. } = &err {
            log::debug!("verifier log for {SAMPLER}:\n{verifier_log}");
        }
        return Err(err).context("loading perf_event/cpu-clock");
    }
    let cpus = aya::util::online_cpus()
        .map_err(|(path, err)| anyhow::Error::new(err).context(format!("reading {path}")))?;
    for cpu in cpus {
        program
            .attach(
                PerfEventConfig::Software(SoftwareEvent::CpuClock),
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(u64::from(SAMPLE_HZ)),
                false,
            )
            .with_context(|| format!("attaching perf_event/cpu-clock on CPU {cpu}"))?;
    }
    Ok(())
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
