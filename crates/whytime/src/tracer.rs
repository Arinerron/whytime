//! Loading and attaching the BPF object, and access to its maps.

use std::io;
use std::os::fd::{AsRawFd as _, RawFd};

use anyhow::Context as _;
use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, ProgramError};
use aya::{Btf, Ebpf, EbpfLoader};
use whytime_abi::{STAT_NR, TaskState};

use crate::sys::SyscallTable;

/// Scheduler and lifecycle programs, `(program, tracepoint)`; whytime cannot run without them.
pub const SCHED: [(&str, &str); 5] = [
    ("on_switch", "sched_switch"),
    ("on_waking", "sched_waking"),
    ("on_fork", "sched_process_fork"),
    ("on_exec", "sched_process_exec"),
    ("on_exit", "sched_process_exit"),
];

/// Syscall programs; without them blocks are not classified. `sys_exit` attaches first: on
/// its own it only clears state, while `sys_enter` alone would leave stale syscalls behind.
pub const SYSCALLS: [(&str, &str); 2] =
    [("on_sys_exit", "sys_exit"), ("on_sys_enter", "sys_enter")];

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

/// A successful load: the scheduler programs are attached; the syscall ones may not be.
#[derive(Debug)]
pub struct Loaded {
    /// The tracer.
    pub tracer: Tracer,
    /// Why the syscall programs could not be attached, if they could not.
    pub syscalls: Result<(), anyhow::Error>,
}

impl Tracer {
    /// Loads the object, fills the syscall table and attaches every program. Fails only if
    /// the object or a scheduler program cannot be loaded or attached.
    pub fn load(syscalls: &SyscallTable) -> anyhow::Result<Loaded> {
        raise_memlock();
        let btf = Btf::from_sys_fs().context("reading kernel BTF (/sys/kernel/btf/vmlinux)")?;
        log::debug!(
            "loading BPF object: {} bytes, wire abi {:#018x}",
            whytime_bpf::OBJECT.len(),
            whytime_bpf::ABI_HASH
        );
        let mut ebpf = EbpfLoader::new()
            .btf(Some(&btf))
            .load(whytime_bpf::OBJECT)
            .context("creating BPF maps")?;

        let mut flags: Array<_, u32> = Array::try_from(map(&mut ebpf, "sys_flags")?)?;
        for (nr, bits) in syscalls.bpf_flags() {
            flags.set(nr, bits, 0).context("filling sys_flags")?;
        }

        for (prog, tracepoint) in SCHED {
            attach(&mut ebpf, &btf, prog, tracepoint)?;
        }
        let syscalls = SYSCALLS
            .into_iter()
            .try_for_each(|(prog, tracepoint)| attach(&mut ebpf, &btf, prog, tracepoint));

        let maps = Maps {
            ring: RingBuf::try_from(take(&mut ebpf, "events")?)?,
            tasks: HashMap::try_from(take(&mut ebpf, "tasks")?)?,
            tracked: HashMap::try_from(take(&mut ebpf, "tracked")?)?,
            stats: PerCpuArray::try_from(take(&mut ebpf, "stats")?)?,
        };
        Ok(Loaded {
            tracer: Self { ebpf, maps },
            syscalls,
        })
    }

    /// Starts tracing process `tgid` and every process it forks from now on.
    pub fn track(&mut self, tgid: u32) -> anyhow::Result<()> {
        self.maps
            .tracked
            .insert(tgid, 1, 0)
            .with_context(|| format!("tracking pid {tgid}"))
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

    /// Records and tasks lost in kernel (all `stats` slots, all CPUs).
    pub fn dropped(&self) -> u64 {
        (0..STAT_NR)
            .filter_map(|slot| self.stats.get(&slot, 0).ok())
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

fn attach(ebpf: &mut Ebpf, btf: &Btf, prog: &str, tracepoint: &str) -> anyhow::Result<()> {
    let program: &mut BtfTracePoint = ebpf
        .program_mut(prog)
        .with_context(|| format!("BPF object has no program {prog}"))?
        .try_into()?;
    if let Err(err) = program.load(tracepoint, btf) {
        if let ProgramError::LoadError { verifier_log, .. } = &err {
            log::debug!("verifier log for {prog}:\n{verifier_log}");
        }
        return Err(err).with_context(|| format!("loading tp_btf/{tracepoint}"));
    }
    program
        .attach()
        .with_context(|| format!("attaching tp_btf/{tracepoint}"))?;
    Ok(())
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
