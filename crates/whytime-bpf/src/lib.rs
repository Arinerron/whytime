//! whytime's BPF objects, compiled from `bpf/whytime.bpf.c` by the build script.
//!
//! The objects are relocatable C CO-RE: aya rewrites field offsets against the running
//! kernel's BTF at load time.

/// The BPF ELF object of plain runs, 8-byte aligned as aya requires: no stack maps, no
/// sampler, so nothing about stack capture can keep it from loading.
pub static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/whytime.bpf.o"));

/// The same programs built with stack capture (`WHYTIME_STACKS`): stack maps, block-time
/// stacks in `on_switch`, and the `on_sample` sampler. Loaded for `--flamegraph`/`--folded`.
pub static STACKS_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/whytime_stacks.bpf.o"));

/// ABI hash of the wire header the object was compiled against (`WHYTIME_WIRE_H_ABI_HASH`).
pub const ABI_HASH: u64 = include!(concat!(env!("OUT_DIR"), "/abi_hash.rs"));
