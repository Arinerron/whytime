//! whytime's BPF object, compiled from `bpf/whytime.bpf.c` by the build script.
//!
//! The object is relocatable C CO-RE: aya rewrites field offsets against the running kernel's
//! BTF at load time.

/// The BPF ELF object, 8-byte aligned as aya requires.
pub static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/whytime.bpf.o"));

/// ABI hash of the wire header the object was compiled against (`WHYTIME_WIRE_H_ABI_HASH`).
pub const ABI_HASH: u64 = include!(concat!(env!("OUT_DIR"), "/abi_hash.rs"));
