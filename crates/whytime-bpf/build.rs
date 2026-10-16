//! Renders the wire header from `whytime-abi`, then compiles `bpf/whytime.bpf.c` into
//! `$OUT_DIR/whytime.bpf.o` with clang. Needs only clang with BPF CO-RE support: no nightly
//! Rust, no bpf-linker.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let header = whytime_abi::header();
    fs::write(out_dir.join("whytime_wire.h"), header.finish()).expect("write whytime_wire.h");
    let hash = header.abi_hash();
    fs::write(
        out_dir.join("abi_hash.rs"),
        format!(
            "0x{:04X}_{:04X}_{:04X}_{:04X}",
            (hash >> 48) & 0xFFFF,
            (hash >> 32) & 0xFFFF,
            (hash >> 16) & 0xFFFF,
            hash & 0xFFFF
        ),
    )
    .expect("write abi_hash.rs");

    // libbpf's bpf_tracing.h keys pt_regs access off __TARGET_ARCH_<arch>; vmlinux_min.h
    // declares the pt_regs layout for these two only (both little-endian: bpfel).
    let arch = match env::var("CARGO_CFG_TARGET_ARCH")
        .expect("target arch")
        .as_str()
    {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => panic!("unsupported target arch {other}: whytime builds for x86_64 and aarch64"),
    };
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let object = out_dir.join("whytime.bpf.o");
    let status = Command::new(&clang)
        .args([
            "-target", "bpfel", "-O2", "-g", "-mcpu=v3", "-Wall", "-Werror",
        ])
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .args(["-I", "bpf", "-I", "bpf/include", "-I"])
        .arg(&out_dir)
        .args(["-c", "bpf/whytime.bpf.c", "-o"])
        .arg(&object)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", clang.display()));
    assert!(status.success(), "clang failed: {status}");
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-env-changed=CLANG");
}
