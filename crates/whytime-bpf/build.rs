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

    // libbpf's bpf_tracing.h keys pt_regs access off __TARGET_ARCH_<arch>.
    let arch = match env::var("CARGO_CFG_TARGET_ARCH")
        .expect("target arch")
        .as_str()
    {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        "s390x" => "s390",
        "loongarch64" => "loongarch",
        "powerpc64" => "powerpc",
        other => panic!("no __TARGET_ARCH mapping for {other}"),
    };
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN")
        .expect("target endian")
        .as_str()
    {
        "big" => "bpfeb",
        _ => "bpfel",
    };
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let object = out_dir.join("whytime.bpf.o");
    let status = Command::new(&clang)
        .args([
            "-target", target, "-O2", "-g", "-mcpu=v3", "-Wall", "-Werror",
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
