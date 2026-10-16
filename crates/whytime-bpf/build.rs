//! Renders the wire header from `whytime-abi`, then compiles `bpf/whytime.bpf.c` twice with
//! clang: `$OUT_DIR/whytime.bpf.o` (plain runs) and, with `-DWHYTIME_STACKS`,
//! `$OUT_DIR/whytime_stacks.bpf.o` (stack capture for flamegraphs). Needs only clang with BPF
//! CO-RE support: no nightly Rust, no bpf-linker. Under docs.rs (`DOCS_RS`), writes empty
//! placeholder objects instead.

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
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=DOCS_RS");

    let variants: [(&str, &[&str]); 2] = [
        ("whytime.bpf.o", &[]),
        ("whytime_stacks.bpf.o", &["-DWHYTIME_STACKS"]),
    ];
    // docs.rs: the objects are embedded, not documented; skip clang and the arch check.
    if env::var_os("DOCS_RS").is_some() {
        for (name, _) in variants {
            fs::write(out_dir.join(name), []).expect("write placeholder object");
        }
        return;
    }

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
    for (name, defines) in variants {
        let object = out_dir.join(name);
        let status = Command::new(&clang)
            .args([
                "-target", "bpfel", "-O2", "-g", "-mcpu=v3", "-Wall", "-Werror",
            ])
            .arg(format!("-D__TARGET_ARCH_{arch}"))
            .args(defines)
            .args(["-I", "bpf", "-I", "bpf/include", "-I"])
            .arg(&out_dir)
            .args(["-c", "bpf/whytime.bpf.c", "-o"])
            .arg(&object)
            .status()
            .unwrap_or_else(|e| panic!("failed to run {}: {e}", clang.display()));
        assert!(status.success(), "clang failed on {name}: {status}");
    }
}
