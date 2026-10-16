# whytime-bpf

Internal crate of [whytime](https://github.com/Arinerron/whytime): its BPF objects, C CO-RE
compiled from `bpf/whytime.bpf.c` by `build.rs`, and the hash of the ABI they were compiled
against. Building it needs clang with the BPF target (`clang -print-targets | grep bpf`;
override the binary with `CLANG=`). x86_64 and aarch64 only.

It is published only so that `whytime` can be installed from crates.io. Its version moves in
lockstep with `whytime` and `whytime-abi`, which it is pinned to with an exact (`=`)
requirement; there is no API stability between releases. Use the
[`whytime`](https://crates.io/crates/whytime) crate instead.

License: MIT (see `LICENSE`), except the vendored libbpf headers in `bpf/include/bpf`, which
are `LGPL-2.1 OR BSD-2-Clause` (their license texts are beside them).
