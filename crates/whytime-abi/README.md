# whytime-abi

Internal crate of [whytime](https://github.com/Arinerron/whytime): the kernel/user ABI shared
by its BPF program and its loader (ring buffer records, the per-task map value and shared
constants), plus the C header the BPF build renders from them (feature `std`).

It is published only so that `whytime` can be installed from crates.io. Its version moves in
lockstep with `whytime` and `whytime-bpf`, which depend on it with an exact (`=`) requirement;
there is no API stability between releases. Use the
[`whytime`](https://crates.io/crates/whytime) crate instead.

License: MIT (see `LICENSE`).
