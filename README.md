# whytime

`time` tells you how long. `whytime` tells you **where it went**.

```
$ sudo whytime -- sh -c 'sleep 0.5; dd if=/dev/zero of=$HOME/.cache/wt-demo bs=4k count=2000 oflag=dsync 2>/dev/null'
wall 13.7s
  94%  fsync on ~/.cache
   4%  timer sleep (sleep)
   2%  waiting on child: dd
  <1%  other
critical path: 3 processes · 0 events lost
```

whytime runs a command, traces it and every process it starts with eBPF, and splits the
wall-clock time along the command's critical path: on-CPU, waiting on a child that was
computing, timer sleeps, fsync (per directory), file I/O, network peers (`ip:port`), pipes,
locks, polling, waiting for a CPU. Shares always add up to 100% of the wall time.

```
$ whytime -- ./build.sh            # report on stderr; the command's output passes through
$ whytime --json -- make -j8       # schema whytime.report/1
$ whytime --duration 30s -- ./server   # report after 30 s; the server keeps running
$ whytime doctor                   # can it run here? exact fixes if not
```

whytime exits with the command's exit code (125 if tracing could not start, 126/127 if the
command is not executable / not found).

## Install

One static binary (Rust, musl; the BPF side is C CO-RE compiled by clang — no nightly) for
x86_64 and aarch64. Release tarballs on
[GitHub releases](https://github.com/Arinerron/whytime/releases) contain the binary,
completions and man pages. To build from source, check out
[tracekit](https://github.com/Arinerron/tracekit) next to the repository (it is a `../tracekit`
path dependency):

```sh
git clone https://github.com/Arinerron/whytime
git clone https://github.com/Arinerron/tracekit
cd whytime
cargo build --release -p whytime
sudo install target/x86_64-unknown-linux-musl/release/whytime /usr/local/bin/
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime   # or run it with sudo
```

For arm64: `cargo build --release -p whytime --target aarch64-unknown-linux-musl` (links with
the toolchain's bundled `rust-lld`; no cross compiler needed) →
`target/aarch64-unknown-linux-musl/release/whytime`.

Under `sudo`, the command runs as you (your uid, groups and `HOME`), not as root.
Needs Linux ≥ 5.18 with BTF (`/sys/kernel/btf/vmlinux`).

### Shell completions and man pages

```sh
whytime completions bash | sudo tee /usr/share/bash-completion/completions/whytime >/dev/null
whytime completions zsh  | sudo tee /usr/share/zsh/site-functions/_whytime >/dev/null
whytime completions fish > ~/.config/fish/completions/whytime.fish
# also: elvish, powershell

cargo xtask man target/man          # whytime.1, whytime-doctor.1, ...
sudo install -m 644 target/man/*.1 /usr/local/share/man/man1/
```

## JSON report stability

`--json` emits schema `whytime.report/1`. Within `/1`, changes are additive only (new
optional fields, new `class` values); removing or renaming a field or changing its meaning
bumps the schema to `whytime.report/2`. Consumers must ignore unknown fields and treat an
unknown `class` as `other`. The field reference is in [AGENTS.md](AGENTS.md#report).

## License

MIT, see [LICENSE](LICENSE). The BPF object declares `Dual MIT/GPL` at load time because the
kernel only grants GPL-only helpers to programs with a GPL-compatible license string (MIT
code may be distributed under the GPL). The vendored libbpf headers in
`crates/whytime-bpf/bpf/include/bpf/` keep their own license, `LGPL-2.1 OR BSD-2-Clause`.

## Status: MVP

Wrap mode with off-CPU/on-CPU attribution across the process tree. Not yet: attaching to a
running process (`-p`), flamegraphs, hostnames for network peers (DNS correlation). The
attribution model, its limits, and the developer guide are in [AGENTS.md](AGENTS.md).
