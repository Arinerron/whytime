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
$ whytime --record ci.wt -- make   # also save a trace file...
$ whytime report ci.wt [--json]    # ...and print the same report from it later, offline
```

whytime exits with the command's exit code (125 if tracing could not start, 126/127 if the
command is not executable / not found).

A trace file holds the raw kernel records and every lookup the report used, so
`whytime report` reproduces the report exactly, offline and without privileges (attach it to
a bug report or a CI artifact). It exits 2 if the file is damaged or was recorded by a
whytime with a different record layout. Under `sudo`, the file belongs to you.

## Install

One static binary (Rust, musl; the BPF side is C CO-RE compiled by clang — no nightly).

```sh
cargo build --release -p whytime
sudo install target/x86_64-unknown-linux-musl/release/whytime /usr/local/bin/
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime   # or run it with sudo
```

Under `sudo`, the command runs as you (your uid, groups and `HOME`), not as root.
Needs Linux ≥ 5.18 with BTF (`/sys/kernel/btf/vmlinux`).

## Status: MVP

Wrap mode with off-CPU/on-CPU attribution across the process tree, and trace files
(`--record`, `whytime report`). Not yet: attaching to a running process (`-p`), flamegraphs,
hostnames for network peers (DNS correlation). The attribution model, its limits, and the
developer guide are in [AGENTS.md](AGENTS.md).
