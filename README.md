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
computing, timer sleeps, fsync (per directory), file I/O, file locks (`flock`/`fcntl`),
async I/O completions (io_uring, AIO), network peers (`ip:port`), pipes and other IPC,
futexes, polling, waiting for a CPU. Shares always add up to 100% of the wall time. When the
command waits on another of its threads or processes (joining workers, a contended lock, a
pipe, a child), the time is explained by what that task was doing: a main thread joining
CPU-bound workers is on-CPU, a lock held across a sleep is the sleep. File subjects are
captured in the kernel when the process blocks, so they name the directory even for
processes that are gone by the time whytime reports.

```
$ whytime -- ./build.sh            # report on stderr; the command's output passes through
$ whytime --json -- make -j8       # schema whytime.report/1
$ whytime --duration 30s -- ./server   # report after 30 s; the server keeps running
$ whytime -p 4242                  # attach to a running process; report on exit or Ctrl-C
$ whytime -p 4242 --duration 10s   # ... or after 10 s
$ whytime doctor                   # can it run here? exact fixes if not
$ whytime --record ci.wt -- make   # also save a trace file...
$ whytime report ci.wt [--json]    # ...and print the same report from it later, offline
```

whytime exits with the command's exit code (125 if tracing could not start, 126/127 if the
command is not executable / not found).

A trace file holds the raw kernel records and every lookup the report used (with `-p`, also
what whytime read from `/proc` when it attached), so `whytime report` reproduces the report
exactly, offline and without privileges (attach it to a bug report or a CI artifact). It
exits 2 if the file is damaged or was recorded by a whytime with a different record layout.
Under `sudo`, the file belongs to you.

## Attaching to a running process

`whytime -p PID` traces PID and its descendants (existing ones, and every process they
start) from the moment it attaches until PID exits, `--duration` elapses, or you press
Ctrl-C; then it reports and exits 0. PID itself is never signalled.

```
$ bash -c 'while true; do sleep 0.2; dd if=/dev/zero of=/dev/null bs=1M count=3000 2>/dev/null; done' &
$ sudo whytime -p $! --duration 3s
wall 3.00s
  55%  waiting on child: dd
  44%  timer sleep (sleep)
   1%  other
critical path: 16 processes · 0 events lost
note: attached to running pid 1414887: time before attach is not covered, and each pre-existing thread's first interval is classified from /proc
note: --duration elapsed; the command was still running
```

Time before the attach is not covered. What each thread was doing when whytime attached
(its syscall, and the file, pipe or peer it waits on) is read from `/proc`; without root
that needs ptrace access to the process (`kernel.yama.ptrace_scope`), else that first
stretch is reported as `other` with a note. Without root, whytime attaches only to your
own processes.

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

Wrap and attach mode with off-CPU/on-CPU attribution across the process tree, and trace
files for both (`--record`, `whytime report`). Not yet: flamegraphs, hostnames for network
peers (DNS correlation). The attribution model, its limits, and the developer guide are in
[AGENTS.md](AGENTS.md).
