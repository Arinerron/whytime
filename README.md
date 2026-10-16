# whytime

`time` tells you how long. `whytime` tells you **where it went**.

```
$ sudo whytime -- sh -c 'sleep 0.5; dd if=/dev/zero of=$HOME/.cache/wt-demo bs=4k count=2000 oflag=dsync 2>/dev/null'
wall 16.3s
cpu 356ms across 3 processes · 0.02× parallel
  94%  fsync on ~/.cache
   3%  timer sleep (sleep)
   2%  waiting on child: dd
   1%  other
critical path: 3 processes · 0 events lost
```

whytime runs a command, traces it and every process it starts with eBPF, and splits the
wall-clock time along the command's critical path: on-CPU, waiting on a child that was
computing, timer sleeps, fsync (per directory), file I/O, file locks (`flock`/`fcntl`),
async I/O completions (io_uring, AIO), network peers (`example.com:443`), pipes and other IPC,
futexes, polling, page faults (per mapped file's directory), waiting for a CPU. Shares always
add up to 100% of the wall time. When the command waits on another of its threads or
processes (joining workers, a contended lock, a pipe, a child), the time is explained by what
that task was doing: a main thread joining CPU-bound workers is on-CPU, a lock held across a
sleep is the sleep. A poll/select/epoll wait is reported as the descriptor that became ready
(so `curl` shows its server, not "poll"), and a pipe or poll wait ended by a process outside
the tree names it (`woken by dbus-daemon`). File subjects are captured in the kernel when the
process blocks, so they name the directory even for processes that are gone by the time
whytime reports. Network peers are named after the host the command looked up, read from
its resolver's answers (DNS on port 53 over UDP or TCP, or systemd-resolved as glibc's
`getaddrinfo` uses it), so `curl https://example.com` shows `blocked on network:
example.com:443`; peers reached by address, or looked up before whytime started, stay
`ip:port`. In `--json`, a named peer's line also carries its numeric address (`addr`).

```
$ whytime -- ./build.sh            # report on stderr; the command's output passes through
$ whytime --json -- make -j8       # schema whytime.report/1
$ whytime --duration 30s -- ./server   # report after 30 s; the server keeps running
$ whytime -p 4242                  # attach to a running process; report on exit or Ctrl-C
$ whytime -p 4242 --duration 10s   # ... or after 10 s
$ whytime doctor                   # can it run here? exact fixes if not
$ whytime --record ci.wt -- make   # also save a trace file...
$ whytime report ci.wt [--json]    # ...and print the same report from it later, offline
$ whytime --timeline -- make       # add the window in 10 slices, each with its top lines
$ whytime --perfetto t.json -- make    # also write every thread's timeline for ui.perfetto.dev
```

`--json`, `--timeline` and `--perfetto FILE` work alike in wrap mode, with `-p PID` and with
`whytime report FILE`.

whytime exits with the command's exit code (125 if tracing could not start, 126/127 if the
command is not executable / not found).

A trace file holds the raw kernel records and every lookup the report used (with `-p`, also
what whytime read from `/proc` when it attached), so `whytime report` reproduces the report
exactly, offline and without privileges (attach it to a bug report or a CI artifact). It
exits 2 if the file is damaged or was recorded by a whytime with a different record layout.
Under `sudo`, the file belongs to you.

## Parallelism, same-named processes, CPU holders, timeline

The second line says how much CPU the whole tree used in the window and how many CPUs that
kept busy on average, including work beside the critical path. Processes that share a name
but not their arguments get lines of their own, named by the shortest distinguishing tail
of their arguments (more than four variants, like a build's compiler runs, stay one line):

```
$ sudo whytime -- sh -c 'seq 1 300000 | sort -R | sort -n | tail -1'
300000
wall 6.69s
cpu 6.72s across 5 processes · 1.0× parallel
  93%  waiting on child: sort -R
   5%  waiting on child: sort -n
   1%  other
critical path: 5 processes · 0 events lost
```

Waiting for a CPU says who held it when one task did most of the holding, and `--timeline`
shows when each line happened (here a busy `wt-hog` and the whole pipeline share CPU 21):

```
$ taskset -c 21 ./wt-hog 8000 &
$ sudo whytime --timeline -- taskset -c 21 sh -c 'seq 1 300000 | sort -n | md5sum'
daef482d6c698625ab13d987d14e8781  -
wall 519ms
cpu 270ms across 4 processes · 0.52× parallel
  43%  waiting for a CPU (sort)
  40%  waiting on child: sort
   5%  waiting for a CPU (md5sum) — mostly sort 81%
   4%  waiting for a CPU (seq) — mostly sort 72%
   2%  waiting on child: seq
   2%  waiting on child: md5sum
   2%  waiting for a CPU (sh) — mostly wt-hog 53%
   1%  other
timeline (52ms slices):
     0–52ms  child sort 27% · runqueue seq 20% · runqueue sh 16%
   52–104ms  child sort 100%
  104–156ms  runqueue sort 85% · child sort 15%
  156–207ms  runqueue sort 56% · runqueue seq 18% · child sort 17%
  207–259ms  child sort 100%
  259–311ms  runqueue sort 82% · child sort 18%
  311–363ms  runqueue sort 59% · child sort 28% · runqueue sh 5%
  363–415ms  child sort 54% · runqueue sort 46%
  415–467ms  runqueue sort 54% · runqueue md5sum 21% · child sort 17%
  467–519ms  runqueue sort 33% · child sort 27% · runqueue md5sum 25%
critical path: 4 processes · 0 events lost
```

In JSON these are `parallelism`, the line subjects, `held_by: [{comm, tgid, ns}]` on
runqueue lines and (with `--timeline`) `timeline`. `--perfetto FILE` writes a Chrome Trace
Event file (open it in [ui.perfetto.dev](https://ui.perfetto.dev) or chrome://tracing): one
track per traced thread with its on-CPU, runqueue and blocked stretches (named by class and
subject; syscall, waker and CPU holder in the arguments), fork/exec/exit markers, and a
`critical path` track with the stretches the report adds up.

## Attaching to a running process

`whytime -p PID` traces PID and its descendants (existing ones, and every process they
start) from the moment it attaches until PID exits, `--duration` elapses, or you press
Ctrl-C; then it reports and exits 0. PID itself is never signalled.

```
$ bash -c 'while true; do sleep 0.2; dd if=/dev/zero of=/dev/null bs=1M count=3000 2>/dev/null; done' &
$ sudo whytime -p $! --duration 3s
wall 3.00s
cpu 1.37s across 18 processes · 0.46× parallel
  54%  timer sleep (sleep)
  45%  waiting on child: dd
   1%  other
critical path: 18 processes · 0 events lost
note: attached to running pid 2158752: time before attach is not covered, and each pre-existing thread's first interval is classified from /proc
note: --duration elapsed; the command was still running
```

Time before the attach is not covered. What each thread was doing when whytime attached
(its syscall, and the file, pipe or peer it waits on) is read from `/proc`; without root
that needs ptrace access to the process (`kernel.yama.ptrace_scope`), else that first
stretch is reported as `other` with a note. Without root, whytime attaches only to your
own processes.

## Install

One static binary (Rust, musl; the BPF side is C CO-RE compiled by clang — no nightly) for
x86_64 and aarch64. Release tarballs on
[GitHub releases](https://github.com/Arinerron/whytime/releases) contain the binary,
completions and man pages. To build from source, clone with submodules (the shared
[tracekit](https://github.com/Arinerron/tracekit) crates are pinned as the `tracekit`
submodule):

```sh
git clone --recursive https://github.com/Arinerron/whytime
cd whytime
cargo build --release -p whytime
sudo install target/x86_64-unknown-linux-musl/release/whytime /usr/local/bin/
sudo setcap cap_bpf,cap_perfmon+ep /usr/local/bin/whytime   # or run it with sudo
```

Already cloned without `--recursive` (cargo fails with "failed to read
`…/tracekit/crates/wire/Cargo.toml`")? Run `git submodule update --init`.

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

Wrap and attach mode with off-CPU/on-CPU attribution across the process tree, hostnames for
network peers, trace files for both (`--record`, `whytime report`), timeline and Perfetto
export. Not yet: flamegraphs. The attribution model, its limits, and the developer guide are
in [AGENTS.md](AGENTS.md).
