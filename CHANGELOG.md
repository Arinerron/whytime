# Changelog

All notable changes to whytime are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/). The JSON report has its own schema version
(`whytime.report/1`), which only changes additively within a major schema version.

## [Unreleased]

## [0.1.0] - 2026-10-16

First release.

### Added

- Wrap mode, `whytime -- COMMAND`: runs COMMAND, traces it and every process it starts
  with eBPF, and splits its wall-clock time along the critical path across the whole
  process tree. Shares always add up to 100% of the wall time. COMMAND's output passes
  through and whytime exits with its exit code.
- Attach mode, `whytime -p PID`: traces a running process and its descendants from the
  attach until it exits, `--duration` elapses or Ctrl-C, without signalling it. The state
  of each pre-existing thread at attach time is read from `/proc`.
- Trace files: `--record FILE` saves a run (wrap or attach mode), and `whytime report FILE`
  replays it offline, without privileges, into the identical report, with any of the report
  options below.
- Follow-the-waker attribution: when the critical path waits on another thread or process
  (futexes, pipes and other IPC, poll, `wait` on a child, `vfork`), the time is explained by
  what that task was doing.
- Resource classes: `cpu`, `child`, `runqueue`, `sleep`, `fsync`, `file`, `lock`, `aio`,
  `net`, `ipc`, `futex`, `poll`, `fault`, `signal`, `tty` and `other`.
- In-kernel file path capture when a process blocks, so file, fsync and lock subjects name
  the directory even for processes that have exited by report time.
- Poll, select and epoll waits are attributed to the descriptor that became ready (for
  example the network peer) instead of `poll`.
- Page-fault attribution to the directory of the mapped file.
- Out-of-tree wakers are named (`woken by dbus-daemon`) when a process outside the traced
  tree ends a pipe or poll wait.
- Network peers are named after the host the traced tree looked up, read from its resolver
  traffic (DNS wire format over UDP and TCP on port 53, and systemd-resolved varlink as used
  by glibc's `getaddrinfo`); the numeric address stays available in the JSON report.
- Runqueue time reports the process that held the CPU.
- Flamegraphs of the critical path: `--flamegraph FILE` (SVG) and `--folded FILE` (folded
  stacks in microseconds), with on-CPU samples and the stacks where threads blocked.
- `--perfetto FILE`: export to the Chrome Trace Event format for Perfetto
  (`ui.perfetto.dev`) and `chrome://tracing`, with every traced thread and the critical path.
- `--timeline`: a time-bucketed timeline of the report; a parallelism summary.
- JSON output, `--json`, with schema `whytime.report/1`.
- `whytime doctor`: checks whether whytime can run on this system and prints the exact fix
  for each problem.
- Under `sudo`, COMMAND runs as the invoking user (uid, groups and `HOME`); alternatively,
  file capabilities (`setcap cap_bpf,cap_perfmon+ep`) let whytime run without `sudo`.
- `whytime completions SHELL` (bash, zsh, fish, elvish, PowerShell) and man pages.
- Static musl binaries for x86_64 and aarch64, published as release tarballs with
  completions and man pages.

[Unreleased]: https://github.com/Arinerron/whytime/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Arinerron/whytime/releases/tag/v0.1.0
