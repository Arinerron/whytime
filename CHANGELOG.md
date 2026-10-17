# Changelog

All notable changes to whytime are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/). The JSON report has its own schema version
(`whytime.report/1`), which only changes additively within a major schema version.

## [Unreleased]

### Added

- More ways to install, see the README: an install script (`curl -fsSL
  https://github.com/Arinerron/whytime/releases/latest/download/install.sh | sh`), `.deb`,
  `.rpm`, `.apk` and Arch packages attached to each release (with `SHA256SUMS`), the AUR
  packages `whytime-bin` and `whytime`, a Nix flake (`nix run github:Arinerron/whytime`), a
  container image (`ghcr.io/arinerron/whytime`) and `cargo binstall whytime`.

### Changed

- The man pages are written by hand: whytime(1) explains the report, every class, attach
  mode, trace files, flamegraphs, JSON output, privileges and exit status, and
  whytime-report(1), whytime-doctor(1) (every check) and whytime-completions(1) are full
  pages; the option lists are still generated from the CLI.
- The embedded BPF objects no longer contain the build directory, so builds from the same
  source are reproducible across directories.

## [0.1.1] - 2026-10-16

### Added

- Published on crates.io: `cargo install --locked whytime` (needs clang with the BPF target
  and Rust 1.94 or newer). The internal crates `whytime-abi` and `whytime-bpf` are
  published alongside it, pinned to the same version.

### Changed

- The trace file format changed (32-bit syscalls are recorded as such): `whytime report`
  refuses files recorded by 0.1.0 with exit status 2.

### Security

- Under `sudo`, output files (`--record`, `--perfetto`, `--flamegraph`, `--folded`) are
  created with the invoking user's permissions. They were previously opened as root,
  following symlinks and truncating whatever file was there, then handed to the user.

### Fixed

- whytime builds on glibc targets (x86_64 and aarch64 `*-linux-gnu`), not only musl.
- whytime no longer aborts (exit 134) when stderr is a closed pipe, as in
  `whytime -- make 2>&1 | head`.
- Control characters in process names, arguments and paths are escaped in the text report,
  and no longer make flamegraph SVGs invalid.
- Signals inherited as ignored (`nohup`, background jobs of non-interactive shells) stay
  ignored for COMMAND.
- The `--perfetto` path is checked before COMMAND runs, like the other output files,
  instead of failing after the run.
- Attach mode holds the target before checking its owner, so a PID reused in between can no
  longer be traced in its place.
- Misspelled options (`--duraton 5`) are rejected instead of being run as COMMAND.
- COMMAND no longer inherits a raised `RLIMIT_MEMLOCK`.
- The exit of a process whose last thread to exit is an io_uring SQPOLL or vhost worker is
  no longer missed.
- 32-bit (compat) syscalls of 32-bit programs are no longer misclassified as the 64-bit
  syscall with the same number.
- `whytime doctor` points to the verifier log (`WHYTIME_LOG=debug`) when the verifier
  rejects a program, instead of suggesting `setcap` or `sudo`.
- whytime loads on kernels built without IPv6.
- Host names are recovered from DNS over TCP as musl's resolver does it, and a TCP reply
  read in several pieces is no longer partly parsed as a new message.
- A wakeup or a ready descriptor recorded just as a thread blocked is no longer lost, which
  attributed the wait to its syscall instead of to its waker or the ready descriptor.
- Report time no longer grows quadratically or cubically with chains of threads handing
  work over to each other.
- Waits ended by a process outside the traced tree are no longer chained as timeouts.
- The waker of a wait is found after a non-leader thread calls `exec`.
- `sync()` and `msync()` no longer read a file descriptor from an unrelated register, which
  attributed them to an unrelated file.
- Crafted trace files whose traced process has no threads are rejected instead of aborting
  `whytime report`.

## [0.1.0] - 2026-10-16

First release.

### Added

- Wrap mode, `whytime -- COMMAND`: runs COMMAND, traces it and every process it starts
  with eBPF, and splits its wall-clock time along the critical path across the whole
  process tree. Shares always add up to 100% of the wall time. COMMAND's output passes
  through, the report goes to stderr, and whytime exits with COMMAND's exit code (125 if
  tracing could not start, 126/127 if COMMAND is not executable / not found).
- Attach mode, `whytime -p PID` (`--pid`): traces a running process and its descendants
  from the attach until it exits, `--duration` elapses or Ctrl-C, without signalling it.
  The state of each pre-existing thread at attach time is read from `/proc`. Exits 0 after
  the report, 1 if PID cannot be attached to.
- `--duration D` (`500ms`, `30s`, `2m`, ...) in both modes: report after D while COMMAND or
  PID keeps running.
- Trace files: `--record FILE` saves a run (wrap or attach mode), and `whytime report FILE`
  replays it offline, without privileges, into the identical report, with any of the report
  options below (exit 2 if the file cannot be replayed).
- Follow-the-waker attribution: when the critical path waits on another thread or process
  (futexes, pipes and other IPC, poll, `wait` on a child, `vfork`), the time is explained by
  what that task was doing.
- Resource classes: `cpu`, `child`, `runqueue`, `sleep`, `fsync`, `file`, `lock`, `aio`,
  `net`, `ipc`, `futex`, `poll`, `fault`, `signal`, `tty` and `other`.
- In-kernel file path capture when a process blocks, so file, fsync and lock subjects name
  the directory even for processes that have exited by report time.
- Poll, select and epoll waits are attributed to the descriptor that became ready (for
  example the network peer) instead of `poll`.
- Page-fault attribution to the directory of the mapped file, or to anonymous memory.
- Out-of-tree wakers are named (`woken by dbus-daemon`) when a process outside the traced
  tree ends a pipe or poll wait.
- Network peers are named after the host the traced tree looked up, read from its resolver
  traffic (DNS wire format over UDP and TCP on port 53, and systemd-resolved varlink as used
  by glibc's `getaddrinfo`); the numeric address stays available in the JSON report
  (`addr`).
- Processes that share a name but not their arguments get separate lines, named by the
  shortest distinguishing tail of their arguments (`sort -R`, `sort -n`).
- Runqueue lines name the task that held the CPU (`held_by` in JSON, `— mostly X N%` in
  the text report).
- A parallelism summary: CPU time of the whole tree in the window and the average number
  of busy CPUs (`parallelism` in JSON).
- `--timeline`: the window in 10 equal slices, each with its largest lines.
- `--perfetto FILE`: export to the Chrome Trace Event format for Perfetto
  (`ui.perfetto.dev`) and `chrome://tracing`, with every traced thread and the critical path.
- Flamegraphs of the critical path: `--flamegraph FILE` (SVG) and `--folded FILE` (folded
  stacks in microseconds), with on-CPU samples at 199 Hz and the stacks where threads
  blocked; in wrap and attach mode, and from trace files recorded with either flag.
- JSON output, `--json`, with schema `whytime.report/1`.
- `whytime doctor` (`--json` for schema `bpfdoctor/1`): checks whether whytime can run on
  this system, loads every probe set, and prints the exact fix for each problem.
- Under `sudo`, COMMAND runs as the invoking user (uid, groups and `HOME`); alternatively,
  file capabilities (`setcap cap_bpf,cap_perfmon+ep`) let whytime run without `sudo`.
- `whytime completions SHELL` (bash, zsh, fish, elvish, PowerShell) and man pages.
- `WHYTIME_LOG=debug` for debug logging, including the BPF verifier log on load failures.
- Static musl binaries for x86_64 and aarch64, published as release tarballs with
  completions, man pages, the license texts of the code compiled into them
  (`THIRD_PARTY_LICENSES.md`) and SHA-256 checksums.

[Unreleased]: https://github.com/Arinerron/whytime/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Arinerron/whytime/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Arinerron/whytime/releases/tag/v0.1.0
