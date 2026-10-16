# Security Policy

## Supported versions

whytime is pre-1.0. Security fixes are made on the `main` branch and released in a new
version of the latest release line; older releases are not patched.

| Version | Supported |
|---|---|
| 0.1.x (latest release) | Yes |
| Older | No |

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions or pull
requests.

Report them privately through GitHub's private vulnerability reporting:
[open a draft security advisory](https://github.com/Arinerron/whytime/security/advisories/new)
on Arinerron/whytime (Security tab, "Report a vulnerability"). If that is not available to
you, contact the maintainer through their [GitHub profile](https://github.com/Arinerron)
and ask for a private channel without including details.

Please include:

- the whytime version (`whytime --version`), kernel (`uname -r`) and distribution;
- how whytime was granted privileges (`sudo`, file capabilities via `setcap`, or root);
- the steps or a proof of concept, and the impact you observed;
- whether the issue is already public anywhere.

We aim to acknowledge a report within 7 days and to send an initial assessment within 14
days. We will keep you informed while a fix is prepared, agree on a disclosure date with you, and
credit you in the advisory and the changelog unless you prefer otherwise.

## Security model and scope

whytime loads eBPF programs into the kernel, so it runs with elevated privileges. Reports
about the boundaries below are especially welcome.

### Privileges

- whytime needs `CAP_BPF` and `CAP_PERFMON`, or root. It gets them either from `sudo` or
  from file capabilities set once with
  `sudo setcap cap_bpf,cap_perfmon+ep /path/to/whytime`.
- **Under sudo**, whytime drops privileges before it runs COMMAND: the command runs with
  the invoking user's uid, gid and supplementary groups (from `SUDO_UID`, `SUDO_GID` and
  `SUDO_USER`), with `HOME`, `USER` and `LOGNAME` restored. If the drop fails, whytime exits
  with status 125 instead of running the command. Output files (`--record`, `--perfetto`,
  `--flamegraph`, `--folded`) are opened by a child process running as the invoking user,
  never by root, so whytime writes only where that user could.
- **With file capabilities**, the capabilities apply to the whytime process only; the
  kernel drops them when it executes COMMAND (no ambient capabilities are set). Every user
  who can execute a whytime binary with file capabilities gets `CAP_BPF` and `CAP_PERFMON`
  within it. If that is not acceptable on a shared machine, restrict who may execute it,
  for example with a dedicated group and mode `0750`. File capabilities are ignored on
  `nosuid` mounts.
- **Attach mode** (`-p PID`) without root accepts only processes whose real, effective and
  saved uid and gid all match the invoking user (the ptrace rule), unless whytime also has
  `CAP_SYS_PTRACE`. It refuses pid 1 and itself, and never signals the target.
- `whytime report FILE` never loads BPF programs and needs no privileges.

Examples of issues in scope:

- a way for an unprivileged user to use a whytime binary with file capabilities to observe
  or affect processes or data they could not otherwise access, or to keep capabilities in
  COMMAND;
- COMMAND running with more privileges than the invoking user under `sudo`;
- a trace file, reply from a resolver, or other untrusted input that makes whytime crash in
  a way other than a clean error, read or write outside its buffers, or create or overwrite
  files it should not (for example through `--record` under `sudo`);
- a BPF program that can destabilize the kernel or leak kernel memory into a report or
  trace file.

Out of scope: anything that requires root or the capabilities whytime is granted to begin
with, kernel or verifier bugs that whytime merely exposes (please report those upstream,
but feel free to let us know), and information the report is documented to contain (below).

### Trace files contain sensitive data

Reports, trace files written by `--record`, and exports such as flamegraphs and Perfetto
traces describe what the traced processes did. Treat trace files in particular as
sensitive before attaching them to a public issue. They can contain:

- the command line and the argument vectors of every traced process (truncated, but often
  enough to include tokens or passwords passed on the command line);
- file and directory paths the processes waited on, and your home directory;
- network peer addresses and ports;
- hostnames the processes looked up, derived from raw resolver traffic (DNS messages on
  port 53 and systemd-resolved varlink requests and replies) that is stored verbatim;
- process names (`comm`) of processes outside the traced tree that woke a traced thread or
  held its CPU;
- with `--flamegraph` or `--folded`, the symbolized call stacks of the traced processes
  (function names and the names of the binaries and libraries they ran);
- in attach mode, what whytime read from `/proc` when it attached.

Under `sudo`, trace, Perfetto and flamegraph files are created by the invoking user and
belong to them. Review or redact what you share; a maintainer can usually work with a
trace of a minimal reproduction instead of a production workload.
