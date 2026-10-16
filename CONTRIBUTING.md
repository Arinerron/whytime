# Contributing to whytime

Thanks for your interest in whytime. This guide is for anyone who wants to report a bug,
propose a feature, or send a change: a typo fix, a new resource class, a probe for an
older kernel, or a new end-to-end scenario. Bug reports with a trace file attached are as
valuable as code.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security
issues go through the private process in [SECURITY.md](SECURITY.md), not public issues.

## Before you start

- For anything larger than a small fix, open an issue first and describe the change. It
  saves you work if the approach needs adjusting.
- [AGENTS.md](AGENTS.md) is the architecture and developer guide: layout, how the BPF object
  is built, the probes, the wire records, the attribution model and its limits, the report
  format, trace files, privileges, the e2e suite and known gotchas. Read the sections that
  touch your change before editing.

## Prerequisites

- Linux 5.18 or newer with BTF (`/sys/kernel/btf/vmlinux` exists), x86_64 or aarch64.
- clang with the BPF target (any clang that compiles BPF CO-RE; check with
  `clang -print-targets | grep bpf`). Override the binary with `CLANG=`.
- Rust stable through [rustup](https://rustup.rs). `rust-toolchain.toml` pins the channel
  and installs the `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` targets
  automatically; no nightly and no `bpf-linker` are needed. The minimum supported Rust
  version is in the root `Cargo.toml` (`rust-version`).
- Passwordless `sudo` (`sudo -n true` succeeds) to run the end-to-end suite, which loads
  BPF programs and sets file capabilities.

## Getting the source

The shared [tracekit](https://github.com/Arinerron/tracekit) crates are a git submodule:

```sh
git clone --recursive https://github.com/Arinerron/whytime
cd whytime
```

If you cloned without `--recursive` (cargo fails with "failed to read
`.../tracekit/crates/wire/Cargo.toml`"), run `git submodule update --init`. Do not change
files under `tracekit/` in a whytime pull request; changes to the shared crates belong in
the tracekit repository.

## Build and test

`.cargo/config.toml` makes `x86_64-unknown-linux-musl` the default target, so every binary
is static and lands under `target/x86_64-unknown-linux-musl/`.

| What | Command |
|---|---|
| Debug build | `cargo build` |
| Release binary | `cargo build --release -p whytime` |
| Unit tests (no root; includes the replay fixtures) | `cargo test --workspace` |
| Re-record the replay fixtures | `cargo xtask record-fixtures` (needs `sudo -n`) |
| End-to-end suite | `cargo xtask test-e2e` |
| aarch64 | `cargo build --release -p whytime --target aarch64-unknown-linux-musl` |
| Man pages | `cargo xtask man [DIR]` (default `$CARGO_TARGET_DIR/man`, or `target/man`) |
| Third-party notices | `cargo xtask licenses [FILE]` (default `$CARGO_TARGET_DIR/THIRD_PARTY_LICENSES.md`, or `target/...`; shipped in release tarballs) |
| Completions | `whytime completions <bash\|zsh\|fish\|elvish\|powershell>` |
| Debug logging | `WHYTIME_LOG=debug whytime ...` (includes the verifier log on load failures) |

If your `/tmp` is small or a tmpfs with a quota, point cargo's scratch and target
directories somewhere roomier before building:

```sh
mkdir -p ~/.cache/whytime-tmp ~/.cache/whytime-target
export TMPDIR=~/.cache/whytime-tmp CARGO_TARGET_DIR=~/.cache/whytime-target
```

With `CARGO_TARGET_DIR` set, binaries are under that directory instead of `target/`.

### End-to-end suite

`cargo xtask test-e2e` builds the release binary and the test workloads, then runs every
scenario through `sudo -n whytime --json` and checks the reports. Its scratch directory is
`~/.cache/whytime-e2e`; set `WHYTIME_E2E_DIR` to use another one (for example one per
checkout, to run suites in parallel). The scratch directory must be on a real filesystem
such as ext4: the suite refuses tmpfs and needs file capabilities, which `nosuid` mounts
ignore. CI runs the same suite in a virtme-ng VM; see the e2e section and the gotchas in
AGENTS.md if you want to reproduce that locally.

## Reporting a bug

Please use the bug report form. The most useful thing you can attach is a trace file:

```sh
sudo whytime --record bug.wt -- CMD     # or: sudo whytime -p PID --record bug.wt
whytime report bug.wt --json           # replays offline, no privileges needed
```

`whytime report` reproduces the report exactly from the file, so a maintainer can debug
the attribution without your machine. Trace files can contain command lines, file paths
and hostnames; look at [SECURITY.md](SECURITY.md#trace-files-contain-sensitive-data)
before sharing one publicly. Also include the full `whytime doctor` output, your kernel
(`uname -r`) and distribution.

## Coding conventions

- **Documentation.** Every item (functions, types, fields, constants, modules) gets a doc
  comment that says what it is for and any invariant the caller must know. Comments explain
  why, not what.
- **Lints and formatting.** The root `Cargo.toml` has the workspace lint block
  (`clippy::all` and `clippy::pedantic` as warnings, with a few documented allowances); do
  not add blanket `allow`s. The tree is not formatted with `rustfmt`: do not run `cargo fmt`
  over it, match the style of the surrounding code, and keep reformatting of unrelated code
  out of your change.
- **Record ABI.** Records shared by the BPF programs and user space are declared once in
  `crates/whytime-abi`. Change a record only there: the C header is generated from it at
  build time, so a mismatch between the Rust and C sides is a compile error. Append new
  fields at the end of a struct, 8-byte aligned, then update the C code that fills them and
  the user-space code that reads them. Never hand-edit a C struct that mirrors a record.
- **Anything that affects the report goes through the recording.** A new `/proc` lookup or
  other external input must be saved in trace files so `whytime report` stays identical to
  the live report (see "Trace files" in AGENTS.md).
- **BPF code** is C CO-RE in `crates/whytime-bpf/bpf/`. Declare only the kernel fields you
  use in `vmlinux_min.h`. Keep per-syscall and per-switch cost low: the programs run for
  every task on the system, and the performance budget in AGENTS.md is guarded by the
  `overhead` e2e scenario.
- **Docs travel with code.** When you change behaviour, update AGENTS.md (and README.md for
  user-visible changes) in the same pull request.

## Adding an end-to-end scenario

1. If no existing workload fits, add a small program to `crates/whytime-testbins/src/bin/`
   (named `wt-<something>`), a matching `[[bin]]` entry in its `Cargo.toml`, and its name
   to the list of binaries xtask expects after the build. Workloads must be deterministic,
   take their durations as arguments, and must not print JSON to stderr (the harness finds
   the report by its schema prefix there).
2. Add a `(name, command, check)` entry to the scenario list in `xtask/src/main.rs`, using
   the existing helpers to run whytime under `sudo -n` and a `check_*` function that parses
   the report and asserts on class shares and subjects. Prefer thresholds with margin over
   exact numbers: the suite runs on loaded machines and in VMs. Return a `Skip` error, with
   the reason, when the environment cannot run the scenario.
3. Document the scenario in the "e2e suite" list in AGENTS.md: workload, expectation, and
   why the threshold holds.
4. Run `cargo xtask test-e2e` and include the PASS line in your pull request.

## Commits and pull requests

- Keep each pull request to one logical change; split refactors from behaviour changes.
- Write commit subjects in the imperative mood, under about 72 characters, with a body that
  explains why the change is needed when it is not obvious.
- Make sure `cargo build`, `cargo test --workspace` and, for anything that touches tracing,
  attribution or reporting, `cargo xtask test-e2e` pass. Say in the pull request what you
  ran and on which kernel.
- Add an entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for user-visible
  changes.
- CI runs the build, unit tests, an aarch64 build with a qemu smoke test, and the e2e suite
  in a VM. A maintainer reviews every pull request; expect questions about overhead and
  about how the change is reflected in the report.

## Report schema policy

`whytime --json` emits schema `whytime.report/1`. Within `/1`, changes are additive only:
new optional fields and new `class` values. Removing or renaming a field, or changing the
meaning of an existing one, requires bumping the schema to `whytime.report/2` and should be
discussed in an issue first. Consumers ignore unknown fields and treat an unknown `class`
as `other`, so additive changes are safe. If your change touches the JSON report, update
the field reference in AGENTS.md and call out the schema impact in the pull request.

The trace file format is versioned separately (see `crates/whytime/src/record.rs`); a
change to the record layout makes older trace files fail to replay with exit status 2,
which is expected.

## License

whytime is licensed under the [MIT License](LICENSE). By contributing, you agree that your
contributions are licensed under the same terms.
