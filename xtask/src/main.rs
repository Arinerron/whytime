//! Build and test automation for whytime.
//!
//! `cargo xtask test-e2e` builds the release binaries, then runs each scenario under
//! `sudo -n` with `--json` and asserts on the report. Every report must have shares summing to
//! 1 ± 0.001 and no lost records.
//!
//! `cargo xtask man [DIR]` writes `whytime.1` and one page per subcommand to DIR (default
//! `$CARGO_TARGET_DIR/man`, else `target/man`), from the binary's own clap definition.

/// The binary's CLI, compiled in from its source so the man pages cannot drift from it.
#[path = "../../crates/whytime/src/cli.rs"]
#[allow(dead_code)]
mod cli;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use clap::CommandFactory as _;
use serde_json::Value;

const USAGE: &str = "usage: cargo xtask test-e2e | cargo xtask man [DIR]";
/// Delay of the scenario-6 server between accept and reply.
const SERVER_DELAY: Duration = Duration::from_millis(300);
/// Seconds the attach scenarios let their target run before whytime attaches.
const ATTACH_DELAY: &str = "0.3";
/// Seconds of slack on the attach-interrupt window around the span the script measured
/// (ready → `kill`): `/proc/uptime` ticks (10 ms), the 10 ms poll for ready, and whytime's
/// wakeup on the signalfd (measured ≤ 1.3 ms after the signal).
const INTERRUPT_SLACK: f64 = 0.1;
/// A pid above any `pid_max`, so no process has it.
const NO_PID: &str = "4194304";
/// One-byte reads `wt-syscalls` does in the overhead scenario.
const OVERHEAD_READS: &str = "2000000";
/// Runs of each side (traced, untraced) in the overhead scenario; the fastest counts.
const OVERHEAD_RUNS: usize = 5;
/// Highest accepted traced/untraced on-CPU time ratio of `wt-syscalls`: measured 1.4–1.8
/// under parallel load (describing every syscall at `sys_enter`, as before, measured 2.2).
const MAX_OVERHEAD: f64 = 2.5;
/// Where the suite's DNS server (`wt-dns serve`) listens: port 53, as resolver capture
/// expects, on a loopback address of its own.
const DNS_SERVER: &str = "127.0.0.153:53";
/// The name it resolves, to 127.0.0.1 (the slow server's address).
const DNS_NAME: &str = "slow.whytime.test";
/// systemd-resolved's varlink socket, which glibc's nss-resolve talks to.
const RESOLVED_SOCKET: &str = "/run/systemd/resolve/io.systemd.Resolve";

/// A check outcome that is neither pass nor failure: the host lacks what the scenario needs.
#[derive(Debug)]
struct Skip(String);

impl std::fmt::Display for Skip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Skip {}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("test-e2e") => test_e2e(),
        Some("man") => man(args.next().map(PathBuf::from)),
        _ => bail!("{USAGE}"),
    }
}

/// Renders the man pages into `dir`.
fn man(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = match dir {
        Some(dir) => dir,
        None => std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(
                || Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"),
                PathBuf::from,
            )
            .join("man"),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    clap_mangen::generate_to(cli::Cli::command(), &dir)
        .with_context(|| format!("writing man pages to {}", dir.display()))?;
    println!("{}", dir.display());
    Ok(())
}

fn test_e2e() -> anyhow::Result<()> {
    let bins = build()?;
    let ok = Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .context("running sudo")?;
    ensure!(ok.success(), "the e2e suite needs passwordless `sudo -n`");

    // WHYTIME_E2E_DIR lets parallel checkouts run the suite without sharing files.
    let work = match std::env::var_os("WHYTIME_E2E_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?)
            .join(".cache/whytime-e2e"),
    };
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    let fs_type = run(Command::new("stat").args(["-f", "-c", "%T"]).arg(&work))?;
    let fs_type = String::from_utf8_lossy(&fs_type.stdout).trim().to_owned();
    ensure!(
        fs_type != "tmpfs",
        "{} is on tmpfs; fsync would not wait",
        work.display()
    );

    let server = slow_server()?;
    let whytime = &bins["whytime"];
    let bin = |name: &str| bins[name].display().to_string();
    let sudo = |args: &[&str]| traced(whytime, args);

    let fsync_dir = work.display().to_string();
    let server_arg = server.to_string();
    let trace_file = work.join("replay.wt");
    let attach_trace = work.join("attach.wt");
    let perfetto_file = work.join("replay.perfetto.json");
    let attach_perfetto = work.join("attach.perfetto.json");
    // An untraced CPU hog with its own comm: wt-burn under another name.
    let hog = work.join("wt-hog");
    let _ = std::fs::remove_file(&hog);
    std::os::unix::fs::symlink(&bins["wt-burn"], &hog)
        .with_context(|| format!("linking {}", hog.display()))?;
    // A fresh directory per run; wt-flock creates it and removes it (renamed) on success.
    let lock_dir = work.join(format!("flock-{}", std::process::id()));
    let mut lock_moved = lock_dir.clone().into_os_string();
    lock_moved.push(".moved");
    let _ = std::fs::remove_dir_all(&lock_dir);
    let _ = std::fs::remove_dir_all(&lock_moved);
    let lock_subject = home_relative(&lock_dir);
    let lock_arg = lock_dir.display().to_string();
    let overhead_whytime = whytime.clone();
    let syscalls = bin("wt-syscalls");
    // wt-fault write leaves the file synced and out of the page cache (touch checks it).
    let fault_file = work.join("fault.bin").display().to_string();
    let wrote = run(Command::new(bin("wt-fault")).args(["write", &fault_file, "128"]))?;
    ensure!(wrote.status.success(), "wt-fault write {fault_file} failed");
    let fault_dir = home_relative(&work.canonicalize()?);
    let fifo = work.join("waker.fifo");
    let _ = std::fs::remove_file(&fifo);
    let made = run(Command::new("mkfifo").arg(&fifo))?;
    ensure!(made.status.success(), "mkfifo {} failed", fifo.display());
    let watched = work.join("waker.watched");
    std::fs::write(&watched, b"").with_context(|| format!("creating {}", watched.display()))?;
    let mut dns_server = dns_server(&bins["wt-dns"], &work)?;
    let dns_trace = work.join("dns.wt");
    let dns_perfetto = work.join("dns.perfetto.json");
    let port = server.port().to_string();
    let varlink_skip = varlink_skip();
    let scenarios: Vec<(&str, Command, Check)> = vec![
        (
            "sleep",
            sudo(&[&bin("wt-sleep"), "1000"]),
            Box::new(check_sleep),
        ),
        (
            "cpu-burn",
            sudo(&[&bin("wt-burn"), "1000"]),
            Box::new(check_burn),
        ),
        (
            "fsync",
            sudo(&[&bin("wt-fsync"), &fsync_dir, "200"]),
            Box::new(check_fsync),
        ),
        (
            "child",
            sudo(&[&bin("wt-child"), "1000"]),
            Box::new(check_child),
        ),
        (
            "lock-holder",
            sudo(&[&bin("wt-futex"), "500"]),
            Box::new(check_lock_holder),
        ),
        (
            "tcp-slow",
            sudo(&[&bin("wt-tcp"), &server_arg, "3"]),
            Box::new(move |out: &Output| check_tcp(out, server)),
        ),
        (
            "exit-code",
            sudo(&["sh", "-c", "exit 7"]),
            Box::new(check_exit_code),
        ),
        (
            "nopriv",
            {
                let mut cmd = Command::new(whytime);
                cmd.args(["--json", "--", "true"]);
                cmd
            },
            Box::new(check_nopriv),
        ),
        (
            "setcap",
            setcap_copy(whytime, &work, &bin("wt-sleep"))?,
            Box::new(check_setcap),
        ),
        (
            "threads-cpu",
            sudo(&[&bin("wt-threads"), "4", "600"]),
            Box::new(check_threads_cpu),
        ),
        (
            "threads-timed",
            sudo(&[&bin("wt-threads"), "4", "600", "50"]),
            Box::new(check_threads_cpu),
        ),
        (
            "vfork",
            sudo(&[&bin("wt-vfork"), "600"]),
            Box::new(check_vfork),
        ),
        (
            "flock-path",
            sudo(&[&bin("wt-flock"), &lock_arg, "600"]),
            Box::new(move |out: &Output| check_flock(out, &lock_subject)),
        ),
        (
            "overhead",
            sudo(&[&syscalls, OVERHEAD_READS]),
            Box::new(move |out: &Output| check_overhead(out, &overhead_whytime, &syscalls)),
        ),
        (
            "poll-ready",
            sudo(&[&bin("wt-poll"), &server_arg, "4"]),
            Box::new(move |out: &Output| check_poll(out, server)),
        ),
        (
            "fault",
            sudo(&[&bin("wt-fault"), "touch", &fault_file]),
            Box::new(move |out: &Output| check_fault(out, &fault_dir)),
        ),
        (
            "waker",
            {
                // sh starts the writer next to whytime, outside the traced tree, then
                // becomes sudo.
                let mut cmd = Command::new("sh");
                cmd.args([
                    "-c",
                    r#""$1" write "$2" "$3" 8 100 & exec sudo -n "$4" --json -- "$1" read "$2" "$3" 8"#,
                    "sh",
                ])
                .arg(bin("wt-fifo"))
                .arg(&fifo)
                .arg(&watched)
                .arg(whytime);
                cmd
            },
            Box::new(check_waker),
        ),
        (
            "record-replay",
            {
                let mut cmd = Command::new("sudo");
                cmd.arg("-n").arg(whytime).args(["--json", "--timeline", "--perfetto"]);
                cmd.arg(&perfetto_file).arg("--record").arg(&trace_file);
                cmd.args(["--", &bin("wt-child"), "300"]);
                cmd
            },
            Box::new({
                let (whytime, work) = (whytime.clone(), work.clone());
                let files = (trace_file.clone(), perfetto_file.clone());
                move |out: &Output| check_replay(out, &whytime, (&files.0, &files.1), &work)
            }),
        ),
        (
            "attach-blocked",
            attach_cmd(whytime, &[&bin("wt-sleep"), "30000"], &["--duration", "1s"], None),
            Box::new(check_attach_blocked),
        ),
        (
            "attach-running",
            attach_cmd(whytime, &[&bin("wt-burn"), "30000"], &["--duration", "1s"], None),
            Box::new(check_attach_running),
        ),
        (
            "attach-threads",
            attach_cmd(whytime, &[&bin("wt-futex"), "30000"], &["--duration", "1s"], None),
            Box::new(check_attach_threads),
        ),
        (
            "attach-exit",
            attach_cmd(
                whytime,
                &["sh", "-c", "\"$0\" 1200; exit 3", &bin("wt-sleep")],
                &[],
                None,
            ),
            Box::new(check_attach_exit),
        ),
        (
            "attach-spawn",
            attach_cmd(whytime, &[&bin("wt-attach"), "1500", "800"], &[], None),
            Box::new(check_attach_spawn),
        ),
        (
            "attach-interrupt",
            attach_cmd(whytime, &[&bin("wt-sleep"), "30000"], &[], Some("1")),
            Box::new(check_attach_interrupt),
        ),
        (
            "attach-nopid",
            {
                let mut cmd = Command::new(whytime);
                cmd.args(["--json", "-p", NO_PID]);
                cmd
            },
            Box::new(check_attach_nopid),
        ),
        (
            // A shell looping short wt-fsync runs: seeds (the shell, maybe a child), then
            // fork/exec/exit and fsync records, and file lookups, all inside the window.
            "attach-record",
            attach_cmd(
                whytime,
                &[
                    "sh",
                    "-c",
                    "while :; do \"$0\" \"$1\" 20; done",
                    &bin("wt-fsync"),
                    &fsync_dir,
                ],
                &[
                    "--duration",
                    "1s",
                    "--timeline",
                    "--perfetto",
                    &attach_perfetto.display().to_string(),
                    "--record",
                    &attach_trace.display().to_string(),
                ],
                None,
            ),
            Box::new({
                let (whytime, work) = (whytime.clone(), work.clone());
                let files = (attach_trace.clone(), attach_perfetto.clone());
                move |out: &Output| {
                    check_attach_record(out, &whytime, (&files.0, &files.1), &work)
                }
            }),
        ),
        (
            // wt-dns asks the suite's DNS server for slow.whytime.test from an unconnected UDP
            // socket, then connects to the slow server at the answer; recorded and replayed,
            // with the name in the timeline and the Perfetto file.
            "dns-udp",
            {
                let mut cmd = Command::new("sudo");
                cmd.arg("-n").arg(whytime).args(["--json", "--timeline", "--perfetto"]);
                cmd.arg(&dns_perfetto).arg("--record").arg(&dns_trace);
                cmd.arg("--").arg(bin("wt-dns"));
                cmd.args(["udp", DNS_SERVER, DNS_NAME, &port, "3"]);
                cmd
            },
            Box::new({
                let (whytime, work) = (whytime.clone(), work.clone());
                let files = (dns_trace.clone(), dns_perfetto.clone());
                move |out: &Output| {
                    let named = check_host(out, DNS_NAME, server)?;
                    let subject = format!("{DNS_NAME}:{}", server.port());
                    let shown = check_host_shown(out, &files.1, &subject)?;
                    let replayed = check_replay(out, &whytime, (&files.0, &files.1), &work)?;
                    Ok(format!("{named}; {shown}; {replayed}"))
                }
            }),
        ),
        (
            // The same over TCP: length prefix and message read separately, like glibc.
            "dns-tcp",
            sudo(&[&bin("wt-dns"), "tcp", DNS_SERVER, DNS_NAME, &port, "3"]),
            Box::new(move |out: &Output| check_host(out, DNS_NAME, server)),
        ),
        (
            // glibc's getaddrinfo through nss-resolve asks systemd-resolved over varlink;
            // then wt-tcp connects to the slow server at 127.0.0.1 (skipped, running `true`,
            // where that path does not exist).
            "dns-varlink",
            if varlink_skip.is_some() {
                Command::new("true")
            } else {
                let script = "getent ahostsv4 localhost >/dev/null && exec \"$0\" \"$1\" 3";
                sudo(&["sh", "-c", script, &bin("wt-tcp"), &server_arg])
            },
            Box::new(move |out: &Output| match &varlink_skip {
                Some(reason) => Err(Skip(reason.clone()).into()),
                None => check_host(out, "localhost", server),
            }),
        ),
        (
            "parallelism",
            sudo(&[&bin("wt-threads"), "4", "600"]),
            Box::new(check_parallelism),
        ),
        (
            // Two runs of one program with different arguments, one after the other.
            "same-comm",
            sudo(&["sh", "-c", "\"$0\" 400; \"$0\" 250; exit 0", &bin("wt-burn")]),
            Box::new(check_same_comm),
        ),
        (
            // The hog and the traced burner share one CPU; the burner naps every 5 ms, so
            // its time is many scheduling stretches, each with its own CPU holder.
            "held-by",
            {
                let mut cmd = Command::new("sh");
                cmd.args([
                    "-c",
                    "cpu=$(taskset -cp $$ | sed 's/.*[-,: ]//')\n\
                     taskset -c \"$cpu\" \"$1\" 5000 & h=$!\n\
                     sleep 0.3\n\
                     sudo -n \"$2\" --json -- taskset -c \"$cpu\" \"$3\" 1500 5; s=$?\n\
                     kill \"$h\"; wait \"$h\"\n\
                     exit \"$s\"",
                    "sh",
                ])
                .arg(&hog)
                .arg(whytime)
                .arg(bin("wt-burn"));
                cmd
            },
            Box::new(check_held_by),
        ),
    ];

    let mut failed = 0;
    for (index, (name, mut command, check)) in scenarios.into_iter().enumerate() {
        let n = index + 1;
        let out = run(command.stdin(Stdio::null()))?;
        match check(&out) {
            Ok(summary) => println!("PASS {n} {name}: {summary}"),
            Err(err) if err.downcast_ref::<Skip>().is_some() => println!("SKIP {n} {name}: {err}"),
            Err(err) => {
                failed += 1;
                println!("FAIL {n} {name}: {err:#}");
                println!("---- stderr ----\n{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        std::io::stdout().flush()?;
    }
    // Closing its stdin ends the DNS server; kill it should it linger.
    drop(dns_server.stdin.take());
    let _ = dns_server.kill();
    let _ = dns_server.wait();
    ensure!(failed == 0, "{failed} scenario(s) failed");
    println!("all scenarios passed");
    Ok(())
}

type Check = Box<dyn Fn(&Output) -> anyhow::Result<String>>;

/// Builds the release binaries; returns executable name → path.
fn build() -> anyhow::Result<HashMap<String, PathBuf>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let out = Command::new(cargo)
        .current_dir(root)
        .args([
            "build",
            "--release",
            "--package",
            "whytime",
            "--package",
            "whytime-testbins",
            "--message-format=json-render-diagnostics",
        ])
        .stderr(Stdio::inherit())
        .output()
        .context("running cargo build")?;
    ensure!(out.status.success(), "cargo build failed");
    let mut bins = HashMap::new();
    for line in out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let msg: Value = serde_json::from_slice(line)?;
        if msg["reason"] == "compiler-artifact"
            && let Some(exe) = msg["executable"].as_str()
            && let Some(name) = msg["target"]["name"].as_str()
        {
            bins.insert(name.to_owned(), PathBuf::from(exe));
        }
    }
    for name in [
        "whytime",
        "wt-sleep",
        "wt-burn",
        "wt-fsync",
        "wt-child",
        "wt-futex",
        "wt-tcp",
        "wt-attach",
        "wt-threads",
        "wt-vfork",
        "wt-syscalls",
        "wt-flock",
        "wt-poll",
        "wt-fault",
        "wt-fifo",
        "wt-dns",
    ] {
        ensure!(
            bins.contains_key(name),
            "cargo did not report the {name} binary"
        );
    }
    Ok(bins)
}

fn run(cmd: &mut Command) -> anyhow::Result<Output> {
    cmd.output().with_context(|| format!("running {cmd:?}"))
}

/// `sudo -n whytime --json -- ARGS`.
fn traced(whytime: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n").arg(whytime).args(["--json", "--"]).args(args);
    cmd
}

/// `path` as whytime prints it for the invoking user: a leading `$HOME` becomes `~`.
fn home_relative(path: &Path) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match home.as_deref().and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// A TCP server outside the traced tree: accepts, waits [`SERVER_DELAY`], replies, closes.
fn slow_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding the test server")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                std::thread::sleep(SERVER_DELAY);
                let _ = stream.write_all(b"pong\n");
            });
        }
    });
    Ok(addr)
}

/// Starts `wt-dns serve` on [`DNS_SERVER`] answering [`DNS_NAME`] with 127.0.0.1, outside the
/// traced tree: a copy in `work` with `cap_net_bind_service` (port 53) run as the current
/// user. It exits when its stdin closes.
fn dns_server(wt_dns: &Path, work: &Path) -> anyhow::Result<Child> {
    let dir = work.join("bin");
    std::fs::create_dir_all(&dir)?;
    let copy = dir.join("wt-dns-server");
    // Replace rather than overwrite: the old file may carry capabilities.
    let _ = std::fs::remove_file(&copy);
    std::fs::copy(wt_dns, &copy).with_context(|| format!("copying to {}", copy.display()))?;
    let status = Command::new("sudo")
        .args(["-n", "setcap", "cap_net_bind_service+ep"])
        .arg(&copy)
        .status()?;
    ensure!(status.success(), "setcap on {} failed", copy.display());
    let mut child = Command::new(&copy)
        .args(["serve", DNS_SERVER, &format!("{DNS_NAME}=127.0.0.1")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", copy.display()))?;
    let mut ready = String::new();
    let stdout = child.stdout.take().context("DNS server stdout")?;
    BufReader::new(stdout).read_line(&mut ready)?;
    if ready.trim() != "ready" {
        let _ = child.kill();
        bail!("the DNS server did not start on {DNS_SERVER} (see its error above)");
    }
    Ok(child)
}

/// Why the varlink scenario cannot run here, if it cannot: it needs systemd-resolved,
/// nss-resolve in the `hosts` line of `/etc/nsswitch.conf`, and `getent`.
fn varlink_skip() -> Option<String> {
    if !Path::new(RESOLVED_SOCKET).exists() {
        return Some(format!("{RESOLVED_SOCKET} is absent (systemd-resolved not running)"));
    }
    let nss = std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    let resolve = nss
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("hosts:"))
        .any(|hosts| hosts.split_whitespace().any(|source| source == "resolve"));
    if !resolve {
        return Some("/etc/nsswitch.conf does not send host lookups to nss-resolve".to_owned());
    }
    let getent = Command::new("getent").args(["ahostsv4", "localhost"]).output();
    if !getent.is_ok_and(|out| out.status.success()) {
        return Some("`getent ahostsv4 localhost` fails".to_owned());
    }
    None
}

/// Copies whytime to a non-nosuid directory, grants it the required capabilities and returns
/// the command that runs it as the current (unprivileged) user.
fn setcap_copy(whytime: &Path, work: &Path, sleep: &str) -> anyhow::Result<Command> {
    let dir = work.join("bin");
    std::fs::create_dir_all(&dir)?;
    let copy = dir.join("whytime");
    // Replace rather than overwrite: the old file may carry capabilities.
    let _ = std::fs::remove_file(&copy);
    std::fs::copy(whytime, &copy).with_context(|| format!("copying to {}", copy.display()))?;
    let status = Command::new("sudo")
        .args(["-n", "setcap", "cap_bpf,cap_perfmon+ep"])
        .arg(&copy)
        .status()?;
    ensure!(status.success(), "setcap on {} failed", copy.display());
    let mut cmd = Command::new(copy);
    cmd.args(["--json", "--", sleep, "300"]);
    Ok(cmd)
}

/// An `sh` script that starts `target` in the background, waits [`ATTACH_DELAY`], and runs
/// `sudo -n whytime --json -p PID` with `args` on it. With `interrupt`, it waits until
/// whytime observes: sudo's child (`/proc/PID/task/PID/children`) is `whytime`, has blocked
/// SIGINT for its signalfd and sleeps (`SigBlk`, `State` in `/proc/PID/status`; it blocks
/// SIGINT before the 2 `/proc` scans of seeding, ~0.1 s on a loaded host, and seeding does
/// not sleep, so this is the window start). Then it sends whytime SIGINT that many seconds
/// later and prints `interrupt READY BEFORE AFTER` (`/proc/uptime` when ready, before and
/// after the `kill`; see [`check_attach_interrupt`]). Afterwards it prints `target alive` on
/// stdout if the target still runs (whytime must never stop it), stops it, and exits with
/// whytime's status. Running in the background, whytime inherits SIGINT ignored, as from
/// scripts: a SIGINT before it is ready would be lost.
fn attach_cmd(whytime: &Path, target: &[&str], args: &[&str], interrupt: Option<&str>) -> Command {
    // Single-quoted for sh: a trace file path may contain spaces.
    let args: Vec<String> = args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', r"'\''")))
        .collect();
    let args = args.join(" ");
    let run = match interrupt {
        None => format!("sudo -n \"$w\" --json -p \"$t\" {args}; s=$?"),
        // Without a terminal, sudo runs whytime as its direct child. Builtins only in the
        // poll (no fork per probe); SIGTERM, not ignored, ends a whytime that never got ready.
        Some(after) => format!(
            "sudo -n \"$w\" --json -p \"$t\" {args} & j=$!\n\
             i=0 ready=\n\
             while [ -z \"$ready\" ] && [ $i -lt 500 ]; do\n\
               i=$((i + 1)) p= name= st= mask=\n\
               read -r p _ 2>/dev/null < \"/proc/$j/task/$j/children\"\n\
               if [ -n \"$p\" ]; then\n\
                 while read -r key value _; do\n\
                   case $key in\n\
                     Name:) name=$value ;;\n\
                     State:) st=$value ;;\n\
                     SigBlk:) mask=$value; break ;;\n\
                   esac\n\
                 done 2>/dev/null < \"/proc/$p/status\"\n\
               fi\n\
               if [ \"$name\" = whytime ] && [ \"$st\" = S ] &&\n\
                 [ $((0x${{mask:-0}} & 2)) -ne 0 ]; then ready=1\n\
               else sleep 0.01; fi\n\
             done\n\
             if [ -n \"$ready\" ]; then\n\
               read -r ready _ < /proc/uptime\n\
               sleep {after}\n\
               read -r before _ < /proc/uptime\n\
               sudo -n kill -INT \"$p\"\n\
               read -r after _ < /proc/uptime\n\
               echo \"interrupt $ready $before $after\"\n\
             else sudo -n pkill -TERM -P \"$j\"; fi\n\
             wait \"$j\"; s=$?"
        ),
    };
    let script = format!(
        "w=$1; shift\n\
         \"$@\" & t=$!\n\
         sleep {ATTACH_DELAY}\n\
         {run}\n\
         state=$(sed 's/.*) //' \"/proc/$t/stat\" 2>/dev/null | cut -c1)\n\
         if [ -n \"$state\" ] && [ \"$state\" != Z ]; then echo target alive; kill \"$t\"; fi\n\
         wait \"$t\" 2>/dev/null\n\
         exit \"$s\""
    );
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .arg("sh")
        .arg(whytime)
        .args(target);
    cmd
}

/// The JSON report at the end of stderr.
fn report(out: &Output) -> anyhow::Result<Value> {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let start = stderr
        .rfind("{\n  \"schema\": \"whytime.report/1\"")
        .context("no whytime.report/1 JSON on stderr")?;
    let report: Value = serde_json::from_str(&stderr[start..]).context("parsing the report")?;
    let sum: f64 = lines(&report).iter().map(|l| share(l)).sum();
    ensure!((sum - 1.0).abs() <= 0.001, "shares sum to {sum}");
    let dropped = report["quality"]["dropped"].as_u64();
    ensure!(dropped == Some(0), "quality.dropped = {dropped:?}");
    Ok(report)
}

fn lines(report: &Value) -> Vec<&Value> {
    report["lines"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn share(line: &Value) -> f64 {
    line["share"].as_f64().unwrap_or(0.0)
}

/// Total share of `class` lines whose subject satisfies `subject`.
fn class_share(report: &Value, class: &str, subject: impl Fn(&str) -> bool) -> f64 {
    lines(report)
        .into_iter()
        .filter(|l| l["class"] == class && subject(l["subject"].as_str().unwrap_or("")))
        .map(share)
        .sum()
}

#[allow(clippy::cast_precision_loss)]
fn wall_secs(report: &Value) -> f64 {
    report["wall_ns"].as_u64().unwrap_or(0) as f64 / 1e9
}

fn exited(out: &Output, code: i32) -> anyhow::Result<()> {
    ensure!(
        out.status.code() == Some(code),
        "exit status {} (want {code})",
        out.status
    );
    Ok(())
}

fn check_sleep(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let sleep = class_share(&report, "sleep", |_| true);
    let wall = wall_secs(&report);
    ensure!(sleep >= 0.9, "sleep share {sleep:.3} < 0.9");
    ensure!(
        (0.9..=1.1).contains(&wall),
        "wall {wall:.3}s not within 1.0s ± 10%"
    );
    Ok(format!("wall {wall:.3}s, sleep {:.1}%", sleep * 100.0))
}

fn check_burn(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let cpu = class_share(&report, "cpu", |_| true);
    ensure!(cpu >= 0.9, "on-CPU share {cpu:.3} < 0.9");
    Ok(format!(
        "wall {:.3}s, on-CPU {:.1}%",
        wall_secs(&report),
        cpu * 100.0
    ))
}

fn check_fsync(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let top = lines(&report).first().copied().context("no lines")?;
    let class = top["class"].as_str().unwrap_or("");
    ensure!(
        matches!(class, "fsync" | "file"),
        "top class is {class}, not fsync/file"
    );
    ensure!(share(top) >= 0.5, "top share {:.3} < 0.5", share(top));
    Ok(format!(
        "wall {:.3}s, top {class} on {} {:.1}%",
        wall_secs(&report),
        top["subject"].as_str().unwrap_or("?"),
        share(top) * 100.0
    ))
}

fn check_child(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let child = class_share(&report, "child", |s| s == "wt-burn");
    ensure!(child >= 0.8, "waiting on child wt-burn {child:.3} < 0.8");
    Ok(format!(
        "wall {:.3}s, waiting on child: wt-burn {:.1}%",
        wall_secs(&report),
        child * 100.0
    ))
}

/// The main thread waits on a mutex whose holder sleeps: following the futex waker makes
/// that `sleep`, not `futex`.
fn check_lock_holder(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let sleep = class_share(&report, "sleep", |_| true);
    ensure!(sleep >= 0.8, "sleep share {sleep:.3} < 0.8");
    Ok(format!(
        "wall {:.3}s, holder's sleep {:.1}%",
        wall_secs(&report),
        sleep * 100.0
    ))
}

/// The main thread waits for CPU-bound threads of its own process (joins, or timed condition
/// waits that mostly time out): `cpu`, not `futex`.
fn check_threads_cpu(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let cpu = class_share(&report, "cpu", |s| s == "wt-threads");
    ensure!(cpu >= 0.8, "on-CPU (wt-threads) share {cpu:.3} < 0.8");
    Ok(format!(
        "wall {:.3}s, on-CPU {:.1}%",
        wall_secs(&report),
        cpu * 100.0
    ))
}

/// The parent blocks in `clone` while its `CLONE_VFORK` child computes before exec: `child`
/// (the child still carries the parent's comm), not `other`.
fn check_vfork(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let child = class_share(&report, "child", |s| s == "wt-vfork");
    ensure!(child >= 0.8, "waiting on child wt-vfork {child:.3} < 0.8");
    Ok(format!(
        "wall {:.3}s, waiting on child: wt-vfork (before exec) {:.1}%",
        wall_secs(&report),
        child * 100.0
    ))
}

fn check_tcp(out: &Output, server: SocketAddr) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let peer = server.to_string();
    let net = class_share(&report, "net", |s| s == peer);
    ensure!(net >= 0.6, "net share for {peer} {net:.3} < 0.6");
    Ok(format!(
        "wall {:.3}s, net {peer} {:.1}%",
        wall_secs(&report),
        net * 100.0
    ))
}

/// The `net` line on `server` is named `host:PORT`, with `addr` the numeric `server`, three
/// connections (one per round) and at least 0.6 of the wall time.
fn check_host(out: &Output, host: &str, server: SocketAddr) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let subject = format!("{host}:{}", server.port());
    let line = lines(&report)
        .into_iter()
        .find(|l| l["class"] == "net" && l["subject"] == subject.as_str())
        .with_context(|| format!("no net line {subject}"))?;
    ensure!(share(line) >= 0.6, "net share for {subject} {:.3} < 0.6", share(line));
    let addr = server.to_string();
    ensure!(line["addr"] == addr.as_str(), "addr {} (want {addr})", line["addr"]);
    ensure!(line["connections"] == 3, "{} connections (want 3)", line["connections"]);
    Ok(format!(
        "wall {:.3}s, net {subject} (addr {addr}, 3 connections) {:.1}%",
        wall_secs(&report),
        share(line) * 100.0
    ))
}

/// `--timeline` and `--perfetto` name the peer as the report does: a timeline slice has the
/// `net` line `subject` (`host:port`), and the Perfetto file `perfetto` has `net SUBJECT`
/// slices on the critical path's track and the blocked thread's.
fn check_host_shown(out: &Output, perfetto: &Path, subject: &str) -> anyhow::Result<String> {
    let report = report(out)?;
    let slices = report["timeline"].as_array().context("no timeline")?;
    let in_slices = slices
        .iter()
        .filter(|slice| {
            let mut lines = slice["lines"].as_array().into_iter().flatten();
            lines.any(|l| l["class"] == "net" && l["subject"] == subject)
        })
        .count();
    ensure!(in_slices > 0, "no timeline slice has a net line {subject}");
    let bytes =
        std::fs::read(perfetto).with_context(|| format!("reading {}", perfetto.display()))?;
    let json: Value = serde_json::from_slice(&bytes).context("parsing the Perfetto file")?;
    let name = format!("net {subject}");
    let tracks: HashSet<(u64, u64)> = json["traceEvents"]
        .as_array()
        .context("no traceEvents")?
        .iter()
        .filter(|e| e["ph"] == "X" && e["name"] == name.as_str())
        .filter_map(|e| Some((e["pid"].as_u64()?, e["tid"].as_u64()?)))
        .collect();
    ensure!(
        tracks.len() >= 2,
        "Perfetto slices `{name}` on {} track(s), not the critical path's and the thread's",
        tracks.len()
    );
    Ok(format!(
        "{subject} in {in_slices} timeline slices and on {} Perfetto tracks",
        tracks.len()
    ))
}

fn check_exit_code(out: &Output) -> anyhow::Result<String> {
    exited(out, 7)?;
    report(out)?;
    Ok("exit 7 passed through".to_owned())
}

fn check_nopriv(out: &Output) -> anyhow::Result<String> {
    exited(out, 125)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let line = stderr
        .lines()
        .find(|l| l.contains("setcap "))
        .context("no setcap fix on stderr")?;
    Ok(format!("exit 125, {}", line.trim()))
}

fn check_setcap(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let sleep = class_share(&report, "sleep", |_| true);
    ensure!(sleep >= 0.9, "sleep share {sleep:.3} < 0.9");
    Ok(format!(
        "unprivileged user + file caps: wall {:.3}s, sleep {:.1}%",
        wall_secs(&report),
        sleep * 100.0
    ))
}

/// The `--record --timeline --perfetto P` run reported normally, with a valid timeline and
/// Perfetto file; `whytime report FILE --json --timeline --perfetto P2`, unprivileged, prints
/// the identical report and writes the identical file; the files written under sudo belong to
/// the invoking user; a cut-short copy exits 2.
fn check_replay(
    out: &Output,
    whytime: &Path,
    (trace, perfetto): (&Path, &Path),
    work: &Path,
) -> anyhow::Result<String> {
    use std::os::unix::fs::MetadataExt as _;

    exited(out, 0)?;
    let live = report(out)?;
    let slices = check_timeline(&live)?;
    let tracks = check_perfetto(perfetto, &live)?;
    let replayed_perfetto = perfetto.with_extension("replay.json");
    let replay = run(Command::new(whytime)
        .arg("report")
        .arg(trace)
        .args(["--json", "--timeline", "--perfetto"])
        .arg(&replayed_perfetto))?;
    exited(&replay, 0)?;
    let replayed = report(&replay)?;
    ensure!(
        replayed == live,
        "the replayed report differs from the live one:\nlive: {live}\nreplayed: {replayed}"
    );
    ensure!(
        std::fs::read(perfetto)? == std::fs::read(&replayed_perfetto)?,
        "the replayed Perfetto file differs from the live one"
    );
    let human = run(Command::new(whytime).arg("report").arg(trace))?;
    exited(&human, 0)?;
    ensure!(
        String::from_utf8_lossy(&human.stderr).starts_with("wall "),
        "the human replay does not start with the wall time"
    );
    for file in [trace, perfetto] {
        let owner = std::fs::metadata(file)?.uid();
        ensure!(
            owner == std::fs::metadata(work)?.uid(),
            "{} belongs to uid {owner}, not the invoking user",
            file.display()
        );
    }

    let bytes = std::fs::read(trace).with_context(|| format!("reading {}", trace.display()))?;
    let cut = trace.with_extension("cut.wt");
    std::fs::write(&cut, &bytes[..bytes.len() / 2])?;
    let damaged = run(Command::new(whytime).arg("report").arg(&cut))?;
    exited(&damaged, 2)?;
    let message = String::from_utf8_lossy(&damaged.stderr);
    ensure!(
        message.contains("truncated"),
        "a cut-short trace is not reported as truncated: {message}"
    );
    Ok(format!(
        "{} bytes, {} events, {slices} timeline slices, {tracks} Perfetto tracks: the replayed \
         report and Perfetto file are identical; a cut-short file exits 2",
        bytes.len(),
        live["quality"]["events"]
    ))
}

/// `--timeline`: slices tiling `[0, wall_ns)`, each with lines adding up to its length.
/// Returns the number of slices.
fn check_timeline(report: &Value) -> anyhow::Result<usize> {
    let slices = report["timeline"].as_array().context("no timeline")?;
    ensure!(!slices.is_empty(), "an empty timeline");
    let mut cursor = 0;
    for slice in slices {
        let (Some(start), Some(end)) = (slice["start_ns"].as_u64(), slice["end_ns"].as_u64())
        else {
            bail!("a timeline slice without start_ns/end_ns: {slice}");
        };
        ensure!(
            start == cursor && end > start,
            "timeline slice {start}..{end} does not continue at {cursor}"
        );
        let lines = slice["lines"].as_array().map(Vec::as_slice).unwrap_or_default();
        let sum: u64 = lines.iter().filter_map(|line| line["ns"].as_u64()).sum();
        ensure!(
            sum == end - start,
            "timeline slice {start}..{end}: lines sum to {sum} ns"
        );
        cursor = end;
    }
    let wall = report["wall_ns"].as_u64().unwrap_or(0);
    ensure!(cursor == wall, "the timeline ends at {cursor}, not wall_ns {wall}");
    Ok(slices.len())
}

/// The `--perfetto` file: Chrome Trace Event JSON with a `critical path` track whose slices
/// add up to the window (whole microseconds), and no two slices of a track overlapping.
/// Returns the number of tracks with slices.
fn check_perfetto(path: &Path, report: &Value) -> anyhow::Result<usize> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let json: Value = serde_json::from_slice(&bytes).context("parsing the Perfetto file")?;
    let events = json["traceEvents"].as_array().context("no traceEvents")?;
    let critical = events
        .iter()
        .find(|e| {
            e["ph"] == "M" && e["name"] == "process_name" && e["args"]["name"] == "critical path"
        })
        .and_then(|e| e["pid"].as_u64())
        .context("no critical path track")?;
    let mut tracks: HashMap<(u64, u64), Vec<(u64, u64)>> = HashMap::new();
    for event in events.iter().filter(|e| e["ph"] == "X") {
        let field = |key: &str| event[key].as_u64().with_context(|| format!("{key} in {event}"));
        let track = (field("pid")?, field("tid")?);
        tracks.entry(track).or_default().push((field("ts")?, field("dur")?));
    }
    for ((pid, tid), slices) in &mut tracks {
        slices.sort_unstable();
        for pair in slices.windows(2) {
            ensure!(
                pair[0].0 + pair[0].1 <= pair[1].0,
                "track {pid}/{tid}: slices {pair:?} overlap"
            );
        }
    }
    let path_us: u64 = tracks
        .get(&(critical, critical))
        .map(|slices| slices.iter().map(|&(_, dur)| dur).sum())
        .unwrap_or(0);
    let wall_us = report["wall_ns"].as_u64().unwrap_or(0) / 1_000;
    ensure!(
        path_us == wall_us,
        "the critical path track covers {path_us} µs of the {wall_us} µs window"
    );
    Ok(tracks.len())
}

/// Four threads spin side by side: about four CPUs busy over the window.
fn check_parallelism(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let parallelism = &report["parallelism"];
    let factor = parallelism["factor"].as_f64().unwrap_or(0.0);
    ensure!(factor >= 3.0, "parallelism factor {factor:.2} < 3");
    ensure!(
        parallelism["processes"] == 1,
        "parallelism.processes = {}",
        parallelism["processes"]
    );
    #[allow(clippy::cast_precision_loss)]
    let cpu = parallelism["cpu_ns"].as_u64().unwrap_or(0) as f64 / 1e9;
    Ok(format!(
        "wall {:.3}s, cpu {cpu:.3}s, {factor:.2}× parallel",
        wall_secs(&report)
    ))
}

/// `wt-burn 400` and `wt-burn 250` share a comm: each gets lines of its own, named by its
/// arguments.
fn check_same_comm(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let named = |subject: &str| {
        lines(&report)
            .into_iter()
            .filter(|l| l["subject"] == subject)
            .map(share)
            .sum::<f64>()
    };
    let (long, short) = (named("wt-burn 400"), named("wt-burn 250"));
    ensure!(long >= 0.45, "wt-burn 400 lines {long:.3} < 0.45");
    ensure!(short >= 0.25, "wt-burn 250 lines {short:.3} < 0.25");
    ensure!(named("wt-burn") == 0.0, "a line still names plain wt-burn");
    Ok(format!(
        "wt-burn 400 {:.1}%, wt-burn 250 {:.1}%",
        long * 100.0,
        short * 100.0
    ))
}

/// The burner waited for its CPU behind the untraced hog: runqueue lines whose largest CPU
/// holder is `wt-hog`.
fn check_held_by(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let runqueue = class_share(&report, "runqueue", |_| true);
    ensure!(runqueue >= 0.2, "runqueue share {runqueue:.3} < 0.2");
    let mut held: HashMap<String, u64> = HashMap::new();
    for line in lines(&report).into_iter().filter(|l| l["class"] == "runqueue") {
        for holder in line["held_by"].as_array().into_iter().flatten() {
            let comm = holder["comm"].as_str().unwrap_or_default().to_owned();
            *held.entry(comm).or_default() += holder["ns"].as_u64().unwrap_or(0);
        }
    }
    let total: u64 = held.values().sum();
    let hog = held.get("wt-hog").copied().unwrap_or(0);
    ensure!(
        held.values().all(|&ns| ns <= hog) && hog > 0,
        "wt-hog is not the main CPU holder: {held:?}"
    );
    #[allow(clippy::cast_precision_loss)]
    let hog_share = hog as f64 / total.max(1) as f64;
    Ok(format!(
        "runqueue {:.1}%, {:.1}% of it held by wt-hog",
        runqueue * 100.0,
        hog_share * 100.0
    ))
}

/// The report of an attach scenario that exited 0 and ended by `ended_by`.
fn attached(out: &Output, ended_by: &str) -> anyhow::Result<Value> {
    exited(out, 0)?;
    let report = report(out)?;
    ensure!(report["attached_pid"].is_u64(), "no attached_pid");
    ensure!(
        report["ended_by"] == ended_by,
        "ended_by {} (want {ended_by})",
        report["ended_by"]
    );
    Ok(report)
}

/// Whether the attach script found the target still running after whytime finished.
fn target_alive(out: &Output) -> bool {
    String::from_utf8_lossy(&out.stdout).contains("target alive")
}

fn check_attach_blocked(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "duration")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let sleep = class_share(&report, "sleep", |_| true);
    let wall = wall_secs(&report);
    ensure!(sleep >= 0.9, "sleep share {sleep:.3} < 0.9");
    ensure!(
        (0.9..=1.1).contains(&wall),
        "wall {wall:.3}s not within 1.0s ± 10%"
    );
    Ok(format!(
        "blocked before attach: wall {wall:.3}s, sleep {:.1}%",
        sleep * 100.0
    ))
}

fn check_attach_running(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "duration")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let cpu = class_share(&report, "cpu", |_| true);
    ensure!(cpu >= 0.9, "on-CPU share {cpu:.3} < 0.9");
    Ok(format!(
        "running at attach: wall {:.3}s, on-CPU {:.1}%",
        wall_secs(&report),
        cpu * 100.0
    ))
}

fn check_attach_threads(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "duration")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let futex = class_share(&report, "futex", |_| true);
    ensure!(futex >= 0.9, "futex share {futex:.3} < 0.9");
    Ok(format!(
        "two threads: wall {:.3}s, futex {:.1}%",
        wall_secs(&report),
        futex * 100.0
    ))
}

/// Whether `processes[]` has a `comm` process whose parent is the attached target.
fn has_child(report: &Value, comm: &str) -> bool {
    let target = report["attached_pid"].as_u64();
    report["processes"].as_array().is_some_and(|procs| {
        procs
            .iter()
            .any(|p| p["comm"] == comm && p["ppid"].as_u64() == target)
    })
}

fn check_attach_exit(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "exit")?;
    ensure!(!target_alive(out), "the target outlived its reported exit");
    ensure!(
        report["exit_code"] == 3,
        "exit_code {} (want 3)",
        report["exit_code"]
    );
    ensure!(
        has_child(&report, "wt-sleep"),
        "the pre-existing child wt-sleep is not in processes[]"
    );
    let sleep = class_share(&report, "sleep", |_| true);
    ensure!(sleep >= 0.9, "sleep share {sleep:.3} < 0.9");
    Ok(format!(
        "sh waiting on a pre-existing child: wall {:.3}s, sleep {:.1}%, exit_code 3",
        wall_secs(&report),
        sleep * 100.0
    ))
}

fn check_attach_spawn(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "exit")?;
    ensure!(
        report["exit_code"] == 0,
        "exit_code {} (want 0)",
        report["exit_code"]
    );
    ensure!(
        has_child(&report, "wt-burn"),
        "the child started after attach is not in processes[]"
    );
    let child = class_share(&report, "child", |s| s == "wt-burn");
    ensure!(child >= 0.3, "waiting on child wt-burn {child:.3} < 0.3");
    Ok(format!(
        "child forked after attach: wall {:.3}s, waiting on child: wt-burn {:.1}%",
        wall_secs(&report),
        child * 100.0
    ))
}

/// SIGINT ends the window when it arrives: `wall_ns` spans whytime getting ready to the
/// `kill`, as the script measured them (`interrupt READY BEFORE AFTER`, see [`attach_cmd`]),
/// within [`INTERRUPT_SLACK`].
fn check_attach_interrupt(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "interrupt")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stamps: Vec<f64> = stdout
        .lines()
        .find_map(|l| l.strip_prefix("interrupt "))
        .context("no `interrupt` line on stdout (whytime never got ready)")?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .context("parsing the `interrupt` line")?;
    let [ready, before, after] = stamps[..] else {
        bail!("`interrupt` line has {} timestamps (want 3)", stamps.len());
    };
    let (sent_from, sent_to) = (before - ready, after - ready);
    let (lo, hi) = (sent_from - INTERRUPT_SLACK, sent_to + INTERRUPT_SLACK);
    let sleep = class_share(&report, "sleep", |_| true);
    let wall = wall_secs(&report);
    ensure!(sleep >= 0.9, "sleep share {sleep:.3} < 0.9");
    ensure!(
        (lo..=hi).contains(&wall),
        "wall {wall:.3}s not within {lo:.3}..{hi:.3}s (SIGINT {sent_from:.2}..{sent_to:.2}s \
         after ready ± {INTERRUPT_SLACK}s)"
    );
    Ok(format!(
        "SIGINT {sent_from:.2}..{sent_to:.2}s after ready: wall {wall:.3}s, sleep {:.1}%",
        sleep * 100.0
    ))
}

fn check_attach_nopid(out: &Output) -> anyhow::Result<String> {
    exited(out, 1)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let line = stderr
        .lines()
        .find(|l| l.contains("no process"))
        .context("no \"no process\" message on stderr")?;
    Ok(format!("exit 1, {}", line.trim()))
}

/// `-p PID --record`: the attached report (ended by `--duration`, target alive, records
/// seen), then the same replay checks as `--record` in wrap mode.
fn check_attach_record(
    out: &Output,
    whytime: &Path,
    files: (&Path, &Path),
    work: &Path,
) -> anyhow::Result<String> {
    let live = attached(out, "duration")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let events = live["quality"]["events"].as_u64().unwrap_or(0);
    ensure!(events > 0, "no records in the window: nothing to replay but the seeds");
    check_replay(out, whytime, files, work).map(|summary| format!("attached: {summary}"))
}

fn check_flock(out: &Output, dir: &str) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let unresolved: Vec<&str> = lines(&report)
        .into_iter()
        .filter_map(|l| l["subject"].as_str())
        .filter(|s| s.starts_with("dev "))
        .collect();
    ensure!(unresolved.is_empty(), "unresolved file subjects {unresolved:?}");
    let lock = class_share(&report, "lock", |s| s == dir);
    ensure!(lock >= 0.6, "lock share on {dir} {lock:.3} < 0.6");
    Ok(format!(
        "wall {:.3}s, file lock wait on {dir} {:.1}%",
        wall_secs(&report),
        lock * 100.0
    ))
}

/// Compares the least on-CPU time of `wt-syscalls` over [`OVERHEAD_RUNS`] traced runs
/// (`processes[].cpu_ns` in the report; `out` is the first) with the least over as many
/// untraced ones (rusage), interleaved. CPU time, unlike wall time, ignores waits for a CPU on
/// a loaded machine; whytime's in-kernel work runs in the traced task's context and counts.
fn check_overhead(out: &Output, whytime: &Path, syscalls: &str) -> anyhow::Result<String> {
    let cpu_secs = |out: &Output| -> anyhow::Result<f64> {
        exited(out, 0)?;
        let report = report(out)?;
        let ns = report["processes"]
            .as_array()
            .and_then(|procs| procs.iter().find(|p| p["comm"] == "wt-syscalls"))
            .and_then(|p| p["cpu_ns"].as_u64())
            .context("no wt-syscalls process in the report")?;
        Ok(Duration::from_nanos(ns).as_secs_f64())
    };
    let mut traced_secs = cpu_secs(out)?;
    let mut untraced_secs = f64::INFINITY;
    for round in 0..OVERHEAD_RUNS {
        let before = children_cpu();
        let status = Command::new(syscalls)
            .arg(OVERHEAD_READS)
            .stdin(Stdio::null())
            .status()
            .with_context(|| format!("running {syscalls}"))?;
        ensure!(status.success(), "untraced {syscalls} failed: {status}");
        untraced_secs = untraced_secs.min((children_cpu() - before).as_secs_f64());
        if round + 1 < OVERHEAD_RUNS {
            let again = run(traced(whytime, &[syscalls, OVERHEAD_READS]).stdin(Stdio::null()))?;
            traced_secs = traced_secs.min(cpu_secs(&again)?);
        }
    }
    let ratio = traced_secs / untraced_secs;
    ensure!(
        ratio <= MAX_OVERHEAD,
        "traced/untraced CPU {ratio:.2} > {MAX_OVERHEAD} (traced {traced_secs:.3}s, untraced \
         {untraced_secs:.3}s)"
    );
    Ok(format!(
        "{OVERHEAD_READS} reads: CPU untraced {untraced_secs:.3}s, traced {traced_secs:.3}s, \
         ratio {ratio:.2} (max {MAX_OVERHEAD})"
    ))
}

/// User + system CPU time of this process's reaped children so far.
fn children_cpu() -> Duration {
    // SAFETY: `rusage` is plain data; getrusage fills it and cannot fail for RUSAGE_CHILDREN.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_CHILDREN, &raw mut usage);
        usage
    };
    let time = |t: libc::timeval| {
        Duration::new(
            u64::try_from(t.tv_sec).unwrap_or(0),
            u32::try_from(t.tv_usec).unwrap_or(0) * 1000,
        )
    };
    time(usage.ru_utime) + time(usage.ru_stime)
}

/// poll/epoll waits ended by the slow server are `net` on its address (readiness probes).
fn check_poll(out: &Output, server: SocketAddr) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let peer = server.to_string();
    // Without the readiness probes these waits would be class poll.
    let net = class_share(&report, "net", |s| s == peer);
    ensure!(net >= 0.6, "net share for {peer} {net:.3} < 0.6");
    Ok(format!(
        "wall {:.3}s, epoll_wait/poll ended by {peer}: net {:.1}%",
        wall_secs(&report),
        net * 100.0
    ))
}

/// Page faults on a file whose pages were dropped are `fault` on its directory: nearly all
/// of the time `wt-fault` is blocked (neither `cpu` nor `runqueue`; checks the
/// classification), and a fair part of the wall time (catches fault waits leaking into
/// `cpu` or `runqueue`). The rest of the wall is the faults' own CPU work (~25 µs each
/// traced, next to a ~60 µs NVMe read) and waits for a CPU after each wakeup, which grow
/// with load: fault was 60–75% of the wall at load 10–15 on 22 cores, 29–55% with 3
/// runnable tasks per CPU, while staying 100% of the blocked time.
fn check_fault(out: &Output, dir: &str) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let fault = class_share(&report, "fault", |s| s == dir);
    ensure!(fault >= 0.2, "fault share on {dir} {fault:.3} < 0.2");
    let running =
        class_share(&report, "cpu", |_| true) + class_share(&report, "runqueue", |_| true);
    // At least 0.2 of the shares (summing to 1) are fault, so `1 - running` is too.
    let of_blocked = fault / (1.0 - running);
    ensure!(of_blocked >= 0.9, "fault on {dir} {of_blocked:.3} of the blocked time < 0.9");
    Ok(format!(
        "wall {:.3}s, page faults on {dir} {:.1}% ({:.1}% of blocked time)",
        wall_secs(&report),
        fault * 100.0,
        of_blocked * 100.0
    ))
}

/// inotify polls and FIFO reads ended by a writer outside the tree name it.
fn check_waker(out: &Output) -> anyhow::Result<String> {
    const WOKEN: &str = "woken by wt-fifo-writer";
    exited(out, 0)?;
    let report = report(out)?;
    let poll = class_share(&report, "poll", |s| s == WOKEN);
    ensure!(poll >= 0.35, "poll share {WOKEN:?} {poll:.3} < 0.35");
    let ipc = class_share(&report, "ipc", |s| s == WOKEN);
    ensure!(ipc >= 0.35, "ipc share {WOKEN:?} {ipc:.3} < 0.35");
    Ok(format!(
        "wall {:.3}s, {WOKEN}: poll {:.1}%, fifo read {:.1}%",
        wall_secs(&report),
        poll * 100.0,
        ipc * 100.0
    ))
}
