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

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use clap::CommandFactory as _;
use serde_json::Value;

const USAGE: &str = "usage: cargo xtask test-e2e | cargo xtask man [DIR]";
/// Delay of the scenario-6 server between accept and reply.
const SERVER_DELAY: Duration = Duration::from_millis(300);
/// Seconds the attach scenarios let their target run before whytime attaches.
const ATTACH_DELAY: &str = "0.3";
/// A pid above any `pid_max`, so no process has it.
const NO_PID: &str = "4194304";
/// One-byte reads `wt-syscalls` does in the overhead scenario.
const OVERHEAD_READS: &str = "2000000";
/// Runs of each side (traced, untraced) in the overhead scenario; the fastest counts.
const OVERHEAD_RUNS: usize = 5;
/// Highest accepted traced/untraced on-CPU time ratio of `wt-syscalls`: measured 1.4–1.8
/// under parallel load (describing every syscall at `sys_enter`, as before, measured 2.2).
const MAX_OVERHEAD: f64 = 2.5;

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
    // wt-fault touch drops the file's cached pages itself; it only needs a synced file.
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
    // Flamegraph files, fresh per run so a stale one cannot pass.
    let flame = work.join("flame");
    let _ = std::fs::remove_dir_all(&flame);
    std::fs::create_dir_all(&flame).with_context(|| format!("creating {}", flame.display()))?;
    let in_flame = |name: &str| flame.join(name);
    let path = |name: &str| in_flame(name).display().to_string();
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
                cmd.arg("-n").arg(whytime).args(["--json", "--record"]);
                cmd.arg(&trace_file).args(["--", &bin("wt-child"), "300"]);
                cmd
            },
            Box::new({
                let (whytime, trace, work) = (whytime.clone(), trace_file.clone(), work.clone());
                move |out: &Output| check_replay(out, &whytime, &trace, &work)
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
                &["--duration", "1s", "--record", &attach_trace.display().to_string()],
                None,
            ),
            Box::new({
                let (whytime, trace, work) = (whytime.clone(), attach_trace.clone(), work.clone());
                move |out: &Output| check_attach_record(out, &whytime, &trace, &work)
            }),
        ),
        (
            "flamegraph",
            traced_with(
                whytime,
                &["--folded", &path("burn.folded"), "--flamegraph", &path("burn.svg")],
                &[&bin("wt-flame"), "600", "400"],
            ),
            Box::new({
                let (folded, svg) = (in_flame("burn.folded"), in_flame("burn.svg"));
                let work = work.clone();
                move |out: &Output| check_flamegraph(out, &folded, &svg, &work)
            }),
        ),
        (
            "flame-kernel",
            traced_with(
                whytime,
                &["--folded", &path("fsync.folded")],
                &[&bin("wt-fsync"), &fsync_dir, "50"],
            ),
            Box::new({
                let folded = in_flame("fsync.folded");
                move |out: &Output| check_flame_kernel(out, &folded)
            }),
        ),
        (
            "flame-replay",
            traced_with(
                whytime,
                &["--record", &path("flame.wt"), "--folded", &path("live.folded")],
                &[&bin("wt-flame"), "300", "200"],
            ),
            Box::new({
                let (whytime, dir, plain) = (whytime.clone(), flame.clone(), trace_file.clone());
                move |out: &Output| check_flame_replay(out, &whytime, &dir, &plain)
            }),
        ),
        (
            "attach-flame",
            attach_cmd(
                whytime,
                &[&bin("wt-flame"), "30000", "0"],
                &["--duration", "1s", "--folded", &path("attach.folded")],
                None,
            ),
            Box::new({
                let folded = in_flame("attach.folded");
                move |out: &Output| check_attach_flame(out, &folded)
            }),
        ),
    ];

    let mut failed = 0;
    for (index, (name, mut command, check)) in scenarios.into_iter().enumerate() {
        let n = index + 1;
        let out = run(command.stdin(Stdio::null()))?;
        match check(&out) {
            Ok(summary) => println!("PASS {n} {name}: {summary}"),
            Err(err) => {
                failed += 1;
                println!("FAIL {n} {name}: {err:#}");
                println!("---- stderr ----\n{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        std::io::stdout().flush()?;
    }
    ensure!(failed == 0, "{failed} scenario(s) failed");
    println!("all scenarios passed");
    Ok(())
}

type Check = Box<dyn Fn(&Output) -> anyhow::Result<String>>;

/// Builds the release `whytime` and the testbins; returns executable name → path. The
/// testbins get frame pointers and keep their symbols (profile `e2e`), so flamegraph checks
/// can unwind and name their functions; RUSTFLAGS apply to the whole build, so they build in
/// a target directory of their own, leaving `whytime` as shipped.
fn build() -> anyhow::Result<HashMap<String, PathBuf>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let mut bins = cargo_build(root, &["--release", "--package", "whytime"], None)?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| root.join("target"), PathBuf::from)
        .join("e2e-testbins");
    let mut testbins = vec!["--profile", "e2e", "--package", "whytime-testbins", "--target-dir"];
    let target = target.to_str().context("target directory is not UTF-8")?;
    testbins.push(target);
    bins.extend(cargo_build(root, &testbins, Some("-C force-frame-pointers=yes"))?);
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
        "wt-flame",
    ] {
        ensure!(
            bins.contains_key(name),
            "cargo did not report the {name} binary"
        );
    }
    Ok(bins)
}

/// `cargo build ARGS` in `root` (with `rustflags` as RUSTFLAGS); returns the executables
/// cargo reports.
fn cargo_build(
    root: &Path,
    args: &[&str],
    rustflags: Option<&str>,
) -> anyhow::Result<HashMap<String, PathBuf>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root)
        .arg("build")
        .args(args)
        .arg("--message-format=json-render-diagnostics")
        .stderr(Stdio::inherit());
    if let Some(flags) = rustflags {
        cmd.env("RUSTFLAGS", flags).env_remove("CARGO_ENCODED_RUSTFLAGS");
    }
    let out = cmd.output().context("running cargo build")?;
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
    Ok(bins)
}

fn run(cmd: &mut Command) -> anyhow::Result<Output> {
    cmd.output().with_context(|| format!("running {cmd:?}"))
}

/// `sudo -n whytime --json -- ARGS`.
fn traced(whytime: &Path, args: &[&str]) -> Command {
    traced_with(whytime, &[], args)
}

/// `sudo -n whytime --json FLAGS -- ARGS`.
fn traced_with(whytime: &Path, flags: &[&str], args: &[&str]) -> Command {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n")
        .arg(whytime)
        .arg("--json")
        .args(flags)
        .arg("--")
        .args(args);
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
/// `sudo -n whytime --json -p PID` with `args` on it; with `interrupt`, it sends whytime
/// SIGINT that many seconds later. Afterwards it prints `target alive` on stdout if the
/// target still runs (whytime must never stop it), stops it, and exits with whytime's
/// status. Running in the background, whytime inherits SIGINT ignored, as from scripts.
fn attach_cmd(whytime: &Path, target: &[&str], args: &[&str], interrupt: Option<&str>) -> Command {
    // Single-quoted for sh: a trace file path may contain spaces.
    let args: Vec<String> = args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', r"'\''")))
        .collect();
    let args = args.join(" ");
    let run = match interrupt {
        None => format!("sudo -n \"$w\" --json -p \"$t\" {args}; s=$?"),
        // Without a terminal, sudo runs whytime as its direct child.
        Some(after) => format!(
            "sudo -n \"$w\" --json -p \"$t\" {args} & j=$!\n\
             sleep {after}\n\
             sudo -n pkill -INT -P \"$j\"\n\
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
         wait \"$t\"\n\
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

/// The `--record` run reported normally; `whytime report FILE --json`, unprivileged, prints the
/// identical report; the file belongs to the invoking user; a cut-short copy exits 2.
fn check_replay(
    out: &Output,
    whytime: &Path,
    trace: &Path,
    work: &Path,
) -> anyhow::Result<String> {
    use std::os::unix::fs::MetadataExt as _;

    exited(out, 0)?;
    let live = report(out)?;
    let replay = run(Command::new(whytime).arg("report").arg(trace).arg("--json"))?;
    exited(&replay, 0)?;
    let replayed = report(&replay)?;
    ensure!(
        replayed == live,
        "the replayed report differs from the live one:\nlive: {live}\nreplayed: {replayed}"
    );
    let human = run(Command::new(whytime).arg("report").arg(trace))?;
    exited(&human, 0)?;
    ensure!(
        String::from_utf8_lossy(&human.stderr).starts_with("wall "),
        "the human replay does not start with the wall time"
    );
    let owner = std::fs::metadata(trace)?.uid();
    ensure!(
        owner == std::fs::metadata(work)?.uid(),
        "the trace file belongs to uid {owner}, not the invoking user"
    );

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
        "{} bytes, {} events: the replayed report is identical; a cut-short file exits 2",
        bytes.len(),
        live["quality"]["events"]
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

fn check_attach_interrupt(out: &Output) -> anyhow::Result<String> {
    let report = attached(out, "interrupt")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let sleep = class_share(&report, "sleep", |_| true);
    let wall = wall_secs(&report);
    ensure!(sleep >= 0.9, "sleep share {sleep:.3} < 0.9");
    ensure!((0.1..=1.0).contains(&wall), "wall {wall:.3}s not within 0.1..1s");
    Ok(format!(
        "SIGINT after 1s: wall {wall:.3}s, sleep {:.1}%",
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
    trace: &Path,
    work: &Path,
) -> anyhow::Result<String> {
    let live = attached(out, "duration")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let events = live["quality"]["events"].as_u64().unwrap_or(0);
    ensure!(events > 0, "no records in the window: nothing to replay but the seeds");
    check_replay(out, whytime, trace, work).map(|summary| format!("attached: {summary}"))
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

/// Page faults on a file whose pages were dropped are `fault` on its directory.
fn check_fault(out: &Output, dir: &str) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let fault = class_share(&report, "fault", |s| s == dir);
    ensure!(fault >= 0.5, "fault share on {dir} {fault:.3} < 0.5");
    Ok(format!(
        "wall {:.3}s, page faults on {dir} {:.1}%",
        wall_secs(&report),
        fault * 100.0
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

/// The stacks of a folded file: frames and microseconds per line.
fn folded(path: &Path) -> anyhow::Result<Vec<(Vec<String>, u64)>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.lines()
        .map(|line| {
            let (stack, count) = line.rsplit_once(' ').context("a folded line without count")?;
            let count = count.parse().context("a folded count")?;
            Ok((stack.split(';').map(str::to_owned).collect(), count))
        })
        .collect()
}

/// Microseconds of the stacks with a frame satisfying `frame`.
fn stacks_us(stacks: &[(Vec<String>, u64)], frame: impl Fn(&str) -> bool) -> u64 {
    stacks
        .iter()
        .filter(|(frames, _)| frames.iter().any(|f| frame(f)))
        .map(|(_, us)| us)
        .sum()
}

/// `--folded`/`--flamegraph` on `wt-flame 600 400`: the folded stacks add up to the wall
/// time, the ones through `burn_cpu_here` and `sleep_here` to the report's `cpu` and `sleep`
/// lines (within 5% of wall); the SVG names them; both files belong to the invoking user.
#[allow(clippy::cast_precision_loss)]
fn check_flamegraph(out: &Output, folded_path: &Path, svg: &Path, work: &Path) -> anyhow::Result<String> {
    use std::os::unix::fs::MetadataExt as _;

    exited(out, 0)?;
    let report = report(out)?;
    let wall_us = report["wall_ns"].as_u64().unwrap_or(0) as f64 / 1e3;
    let stacks = folded(folded_path)?;
    let total = stacks_us(&stacks, |_| true) as f64;
    ensure!(
        (total - wall_us).abs() <= wall_us * 0.01,
        "the folded stacks sum to {total:.0} µs, the wall time is {wall_us:.0} µs"
    );
    let mut summary = Vec::new();
    for (function, class) in [("burn_cpu_here", "cpu"), ("sleep_here", "sleep")] {
        let us = stacks_us(&stacks, |f| f.ends_with(function)) as f64;
        let line = class_share(&report, class, |_| true) * wall_us;
        ensure!(
            (us - line).abs() <= wall_us * 0.05,
            "stacks through {function}: {us:.0} µs, but the {class} line is {line:.0} µs"
        );
        summary.push(format!(
            "{function} {:.1}% ({class} line {:.1}%)",
            us / wall_us * 100.0,
            line / wall_us * 100.0
        ));
    }
    let drawn = std::fs::read_to_string(svg).with_context(|| format!("reading {}", svg.display()))?;
    ensure!(
        drawn.starts_with("<?xml") && drawn.contains("burn_cpu_here"),
        "{} is not an SVG flamegraph with burn_cpu_here",
        svg.display()
    );
    let owner = std::fs::metadata(work)?.uid();
    for file in [folded_path, svg] {
        ensure!(
            std::fs::metadata(file)?.uid() == owner,
            "{} does not belong to the invoking user",
            file.display()
        );
    }
    Ok(format!(
        "wall {:.3}s, folded total {:.1}%: {}",
        wall_us / 1e6,
        total / wall_us * 100.0,
        summary.join(", ")
    ))
}

/// `--folded` on `wt-fsync`: some stack has a kernel frame (`_[k]`) naming fsync, unless the
/// kernel hides its addresses even from root (then skipped, saying so).
fn check_flame_kernel(out: &Output, folded_path: &Path) -> anyhow::Result<String> {
    exited(out, 0)?;
    report(out)?;
    let head = run(Command::new("sudo").args(["-n", "head", "-n1", "/proc/kallsyms"]))?;
    let address = String::from_utf8_lossy(&head.stdout)
        .split_ascii_whitespace()
        .next()
        .and_then(|address| u64::from_str_radix(address, 16).ok());
    if address.is_none_or(|address| address == 0) {
        return Ok("skipped: /proc/kallsyms hides kernel addresses even from root".to_owned());
    }
    let stacks = folded(folded_path)?;
    let kernel_fsync = |f: &str| f.ends_with("_[k]") && f.contains("fsync");
    let us = stacks_us(&stacks, kernel_fsync);
    ensure!(us > 0, "no stack has a kernel frame naming fsync");
    let frames: Vec<&str> = stacks
        .iter()
        .flat_map(|(frames, _)| frames.iter().map(String::as_str))
        .filter(|f| kernel_fsync(f))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(format!("{us} µs under kernel frames {}", frames.join(", ")))
}

/// `--record F --folded A`, then unprivileged `whytime report F --folded B --flamegraph S`:
/// B is A byte for byte, S is drawn; a trace recorded without stacks (`plain`) exits 2.
fn check_flame_replay(out: &Output, whytime: &Path, dir: &Path, plain: &Path) -> anyhow::Result<String> {
    exited(out, 0)?;
    report(out)?;
    let live = std::fs::read(dir.join("live.folded")).context("reading the live folded stacks")?;
    ensure!(!live.is_empty(), "the live folded stacks are empty");
    let replay = run(Command::new(whytime)
        .arg("report")
        .arg(dir.join("flame.wt"))
        .arg("--folded")
        .arg(dir.join("replay.folded"))
        .arg("--flamegraph")
        .arg(dir.join("replay.svg")))?;
    exited(&replay, 0)?;
    let replayed =
        std::fs::read(dir.join("replay.folded")).context("reading the replayed folded stacks")?;
    ensure!(replayed == live, "the replayed folded stacks differ from the live ones");
    let drawn = std::fs::read_to_string(dir.join("replay.svg"))?;
    ensure!(drawn.contains("burn_cpu_here"), "the replayed SVG lacks burn_cpu_here");
    let without = run(Command::new(whytime)
        .arg("report")
        .arg(plain)
        .arg("--folded")
        .arg(dir.join("none.folded")))?;
    exited(&without, 2)?;
    ensure!(
        String::from_utf8_lossy(&without.stderr).contains("recorded without stack capture"),
        "replaying a trace without stacks into --folded does not say why it fails"
    );
    Ok(format!(
        "{} folded lines replayed byte for byte; a trace without stacks exits 2",
        live.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count()
    ))
}

/// `-p PID --folded` on a spinning `wt-flame`: the stacks are mostly `burn_cpu_here`.
#[allow(clippy::cast_precision_loss)]
fn check_attach_flame(out: &Output, folded_path: &Path) -> anyhow::Result<String> {
    attached(out, "duration")?;
    ensure!(target_alive(out), "the target did not survive whytime");
    let stacks = folded(folded_path)?;
    let total = stacks_us(&stacks, |_| true) as f64;
    let burn = stacks_us(&stacks, |f| f.ends_with("burn_cpu_here")) as f64;
    ensure!(
        burn >= total * 0.8,
        "burn_cpu_here stacks {burn:.0} µs of {total:.0} µs (< 80%)"
    );
    Ok(format!(
        "running at attach: burn_cpu_here {:.1}% of {:.3}s of stacks",
        burn / total * 100.0,
        total / 1e6
    ))
}
