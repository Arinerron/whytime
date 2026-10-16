//! Build and test automation for whytime.
//!
//! `cargo xtask test-e2e` builds the release binaries, then runs each scenario under
//! `sudo -n` with `--json` and asserts on the report. Every report must have shares summing to
//! 1 ± 0.001 and no lost records.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use serde_json::Value;

const USAGE: &str = "usage: cargo xtask test-e2e";
/// Delay of the scenario-6 server between accept and reply.
const SERVER_DELAY: Duration = Duration::from_millis(300);
/// One-byte reads `wt-syscalls` does in the overhead scenario.
const OVERHEAD_READS: &str = "2000000";
/// Runs of each side (traced, untraced) in the overhead scenario; the fastest counts.
const OVERHEAD_RUNS: usize = 5;
/// Highest accepted traced/untraced on-CPU time ratio of `wt-syscalls`: measured 1.4–1.8
/// under parallel load (describing every syscall at `sys_enter`, as before, measured 2.2).
const MAX_OVERHEAD: f64 = 2.5;

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("test-e2e") => test_e2e(),
        _ => bail!("{USAGE}"),
    }
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
            "futex",
            sudo(&[&bin("wt-futex"), "800"]),
            Box::new(check_futex),
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
            "flock-path",
            sudo(&[&bin("wt-flock"), &lock_arg, "600"]),
            Box::new(move |out: &Output| check_flock(out, &lock_subject)),
        ),
        (
            "overhead",
            sudo(&[&syscalls, OVERHEAD_READS]),
            Box::new(move |out: &Output| check_overhead(out, &overhead_whytime, &syscalls)),
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
        "wt-syscalls",
        "wt-flock",
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

fn check_futex(out: &Output) -> anyhow::Result<String> {
    exited(out, 0)?;
    let report = report(out)?;
    let futex = class_share(&report, "futex", |_| true);
    ensure!(futex >= 0.5, "futex share {futex:.3} < 0.5");
    Ok(format!(
        "wall {:.3}s, futex {:.1}%",
        wall_secs(&report),
        futex * 100.0
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
