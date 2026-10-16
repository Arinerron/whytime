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
/// Seconds the attach scenarios let their target run before whytime attaches.
const ATTACH_DELAY: &str = "0.3";
/// A pid above any `pid_max`, so no process has it.
const NO_PID: &str = "4194304";

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
    let sudo = |args: &[&str]| {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg(whytime).args(["--json", "--"]).args(args);
        cmd
    };

    let fsync_dir = work.display().to_string();
    let server_arg = server.to_string();
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
        "wt-attach",
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
