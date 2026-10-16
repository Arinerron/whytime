//! Replays the recorded traces in `tests/fixtures` (`cargo xtask record-fixtures` writes
//! them) with the built `whytime report` and compares its output byte for byte with the
//! expected files next to each trace: `NAME.report.json` (stderr of `whytime report
//! NAME.wt --json --timeline`), and where present `NAME.folded` (`--folded`) and
//! `NAME.perfetto.json` (`--perfetto`). Every report must also hold on its own: shares
//! summing to 1 ± 0.001, some lines, no records dropped.
//!
//! `WHYTIME_BLESS=1 cargo test --test fixtures` rewrites the expected files from the current
//! replay (after an intended output change; review the diff). A trace this build cannot
//! replay (record layout or trace format changed) fails, asking to re-record: blessing
//! cannot fix that.
//!
//! The traces were recorded on x86_64, whose syscall numbers they carry: other targets would
//! refuse them, so the test is built for x86_64 only. Replay needs no privileges.
#![cfg(target_arch = "x86_64")]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Set to `1` to rewrite the expected files instead of comparing.
const BLESS: &str = "WHYTIME_BLESS";
/// What to do when the fixtures cannot be replayed at all.
const RERECORD: &str = "run cargo xtask record-fixtures";
/// Trace file magic (`record.rs`).
const MAGIC: &[u8] = b"WHYTRACE";
/// Byte offset of the ABI hash in the trace preamble: magic, version `u32`, zero `u32`.
const ABI_AT: usize = 16;
/// Lines of each side a mismatch shows.
const DIFF_LINES: usize = 12;
/// Characters of a line a mismatch shows (Perfetto files are one long line).
const DIFF_WIDTH: usize = 160;

/// The replayed outputs of a fixture, by expected file suffix, and the `whytime report`
/// flag that writes each (`None`: stderr).
const OUTPUTS: [(&str, Option<&str>); 3] = [
    ("report.json", None),
    ("folded", Some("--folded")),
    ("perfetto.json", Some("--perfetto")),
];

#[test]
fn fixtures_replay_to_their_expected_outputs() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let bless = std::env::var_os(BLESS).is_some_and(|value| value == "1");
    let mut traces: Vec<PathBuf> = files(&dir)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "wt"))
        .collect();
    traces.sort();
    assert!(!traces.is_empty(), "no traces in {}: {RERECORD}", dir.display());
    let names: Vec<String> = traces.iter().map(|trace| stem(trace)).collect();

    let mut failures = Vec::new();
    for path in files(&dir) {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let known = names.iter().any(|stem| {
            name == format!("{stem}.wt")
                || OUTPUTS.iter().any(|(suffix, _)| name == format!("{stem}.{suffix}"))
        });
        if !known {
            failures.push(format!("{name}: not a trace or an output of one; remove it"));
        }
    }
    for trace in &traces {
        if let Err(failure) = check(trace, bless) {
            failures.push(failure);
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} fixtures failed:\n\n{}",
        failures.len(),
        traces.len(),
        failures.join("\n\n")
    );
}

/// The regular files in `dir`, dotfiles (`.gitattributes`) aside.
fn files(dir: &Path) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("reading {}: {err}; {RERECORD}", dir.display()));
    entries
        .map(|entry| entry.expect("reading a fixture directory entry").path())
        .filter(|path| path.is_file() && !stem(path).is_empty())
        .collect()
}

/// A fixture file's name up to its first dot.
fn stem(path: &Path) -> String {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    name.split('.').next().unwrap_or_default().to_owned()
}

/// Replays `trace`, checks the report's invariants and compares (or with `bless`, rewrites)
/// its expected outputs; the failure, if any.
fn check(trace: &Path, bless: bool) -> Result<(), String> {
    let name = stem(trace);
    let dir = trace.parent().expect("a fixture directory");
    let bytes = std::fs::read(trace).map_err(|err| format!("{name}.wt: {err}"))?;
    abi(&name, &bytes)?;

    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fixtures");
    std::fs::create_dir_all(&scratch).map_err(|err| format!("{}: {err}", scratch.display()))?;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_whytime"));
    cmd.arg("report").arg(trace).args(["--json", "--timeline"]);
    let mut outputs = Vec::new();
    for (suffix, flag) in OUTPUTS {
        let expected = dir.join(format!("{name}.{suffix}"));
        match flag {
            None => outputs.push((expected, None)),
            Some(flag) if expected.exists() => {
                let written = scratch.join(format!("{name}.{suffix}"));
                // A stale file must not pass for the replay's output.
                let _ = std::fs::remove_file(&written);
                cmd.arg(flag).arg(&written);
                outputs.push((expected, Some(written)));
            }
            Some(_) => {}
        }
    }
    let out = cmd
        .output()
        .map_err(|err| format!("{name}: running whytime report: {err}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!(
            "{name}: `whytime report {name}.wt` failed ({}); if the trace format or the \
             records changed, {RERECORD}:\n{stderr}",
            out.status
        ));
    }
    invariants(&stderr).map_err(|err| format!("{name}: {err}\n{stderr}"))?;

    let mut failures = Vec::new();
    for (expected, written) in outputs {
        let actual = match &written {
            None => out.stderr.clone(),
            Some(path) => std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))?,
        };
        let file = expected.file_name().unwrap_or_default().to_string_lossy().into_owned();
        if bless {
            std::fs::write(&expected, &actual).map_err(|err| format!("{file}: {err}"))?;
            continue;
        }
        match std::fs::read(&expected) {
            Ok(wanted) if wanted == actual => {}
            Ok(wanted) => failures.push(format!(
                "{file}: the replay differs ({BLESS}=1 rewrites it if intended)\n{}",
                diff(&wanted, &actual)
            )),
            Err(err) => failures.push(format!("{file}: {err}; {RERECORD}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

/// Fails unless `bytes` is a trace recorded with this build's record layouts: an older
/// fixture must be recorded again, never skipped.
fn abi(name: &str, bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(MAGIC) {
        return Err(format!("{name}.wt: not a whytime trace file; {RERECORD}"));
    }
    let hash = bytes
        .get(ABI_AT..ABI_AT + 8)
        .and_then(|hash| hash.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| format!("{name}.wt: truncated preamble; {RERECORD}"))?;
    if hash != whytime_bpf::ABI_HASH {
        return Err(format!(
            "{name}.wt: recorded with wire ABI {hash:#018x}, but this build uses {:#018x} (the \
             record layout changed): {RERECORD}",
            whytime_bpf::ABI_HASH
        ));
    }
    Ok(())
}

/// The `whytime.report/1` JSON on its own: shares summing to 1 ± 0.001, at least one line,
/// no records dropped.
fn invariants(stderr: &str) -> Result<(), String> {
    let report: serde_json::Value =
        serde_json::from_str(stderr).map_err(|err| format!("stderr is not the JSON report: {err}"))?;
    if report["schema"] != "whytime.report/1" {
        return Err(format!("schema {}", report["schema"]));
    }
    let lines = report["lines"].as_array().map(Vec::as_slice).unwrap_or_default();
    if lines.is_empty() {
        return Err("no lines".to_owned());
    }
    let sum: f64 = lines.iter().filter_map(|line| line["share"].as_f64()).sum();
    if (sum - 1.0).abs() > 0.001 {
        return Err(format!("shares sum to {sum}"));
    }
    let dropped = report["quality"]["dropped"].as_u64();
    if dropped != Some(0) {
        return Err(format!("quality.dropped = {dropped:?}"));
    }
    Ok(())
}

/// The first difference between `expected` and `actual` as a unified-style hunk: up to 2 lines
/// of context, then up to [`DIFF_LINES`] lines of each side, each cut to [`DIFF_WIDTH`]
/// characters around the first differing column.
fn diff(expected: &[u8], actual: &[u8]) -> String {
    let expected = String::from_utf8_lossy(expected);
    let actual = String::from_utf8_lossy(actual);
    let old: Vec<&str> = expected.split_inclusive('\n').collect();
    let new: Vec<&str> = actual.split_inclusive('\n').collect();
    let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
    let suffix = old[prefix..]
        .iter()
        .rev()
        .zip(new[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let (removed, added) = (&old[prefix..old.len() - suffix], &new[prefix..new.len() - suffix]);
    // The column where the first changed lines part, so long lines show the change.
    let column = match (removed.first(), added.first()) {
        (Some(a), Some(b)) => a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count(),
        _ => 0,
    };
    let from = prefix.saturating_sub(2);
    let mut out = format!(
        "@@ -{},{} +{},{} @@ (expected -, replayed +)\n",
        prefix + 1,
        removed.len(),
        prefix + 1,
        added.len()
    );
    for line in &old[from..prefix] {
        let _ = writeln!(out, " {}", cut(line, 0));
    }
    for (sign, lines) in [('-', removed), ('+', added)] {
        for line in lines.iter().take(DIFF_LINES) {
            let _ = writeln!(out, "{sign}{}", cut(line, column));
        }
        if lines.len() > DIFF_LINES {
            let _ = writeln!(out, "{sign}... {} more lines", lines.len() - DIFF_LINES);
        }
    }
    out
}

/// `line` without its newline, cut to [`DIFF_WIDTH`] characters from a little before
/// `column`, with `...` where it was cut.
fn cut(line: &str, column: usize) -> String {
    let line = line.trim_end_matches('\n');
    let chars: Vec<char> = line.chars().collect();
    if chars.len() <= DIFF_WIDTH {
        return line.to_owned();
    }
    let start = column.saturating_sub(DIFF_WIDTH / 4).min(chars.len() - DIFF_WIDTH);
    let end = start + DIFF_WIDTH;
    let mut shown = String::new();
    if start > 0 {
        shown.push_str("...");
    }
    shown.extend(&chars[start..end]);
    if end < chars.len() {
        shown.push_str("...");
    }
    shown
}
