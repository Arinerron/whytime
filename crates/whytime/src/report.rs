//! The report: JSON schema `whytime.report/1` and the human rendering.

use std::io::{self, Write};

use serde::Serialize;

use crate::attribute::{Attribution, Line};
use crate::classify::Class;
use crate::timeline::Trace;

/// Lines below this share are folded into "other" in the human rendering.
const MIN_SHOWN_SHARE: f64 = 0.01;
/// At most this many lines are shown before "other".
const MAX_SHOWN_LINES: usize = 8;

/// Why the observation window ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EndedBy {
    /// The command exited.
    Exit,
    /// `--duration` elapsed while the command was still running.
    Duration,
    /// SIGINT, SIGTERM or SIGHUP ended an attached observation (`-p`).
    Interrupt,
}

/// The whole report.
#[derive(Debug, Serialize)]
pub struct Report {
    /// [`Report::SCHEMA`].
    pub schema: &'static str,
    /// The command line that was run (attach mode: the target's).
    pub command: Vec<String>,
    /// The running process whytime attached to (`-p`); absent in wrap mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_pid: Option<u32>,
    /// Window length: the command's exec (or the attach) to its exit (or the deadline).
    pub wall_ns: u64,
    /// Why the window ended.
    pub ended_by: EndedBy,
    /// The command's exit code (128 + signal when killed); `null` while it still runs (or,
    /// attached, if it did not exit during the window).
    pub exit_code: Option<i32>,
    /// Where the window went, largest first; shares sum to 1.
    pub lines: Vec<ReportLine>,
    /// Every process of the traced tree, in order of appearance.
    pub processes: Vec<ProcessEntry>,
    /// Measurement quality.
    pub quality: Quality,
    /// Caveats that apply to this report.
    pub notes: Vec<String>,
}

/// One line of the breakdown.
#[derive(Debug, Serialize)]
pub struct ReportLine {
    /// Resource class.
    pub class: Class,
    /// Fraction of `wall_ns`.
    pub share: f64,
    /// Nanoseconds.
    pub ns: u64,
    /// What within the class: a process comm, directory, `ip:port` or syscall.
    pub subject: String,
    /// Distinct sockets, for `net` lines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connections: Option<usize>,
}

/// A process of the traced tree.
#[derive(Debug, Serialize)]
pub struct ProcessEntry {
    /// Process id.
    pub pid: u32,
    /// Parent process id.
    pub ppid: Option<u32>,
    /// Last `comm`.
    pub comm: String,
    /// Leading arguments (capped at 256 bytes in kernel).
    pub argv: Vec<String>,
    /// On-CPU nanoseconds over all its threads.
    pub cpu_ns: u64,
    /// Exit code (128 + signal when killed); `null` while running.
    pub exit_code: Option<i32>,
    /// The attribution walked through it.
    pub critical: bool,
}

/// How complete the underlying data is.
#[derive(Debug, Serialize)]
pub struct Quality {
    /// Ring buffer records received.
    pub events: u64,
    /// Records or tracked tasks lost in kernel (ring buffer or map full).
    pub dropped: u64,
    /// Whether syscall tracepoints were attached (blocks are classified by resource).
    pub syscalls: bool,
}

/// Inputs of [`Report::new`] besides the trace.
#[derive(Debug)]
pub struct Meta {
    /// The command line.
    pub command: Vec<String>,
    /// Window length.
    pub wall_ns: u64,
    /// Why the window ended.
    pub ended_by: EndedBy,
    /// The command's exit code, when known.
    pub exit_code: Option<i32>,
    /// Records or tasks lost in kernel.
    pub dropped: u64,
    /// Syscall tracepoints attached.
    pub syscalls: bool,
    /// Attach mode: the target and how it was seeded.
    pub attached: Option<Attached>,
}

/// Attach-mode inputs of [`Report::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attached {
    /// The target process.
    pub pid: u32,
    /// Threads blocked at attach whose syscall `/proc` would not show.
    pub unreadable: usize,
}

impl Report {
    /// Version of the JSON layout.
    pub const SCHEMA: &'static str = "whytime.report/1";

    /// Assembles the report.
    pub fn new(trace: &Trace, attribution: Attribution, meta: Meta) -> Self {
        let wall = meta.wall_ns.max(1);
        #[allow(clippy::cast_precision_loss)] // shares are presentation values
        let share = |ns: u64| ns as f64 / wall as f64;
        let critical = attribution.critical();
        let lines: Vec<ReportLine> = attribution
            .lines
            .into_iter()
            .map(
                |Line {
                     class,
                     subject,
                     ns,
                     connections,
                 }| ReportLine {
                    class,
                    share: share(ns),
                    ns,
                    subject,
                    connections,
                },
            )
            .collect();
        let processes = trace
            .procs
            .iter()
            .enumerate()
            .map(|(id, proc)| {
                let info = trace.table.get_key(proc.key);
                ProcessEntry {
                    pid: proc.key.pid,
                    ppid: info.and_then(|info| info.ppid),
                    comm: proc.comm().to_string(),
                    argv: info.map_or_else(Vec::new, |info| {
                        info.argv
                            .iter()
                            .map(|arg| arg.to_string_lossy().into_owned())
                            .collect()
                    }),
                    cpu_ns: proc.cpu_ns,
                    exit_code: info
                        .and_then(|info| info.exit)
                        .and_then(|exit| exit.code)
                        .map(exit_code),
                    critical: critical.contains(&id),
                }
            })
            .collect();

        let mut notes = Vec::new();
        if let Some(attached) = meta.attached {
            notes.push(format!(
                "attached to running pid {}: time before attach is not covered, and each \
                 pre-existing thread's first interval is classified from /proc",
                attached.pid
            ));
            if attached.unreadable > 0 {
                notes.push(format!(
                    "{} thread(s) blocked at attach in a syscall /proc would not show (no \
                     ptrace access, e.g. kernel.yama.ptrace_scope); that first interval is \
                     \"other\": run whytime with sudo, or add cap_sys_ptrace to its file \
                     capabilities",
                    attached.unreadable
                ));
            }
        }
        if lines.iter().any(|line| line.class == Class::Net) {
            notes.push(
                "network subjects are ip:port; hostname/DNS correlation is a later milestone"
                    .to_owned(),
            );
        }
        if !meta.syscalls {
            notes.push(
                "syscall tracepoints unavailable: blocked time is not classified by resource"
                    .to_owned(),
            );
        }
        match meta.ended_by {
            EndedBy::Duration => {
                notes.push("--duration elapsed; the command was still running".to_owned());
            }
            EndedBy::Interrupt => notes.push(
                "observation interrupted (SIGINT/SIGTERM/SIGHUP); the process kept running"
                    .to_owned(),
            ),
            EndedBy::Exit => {}
        }
        if meta.dropped > 0 {
            notes.push(format!(
                "{} records lost in kernel; affected time is reported as \"other (untraced)\"",
                meta.dropped
            ));
        }
        Self {
            schema: Self::SCHEMA,
            command: meta.command,
            attached_pid: meta.attached.map(|attached| attached.pid),
            wall_ns: meta.wall_ns,
            ended_by: meta.ended_by,
            exit_code: meta.exit_code,
            lines,
            processes,
            quality: Quality {
                events: trace.records,
                dropped: meta.dropped,
                syscalls: meta.syscalls,
            },
            notes,
        }
    }

    /// Writes the report as pretty-printed JSON and a newline.
    pub fn render_json(&self, w: &mut dyn Write) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut *w, self)?;
        writeln!(w)
    }

    /// Writes the human breakdown.
    pub fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(w, "wall {}", format_duration(self.wall_ns))?;
        let mut other = 0;
        let mut shown = 0;
        for line in &self.lines {
            if line.class == Class::Other
                || line.share < MIN_SHOWN_SHARE
                || shown == MAX_SHOWN_LINES
            {
                other += line.ns;
                continue;
            }
            shown += 1;
            writeln!(w, "{:>5}  {}", percent(line.share), label(line))?;
        }
        if other > 0 {
            #[allow(clippy::cast_precision_loss)]
            let share = other as f64 / self.wall_ns.max(1) as f64;
            writeln!(w, "{:>5}  other", percent(share))?;
        }
        let critical = self.processes.iter().filter(|p| p.critical).count();
        writeln!(
            w,
            "critical path: {critical} process{} · {} events lost",
            if critical == 1 { "" } else { "es" },
            self.quality.dropped
        )?;
        for note in &self.notes {
            writeln!(w, "note: {note}")?;
        }
        Ok(())
    }
}

/// Shell convention: the exit code, or 128 + signal, from a wait status.
pub fn exit_code(status: i32) -> i32 {
    if status.trailing_zeros() >= 7 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    }
}

fn percent(share: f64) -> String {
    if share > 0.0 && share < 0.005 {
        "<1%".to_owned()
    } else {
        format!("{:.0}%", share * 100.0)
    }
}

fn label(line: &ReportLine) -> String {
    let subject = line.subject.as_str();
    // Subjects naming a syscall ("in openat") read as a phrase, not a location.
    let at = |verb: &str| {
        if subject.starts_with("in ") {
            format!("{verb} {subject}")
        } else {
            format!("{verb} on {subject}")
        }
    };
    match line.class {
        Class::Cpu => format!("on-CPU ({subject})"),
        Class::Child => format!("waiting on child: {subject}"),
        Class::Runqueue => format!("waiting for a CPU ({subject})"),
        Class::Sleep => format!("timer sleep ({subject})"),
        Class::Fsync => at("fsync"),
        Class::File => at("file I/O"),
        Class::Aio => format!("async I/O completion ({subject})"),
        Class::Net => match line.connections {
            Some(n) => format!(
                "blocked on network: {subject} ({n} connection{})",
                if n == 1 { "" } else { "s" }
            ),
            None => format!("blocked on network: {subject}"),
        },
        Class::Ipc => format!("IPC wait ({subject})"),
        Class::Futex => format!("lock/futex wait ({subject})"),
        Class::Lock => at("file lock wait"),
        Class::Poll => format!("poll/epoll wait ({subject})"),
        Class::Signal => format!("waiting for a signal ({subject})"),
        Class::Tty => format!("terminal/device I/O ({subject})"),
        Class::Other => format!("other ({subject})"),
    }
}

/// `41.2s`, `1.03s`, `512ms`, `830µs`.
#[allow(clippy::cast_precision_loss)]
fn format_duration(ns: u64) -> String {
    let secs = ns as f64 / 1e9;
    if secs >= 100.0 {
        format!("{secs:.0}s")
    } else if secs >= 10.0 {
        format!("{secs:.1}s")
    } else if secs >= 1.0 {
        format!("{secs:.2}s")
    } else if ns >= 1_000_000 {
        format!("{:.0}ms", secs * 1e3)
    } else {
        format!("{:.0}µs", secs * 1e6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_status_decodes_exit_and_signal() {
        assert_eq!(exit_code(7 << 8), 7);
        assert_eq!(exit_code(9), 137);
    }

    #[test]
    fn durations_keep_three_significant_digits() {
        assert_eq!(format_duration(41_234_000_000), "41.2s");
        assert_eq!(format_duration(1_034_000_000), "1.03s");
        assert_eq!(format_duration(512_300_000), "512ms");
        assert_eq!(format_duration(830_000), "830µs");
    }
}
