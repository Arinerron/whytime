//! The report: JSON schema `whytime.report/1` and the human rendering.

use std::collections::HashMap;
use std::io::{self, Write};

use serde::Serialize;

use crate::attribute::{Attribution, Held, Line, Span};
use crate::classify::Class;
use crate::timeline::{SegKind, Trace};

/// Lines below this share are folded into the final "other" line of the human rendering.
const MIN_SHOWN_SHARE: f64 = 0.01;
/// At most this many lines are shown before the folded "other" line.
const MAX_SHOWN_LINES: usize = 8;
/// Equal slices of the window in `--timeline`.
const TIMELINE_SLICES: u64 = 10;
/// Lines shown per slice in the human timeline.
const TIMELINE_SHOWN: usize = 3;

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
    /// CPU time of the whole tree within the window.
    pub parallelism: Parallelism,
    /// Where the window went, largest first; shares sum to 1.
    pub lines: Vec<ReportLine>,
    /// With `--timeline`: the window in equal slices.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<Vec<Slice>>,
    /// Every process of the traced tree, in order of appearance.
    pub processes: Vec<ProcessEntry>,
    /// Measurement quality.
    pub quality: Quality,
    /// Caveats that apply to this report.
    pub notes: Vec<String>,
}

/// On-CPU time of every traced thread within the window, against its length.
#[derive(Debug, Serialize)]
pub struct Parallelism {
    /// On-CPU nanoseconds (mixed segments clipped to the window proportionally).
    pub cpu_ns: u64,
    /// Processes with on-CPU time in the window.
    pub processes: usize,
    /// `cpu_ns / wall_ns`: CPUs busy on average.
    pub factor: f64,
}

/// One equal slice of the window, from the critical path.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Slice {
    /// Start, nanoseconds after the window start.
    pub start_ns: u64,
    /// End (exclusive), nanoseconds after the window start.
    pub end_ns: u64,
    /// The critical path within the slice by class and subject, largest first; their `ns`
    /// sum to its length.
    pub lines: Vec<SliceLine>,
}

/// Time of one report line within a [`Slice`].
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct SliceLine {
    /// Resource class.
    pub class: Class,
    /// As in [`ReportLine::subject`].
    pub subject: String,
    /// Nanoseconds within the slice.
    pub ns: u64,
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
    /// `runqueue` lines: who held the CPU meanwhile, largest first (time without a recorded
    /// holder is in none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub held_by: Option<Vec<Held>>,
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
    /// Whether the poll/epoll readiness probes were attached (poll waits are classified by
    /// the descriptor that became ready).
    pub readiness: bool,
    /// Whether the page-fault probes were attached (blocks in page faults are `fault`).
    pub faults: bool,
}

/// Inputs of [`Report::new`] besides the trace.
#[derive(Debug)]
pub struct Meta {
    /// The command line.
    pub command: Vec<String>,
    /// Why the window ended.
    pub ended_by: EndedBy,
    /// The command's exit code, when known.
    pub exit_code: Option<i32>,
    /// Records or tasks lost in kernel.
    pub dropped: u64,
    /// Syscall tracepoints attached.
    pub syscalls: bool,
    /// Readiness probes attached.
    pub readiness: bool,
    /// Page-fault probes attached.
    pub faults: bool,
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

    /// Assembles the report of the window `[start, end)`; with `timeline`, its slices too.
    pub fn new(
        trace: &Trace,
        attribution: Attribution,
        (start, end): (u64, u64),
        meta: Meta,
        timeline: bool,
    ) -> Self {
        let wall_ns = end - start;
        let wall = wall_ns.max(1);
        #[allow(clippy::cast_precision_loss)] // shares are presentation values
        let share = |ns: u64| ns as f64 / wall as f64;
        let critical = attribution.critical();
        let timeline = timeline.then(|| slices(&attribution.spans, start, end));
        let lines: Vec<ReportLine> = attribution
            .lines
            .into_iter()
            .map(
                |Line {
                     class,
                     subject,
                     ns,
                     connections,
                     held_by,
                 }| ReportLine {
                    class,
                    share: share(ns),
                    ns,
                    subject,
                    connections,
                    held_by: (class == Class::Runqueue).then_some(held_by),
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
        if !meta.readiness {
            notes.push(
                "poll/epoll readiness probes unavailable: poll waits are not attributed to the \
                 descriptor that became ready"
                    .to_owned(),
            );
        }
        if !meta.faults {
            notes.push(
                "page-fault probes unavailable: time blocked in page faults is not reported as \
                 \"fault\""
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
            wall_ns,
            ended_by: meta.ended_by,
            exit_code: meta.exit_code,
            parallelism: parallelism(trace, start, end),
            lines,
            timeline,
            processes,
            quality: Quality {
                events: trace.records,
                dropped: meta.dropped,
                syscalls: meta.syscalls,
                readiness: meta.readiness,
                faults: meta.faults,
            },
            notes,
        }
    }

    /// Writes the report as pretty-printed JSON and a newline.
    pub fn render_json(&self, w: &mut dyn Write) -> io::Result<()> {
        serde_json::to_writer_pretty(&mut *w, self)?;
        writeln!(w)
    }

    /// Writes the human breakdown: lines of at least [`MIN_SHOWN_SHARE`] (at most
    /// [`MAX_SHOWN_LINES`] of them, `other`-class lines included), then the rest folded into
    /// one `other` line, then the timeline if there is one.
    pub fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        writeln!(w, "wall {}", format_duration(self.wall_ns))?;
        let Parallelism {
            cpu_ns,
            processes,
            factor,
        } = self.parallelism;
        // Mostly waiting (factor below 1) still shows how little ran.
        let digits = if factor < 1.0 { 2 } else { 1 };
        writeln!(
            w,
            "cpu {} across {processes} process{} · {factor:.digits$}× parallel",
            format_duration(cpu_ns),
            if processes == 1 { "" } else { "es" },
        )?;
        let mut rest = 0;
        let mut shown = 0;
        for line in &self.lines {
            if line.share < MIN_SHOWN_SHARE || shown == MAX_SHOWN_LINES {
                rest += line.ns;
                continue;
            }
            shown += 1;
            writeln!(w, "{:>5}  {}", percent(line.share), label(line))?;
        }
        if rest > 0 {
            #[allow(clippy::cast_precision_loss)]
            let share = rest as f64 / self.wall_ns.max(1) as f64;
            writeln!(w, "{:>5}  other", percent(share))?;
        }
        if let Some(slices) = &self.timeline {
            render_timeline(w, slices, self.wall_ns)?;
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
        Class::Runqueue => match line.held_by.as_deref() {
            // One holder took at least half of it.
            Some([top, ..]) if top.ns.saturating_mul(2) >= line.ns => {
                #[allow(clippy::cast_precision_loss)]
                let share = top.ns as f64 / line.ns.max(1) as f64;
                format!(
                    "waiting for a CPU ({subject}) — mostly {} {}",
                    top.comm,
                    percent(share)
                )
            }
            _ => format!("waiting for a CPU ({subject})"),
        },
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
        Class::Fault => at("page faults"),
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

/// On-CPU time of every traced thread within `[start, end)`.
fn parallelism(trace: &Trace, start: u64, end: u64) -> Parallelism {
    let mut per_proc = vec![0_u64; trace.procs.len()];
    for thread in &trace.threads {
        let segs = &thread.segs;
        for seg in &segs[segs.partition_point(|s| s.end <= start)..] {
            if seg.start >= end {
                break;
            }
            let SegKind::Mixed { run, .. } = seg.kind else {
                continue;
            };
            let (lo, hi) = (seg.start.max(start), seg.end.min(end));
            // Proportionally, as the attribution clips mixed segments.
            let part = u128::from(hi - lo) * u128::from(run) / u128::from(seg.end - seg.start);
            per_proc[thread.proc] += u64::try_from(part).unwrap_or(run).min(run);
        }
    }
    let cpu_ns: u64 = per_proc.iter().sum();
    #[allow(clippy::cast_precision_loss)]
    let factor = cpu_ns as f64 / (end - start).max(1) as f64;
    Parallelism {
        cpu_ns,
        processes: per_proc.iter().filter(|&&ns| ns > 0).count(),
        factor,
    }
}

/// `[start, end)` in [`TIMELINE_SLICES`] equal slices (none shorter than a nanosecond), each
/// with the time `spans` spend in it by class and subject.
fn slices(spans: &[Span], start: u64, end: u64) -> Vec<Slice> {
    let wall = u128::from(end - start);
    let slices = u128::from(TIMELINE_SLICES);
    let mut out = Vec::new();
    let mut first = 0;
    for i in 0..slices {
        let offset = |i: u128| u64::try_from(wall * i / slices).unwrap_or(u64::MAX);
        let (lo, hi) = (start + offset(i), start + offset(i + 1));
        if lo >= hi {
            continue;
        }
        let mut totals: HashMap<(Class, &str), u64> = HashMap::new();
        first += spans[first..].partition_point(|span| span.end <= lo);
        for span in spans[first..].iter().take_while(|span| span.start < hi) {
            *totals.entry((span.class, &span.subject)).or_default() +=
                span.end.min(hi) - span.start.max(lo);
        }
        let mut lines: Vec<SliceLine> = totals
            .into_iter()
            .map(|((class, subject), ns)| SliceLine {
                class,
                subject: subject.to_owned(),
                ns,
            })
            .collect();
        lines.sort_by(|a, b| {
            b.ns.cmp(&a.ns)
                .then_with(|| (a.class, &a.subject).cmp(&(b.class, &b.subject)))
        });
        out.push(Slice {
            start_ns: lo - start,
            end_ns: hi - start,
            lines,
        });
    }
    out
}

/// The human timeline: a row per slice, its time range and its largest lines (at most
/// [`TIMELINE_SHOWN`], each at least [`MIN_SHOWN_SHARE`] of the slice).
fn render_timeline(w: &mut dyn Write, slices: &[Slice], wall_ns: u64) -> io::Result<()> {
    let Some(first) = slices.first() else {
        return Ok(());
    };
    writeln!(w, "timeline ({} slices):", format_duration(first.end_ns))?;
    let ranges: Vec<String> = slices
        .iter()
        .map(|slice| range(slice.start_ns, slice.end_ns, wall_ns))
        .collect();
    let width = ranges.iter().map(|r| r.chars().count()).max().unwrap_or(0);
    for (slice, range) in slices.iter().zip(&ranges) {
        let len = slice.end_ns - slice.start_ns;
        #[allow(clippy::cast_precision_loss)]
        let shown: Vec<String> = slice
            .lines
            .iter()
            .map(|line| (line, line.ns as f64 / len as f64))
            .filter(|&(_, share)| share >= MIN_SHOWN_SHARE)
            .take(TIMELINE_SHOWN)
            .map(|(line, share)| {
                let name = line.class.name();
                match line.subject.as_str() {
                    "" => format!("{name} {}", percent(share)),
                    subject => format!("{name} {subject} {}", percent(share)),
                }
            })
            .collect();
        let pad = width - range.chars().count();
        writeln!(w, "  {}{range}  {}", " ".repeat(pad), shown.join(" · "))?;
    }
    Ok(())
}

/// `[lo, hi)` (offsets into the window) in a unit that suits a window of `wall_ns`.
#[allow(clippy::cast_precision_loss)]
fn range(lo: u64, hi: u64, wall_ns: u64) -> String {
    let (lo, hi) = (lo as f64, hi as f64);
    match wall_ns {
        10_000_000_000.. => format!("{:.1}–{:.1}s", lo / 1e9, hi / 1e9),
        1_000_000_000.. => format!("{:.2}–{:.2}s", lo / 1e9, hi / 1e9),
        10_000_000.. => format!("{:.0}–{:.0}ms", lo / 1e6, hi / 1e6),
        1_000_000.. => format!("{:.1}–{:.1}ms", lo / 1e6, hi / 1e6),
        _ => format!("{:.0}–{:.0}µs", lo / 1e3, hi / 1e3),
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

    /// A report of `lines` `(class, subject, ns)`, wall time their sum.
    fn report(lines: &[(Class, &str, u64)]) -> Report {
        let wall_ns = lines.iter().map(|&(.., ns)| ns).sum::<u64>();
        #[allow(clippy::cast_precision_loss)]
        let lines = lines
            .iter()
            .map(|&(class, subject, ns)| ReportLine {
                class,
                share: ns as f64 / wall_ns as f64,
                ns,
                subject: subject.to_owned(),
                connections: None,
                held_by: None,
            })
            .collect();
        Report {
            schema: Report::SCHEMA,
            command: vec!["cmd".to_owned()],
            attached_pid: None,
            wall_ns,
            ended_by: EndedBy::Exit,
            exit_code: Some(0),
            parallelism: Parallelism {
                cpu_ns: 0,
                processes: 0,
                factor: 0.0,
            },
            lines,
            timeline: None,
            processes: Vec::new(),
            quality: Quality {
                events: 0,
                dropped: 0,
                syscalls: true,
                readiness: true,
                faults: true,
            },
            notes: Vec::new(),
        }
    }

    /// The human rendering between the parallelism line and the critical-path line.
    fn breakdown(report: &Report) -> Vec<String> {
        let mut out = Vec::new();
        report.render_human(&mut out).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .skip(2)
            .take_while(|line| !line.starts_with("critical path"))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn large_other_lines_show_individually_and_only_small_lines_fold() {
        let report = report(&[
            (Class::Cpu, "make", 700),
            (Class::Other, "outside syscalls (page faults, kernel locks)", 230),
            (Class::Fault, "/usr/lib", 60),
            (Class::Sleep, "make", 6),
            (Class::Other, "untraced", 4),
        ]);
        assert_eq!(
            breakdown(&report),
            [
                "  70%  on-CPU (make)",
                "  23%  other (outside syscalls (page faults, kernel locks))",
                "   6%  page faults on /usr/lib",
                "   1%  other",
            ]
        );
    }

    #[test]
    fn lines_beyond_the_shown_maximum_fold_into_other() {
        let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
        let lines: Vec<_> = names
            .into_iter()
            .zip(0..)
            .map(|(name, i)| (Class::Other, name, 100 - i))
            .collect();
        let shown = breakdown(&report(&lines));
        assert_eq!(shown.len(), MAX_SHOWN_LINES + 1);
        assert_eq!(shown[MAX_SHOWN_LINES - 1], "  10%  other (h)");
        // i and j: 92 + 91 of 955.
        assert_eq!(shown[MAX_SHOWN_LINES], "  19%  other");
    }

    #[test]
    fn a_runqueue_line_names_its_cpu_holder_only_when_one_took_at_least_half() {
        let held = |pairs: &[(&str, u64)]| {
            let held_by = pairs.iter().map(|&(comm, ns)| Held {
                comm: comm.to_owned(),
                tgid: 9,
                ns,
            });
            Some(held_by.collect())
        };
        let mut report = report(&[(Class::Runqueue, "make", 100), (Class::Runqueue, "cc1", 100)]);
        report.lines[0].held_by = held(&[("chrome", 61), ("make", 30)]);
        report.lines[1].held_by = held(&[("chrome", 49), ("make", 40)]);
        assert_eq!(
            breakdown(&report),
            [
                "  50%  waiting for a CPU (make) — mostly chrome 61%",
                "  50%  waiting for a CPU (cc1)",
            ]
        );
    }

    /// A critical-path span of `class` and `subject` over `[start, end)`.
    fn span(start: u64, end: u64, class: Class, subject: &str) -> Span {
        Span {
            start,
            end,
            class,
            subject: subject.to_owned(),
            proc: 0,
            thread: 0,
            depth: 0,
            holder: None,
        }
    }

    #[test]
    fn timeline_slices_tile_the_window_and_split_spans_at_their_edges() {
        // 1003 ns in 10 slices: lengths 100 and 101, every nanosecond in exactly one.
        let spans = [
            span(1_000, 1_250, Class::Cpu, "make"),
            span(1_250, 1_900, Class::Child, "cc1"),
            span(1_900, 2_003, Class::Sleep, "make"),
        ];
        let slices = slices(&spans, 1_000, 2_003);
        assert_eq!(slices.len(), 10);
        let mut cursor = 0;
        for slice in &slices {
            assert_eq!(slice.start_ns, cursor);
            assert!((100..=101).contains(&(slice.end_ns - slice.start_ns)));
            let sum: u64 = slice.lines.iter().map(|line| line.ns).sum();
            assert_eq!(sum, slice.end_ns - slice.start_ns, "{slice:?}");
            cursor = slice.end_ns;
        }
        assert_eq!(cursor, 1_003);
        // [200, 300): make's CPU until 250, then cc1, largest first on a tie by class.
        let third: Vec<_> = slices[2]
            .lines
            .iter()
            .map(|line| (line.class, line.subject.as_str(), line.ns))
            .collect();
        assert_eq!(third, [(Class::Cpu, "make", 50), (Class::Child, "cc1", 50)]);
        assert_eq!(slices[9].lines.len(), 1);
        assert_eq!(slices[9].lines[0].class, Class::Sleep);

        // The same at millisecond scale, rendered: a row per slice, largest lines first.
        let ms = 1_000_000;
        let spans = [
            span(0, 250 * ms, Class::Cpu, "make"),
            span(250 * ms, 900 * ms, Class::Child, "cc1"),
            span(900 * ms, 1_000 * ms, Class::Sleep, "make"),
        ];
        let lines = [(Class::Child, "cc1", 650 * ms), (Class::Cpu, "make", 350 * ms)];
        let mut report = report(&lines);
        report.timeline = Some(super::slices(&spans, 0, 1_000 * ms));
        let rows = breakdown(&report);
        assert_eq!(rows[2], "timeline (100ms slices):");
        assert_eq!(rows[3], "  0.00–0.10s  cpu make 100%");
        assert_eq!(rows[5], "  0.20–0.30s  cpu make 50% · child cc1 50%");
        assert_eq!(rows[12], "  0.90–1.00s  sleep make 100%");
    }
}
