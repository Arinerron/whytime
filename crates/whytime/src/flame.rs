//! Wall-clock flamegraphs of the critical path (`--flamegraph FILE`, `--folded FILE`).
//!
//! The attribution's spans tile the window, so folding every span into stacks makes the
//! graph's total width the window: each attributed nanosecond is in exactly one stack. A
//! stack is, outermost first: the report line (`on-CPU (xz)`, `fsync on ~/.cache`), the
//! process's comm (and the thread's own name when it differs), then where that thread was:
//!
//! - on-CPU (a `cpu` or `child` span over a mixed segment): the span's time is split evenly
//!   across the thread's samples in the stretch of the segment the span stands for (on-CPU
//!   and preempted time interleave in a segment, so that stretch is the span's share of it);
//!   with none there, the nearest sample of the thread within one sampling period carries it
//!   all, else `[no sample]`;
//! - blocked: the user, then kernel stack captured when the thread blocked (`[no stack]`
//!   when none was: a thread blocked since before an attach);
//! - waiting for a CPU: `[runqueue]`;
//! - `other (untraced)`: nothing below the line.
//!
//! User frames come from [`Symbols`]; kernel frames get the `_[k]` suffix of the
//! FlameGraph/inferno convention. A stack lost in kernel (stack map collision or full) is
//! `[stack lost]`. Folded output is Brendan Gregg's format (`frame;frame;... count`, one
//! line per distinct stack, sorted) with counts in microseconds (rounded; stacks under
//! 0.5 µs are left out), so the counts sum to the wall time; the SVG is inferno's, root
//! frames colored by class.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use anyhow::Context as _;
use inferno::flamegraph::color::{Color, PaletteMap};
use inferno::flamegraph::{self, Options};
use procctx::ProcKey;
use whytime_abi::SAMPLE_HZ;

use crate::attribute::{self, Attribution, Span};
use crate::classify::Class;
use crate::cli::OutputArgs;
use crate::record::create_owned;
use crate::report::{format_duration, line_label};
use crate::stacks::{Symbols, UserKey, stack_id};
use crate::timeline::{Sample, Seg, SegKind, StackIds, Thread, Trace};

/// Farthest a sample may be from an on-CPU stretch that has none and still stand for it:
/// one sampling period.
const NEAREST_NS: u64 = 1_000_000_000 / SAMPLE_HZ as u64;

/// The files `--flamegraph` and `--folded` name: created before the run, so a bad path fails
/// fast (and under sudo they belong to the invoking user), written when the window ends.
#[derive(Debug, Default)]
pub struct Outputs {
    svg: Option<(PathBuf, File)>,
    folded: Option<(PathBuf, File)>,
}

impl Outputs {
    /// Creates (truncates) the files `output` names, handing regular files to `owner`.
    pub fn create(output: &OutputArgs, owner: Option<(u32, u32)>) -> anyhow::Result<Self> {
        let create = |path: &Option<PathBuf>| {
            path.as_ref()
                .map(|path| {
                    create_owned(path, owner)
                        .map(|file| (path.clone(), file))
                        .with_context(|| format!("creating {}", path.display()))
                })
                .transpose()
        };
        Ok(Self {
            svg: create(&output.flamegraph)?,
            folded: create(&output.folded)?,
        })
    }

    /// Folds the window of `trace` ending at `end` (the stacks from `symbols`; `None`: stack
    /// capture was unavailable) and writes the files. Problems are printed now, before the
    /// report, which stays last on stderr. Returns whether every file was written.
    pub fn write(
        self,
        trace: &Trace,
        end: u64,
        command: &[OsString],
        symbols: Option<&Symbols>,
    ) -> bool {
        if self.svg.is_none() && self.folded.is_none() {
            return true;
        }
        let Some(symbols) = symbols else {
            eprintln!("whytime: no flamegraph: stack capture was unavailable (see whytime doctor)");
            return false;
        };
        let (Some(root), Some(start)) = (trace.root, trace.window.start) else {
            eprintln!("whytime: no flamegraph: the command's exec was not observed");
            return false;
        };
        let end = end.max(start);
        let folded = fold(trace, &attribute::attribute(trace, root, start, end), symbols);
        let mut written = true;
        let mut write = |(path, file): (PathBuf, File), what: &dyn Fn(&mut dyn Write) -> io::Result<()>| {
            if let Err(err) = what(&mut BufWriter::new(file)) {
                eprintln!("whytime: writing {}: {err}", path.display());
                written = false;
            }
        };
        if let Some(folded_file) = self.folded {
            write(folded_file, &|w| folded.write_folded(w));
        }
        if let Some(svg) = self.svg {
            let command: Vec<_> = command.iter().map(|arg| arg.to_string_lossy()).collect();
            let title = format!("whytime: {}", command.join(" "));
            let subtitle = format!(
                "wall {}: the critical path, width = wall-clock time",
                format_duration(end - start)
            );
            write(svg, &|w| folded.write_svg(w, &title, &subtitle));
        }
        written
    }
}

/// The critical path as weighted stacks.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Folded {
    /// Nanoseconds per stack (frames joined by `;`, outermost first).
    stacks: BTreeMap<String, u64>,
    /// The class of each root frame (report line).
    roots: BTreeMap<String, Class>,
}

/// Folds the attributed window of `trace` into stacks.
pub fn fold(trace: &Trace, attribution: &Attribution, symbols: &Symbols) -> Folded {
    let connections: HashMap<(Class, &str), Option<usize>> = attribution
        .lines
        .iter()
        .map(|line| ((line.class, line.subject.as_str()), line.connections))
        .collect();
    let mut folder = Folder {
        trace,
        symbols,
        leaves: HashMap::new(),
        folded: Folded::default(),
    };
    for span in &attribution.spans {
        let connections = connections
            .get(&(span.class, span.subject.as_str()))
            .copied()
            .flatten();
        let root = frame(&line_label(span.class, &span.subject, connections));
        folder.folded.roots.insert(root.clone(), span.class);
        folder.span(span, root);
    }
    folder.folded
}

impl Folded {
    /// The lines of the folded format: `stack microseconds`, sorted by stack.
    fn lines(&self) -> impl Iterator<Item = String> {
        self.stacks.iter().filter_map(|(stack, ns)| {
            let us = ns.saturating_add(500) / 1000;
            (us > 0).then(|| format!("{stack} {us}"))
        })
    }

    /// Writes the folded format.
    pub fn write_folded(&self, w: &mut dyn Write) -> io::Result<()> {
        for line in self.lines() {
            writeln!(w, "{line}")?;
        }
        w.flush()
    }

    /// Writes the SVG flamegraph, titled `title`, with `subtitle` under it.
    pub fn write_svg(&self, w: &mut dyn Write, title: &str, subtitle: &str) -> io::Result<()> {
        let lines: Vec<String> = self.lines().collect();
        let mut palette = PaletteMap::default();
        for (root, &class) in &self.roots {
            palette.insert(root, class_color(class));
        }
        let mut options = Options::default();
        title.clone_into(&mut options.title);
        options.subtitle = Some(subtitle.to_owned());
        "µs".clone_into(&mut options.count_name);
        // Colors from function names, so a replay draws the same graph.
        options.hash = true;
        options.palette_map = Some(&mut palette);
        flamegraph::from_lines(&mut options, lines.iter().map(String::as_str), &mut *w)?;
        w.flush()
    }
}

/// Root frame colors: on-CPU warm, waiting for a CPU yellow, sleeping grey, storage blue,
/// network green, waits on other tasks (locks, IPC, poll, signals, terminals) purple.
fn class_color(class: Class) -> Color {
    let (r, g, b) = match class {
        Class::Cpu | Class::Child => (229, 96, 48),
        Class::Runqueue => (230, 196, 64),
        Class::Sleep => (168, 168, 168),
        Class::Fsync | Class::File | Class::Aio | Class::Fault => (86, 136, 220),
        Class::Net => (64, 170, 96),
        Class::Ipc | Class::Futex | Class::Lock | Class::Poll | Class::Signal | Class::Tty => {
            (164, 112, 212)
        }
        Class::Other => (204, 204, 204),
    };
    Color { r, g, b }
}

/// A frame name safe in the folded format: `;` separates frames and a line holds one stack.
fn frame(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            ';' => ':',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

struct Folder<'a> {
    trace: &'a Trace,
    symbols: &'a Symbols,
    /// Rendered frames below the thread, by process and stack references.
    leaves: HashMap<(ProcKey, StackIds), String>,
    folded: Folded,
}

impl Folder<'_> {
    /// Adds `span`, whose report line is the frame `root`.
    fn span(&mut self, span: &Span, root: String) {
        let len = span.end - span.start;
        if span.class == Class::Other && span.subject == "untraced" {
            self.add(&root, "", len);
            return;
        }
        let trace = self.trace;
        let thread = &trace.threads[span.thread];
        let proc = &trace.procs[span.proc];
        let comm = proc.comm_at(span.start);
        let mut prefix = format!("{root};{}", frame(comm));
        if let Some(name) = thread.name_at(span.start)
            && name != comm
        {
            prefix.push(';');
            prefix.push_str(&frame(name));
        }
        let mut cursor = span.start;
        let first = thread.segs.partition_point(|seg| seg.end <= span.start);
        for seg in &thread.segs[first..] {
            if seg.start >= span.end {
                break;
            }
            let (from, to) = (seg.start.max(span.start), seg.end.min(span.end));
            if from >= to {
                continue;
            }
            // Spans never cover time without a segment (that is `untraced`); kept whole.
            self.add(&prefix, "", from - cursor);
            match &seg.kind {
                SegKind::Blocked(block) => {
                    let leaf = self.leaf(proc.key, block.stacks);
                    self.add(&prefix, &leaf, to - from);
                }
                SegKind::Mixed { run, rq } if span.class != Class::Runqueue => {
                    self.on_cpu(&prefix, proc.key, thread, seg, (from, to), (*run, *rq));
                }
                SegKind::Mixed { .. } | SegKind::Runq => self.add(&prefix, "[runqueue]", to - from),
            }
            cursor = to;
        }
        self.add(&prefix, "", span.end - cursor);
    }

    /// Adds on-CPU time `[from, to)` of `thread`'s mixed segment `seg` (`run`, `rq` its
    /// on-CPU and preempted nanoseconds) under `prefix`.
    fn on_cpu(
        &mut self,
        prefix: &str,
        proc: ProcKey,
        thread: &Thread,
        seg: &Seg,
        (from, to): (u64, u64),
        (run, rq): (u64, u64),
    ) {
        let ns = to - from;
        // The span took `run / (run + rq)` of a stretch of the segment starting at `from`.
        let end = if run == 0 || rq == 0 {
            to
        } else {
            let stretch = u128::from(ns) * u128::from(run + rq) / u128::from(run);
            from.saturating_add(u64::try_from(stretch).unwrap_or(u64::MAX))
                .min(seg.end)
                .max(to)
        };
        let samples = &thread.samples;
        let lo = samples.partition_point(|s| s.ts < from);
        let hi = samples.partition_point(|s| s.ts < end);
        if lo == hi {
            let leaf = match nearest(samples, lo, from, end) {
                Some(sample) => self.leaf(proc, sample.stacks),
                None => "[no sample]".to_owned(),
            };
            self.add(prefix, &leaf, ns);
            return;
        }
        let count = u64::try_from(hi - lo).unwrap_or(u64::MAX);
        for (i, sample) in (0..).zip(&samples[lo..hi]) {
            // Even shares; the remainder goes one nanosecond each to the first samples.
            let share = ns / count + u64::from(i < ns % count);
            let leaf = self.leaf(proc, sample.stacks);
            self.add(prefix, &leaf, share);
        }
    }

    /// The frames below the thread for stacks `ids` of process `proc`.
    fn leaf(&mut self, proc: ProcKey, ids: StackIds) -> String {
        if let Some(leaf) = self.leaves.get(&(proc, ids)) {
            return leaf.clone();
        }
        let mut frames: Vec<String> = Vec::new();
        match ids.user {
            0 if ids.kernel == 0 => frames.push("[no stack]".to_owned()),
            0 => {}
            user if user == -libc::EFAULT => {}
            _ => match UserKey::of(proc, ids).and_then(|key| self.symbols.user.get(&key)) {
                Some(user) => frames.extend(user.iter().map(|name| frame(name))),
                None => frames.push("[stack lost]".to_owned()),
            },
        }
        match ids.kernel {
            0 => {}
            kernel if kernel == -libc::EFAULT => {}
            _ => match stack_id(ids.kernel).and_then(|id| self.symbols.kernel.get(&id)) {
                Some(kernel) => frames.extend(kernel.iter().map(|name| frame(name) + "_[k]")),
                None => frames.push("[stack lost]_[k]".to_owned()),
            },
        }
        let leaf = frames.join(";");
        self.leaves.insert((proc, ids), leaf.clone());
        leaf
    }

    /// Adds `ns` to the stack `prefix;leaf` (`prefix` alone when `leaf` is empty).
    fn add(&mut self, prefix: &str, leaf: &str, ns: u64) {
        if ns == 0 {
            return;
        }
        let stack = if leaf.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix};{leaf}")
        };
        *self.folded.stacks.entry(stack).or_default() += ns;
    }
}

/// The sample nearest to `[from, end)` (which holds none; `at` is where one would be
/// inserted) within [`NEAREST_NS`].
fn nearest(samples: &[Sample], at: usize, from: u64, end: u64) -> Option<Sample> {
    let before = at
        .checked_sub(1)
        .map(|i| samples[i])
        .map(|s| (from - s.ts, s));
    let after = samples.get(at).map(|&s| (s.ts - end, s));
    [before, after]
        .into_iter()
        .flatten()
        .filter(|&(distance, _)| distance <= NEAREST_NS)
        .min_by_key(|&(distance, _)| distance)
        .map(|(_, sample)| sample)
}

#[cfg(test)]
mod tests {
    use libc::SYS_nanosleep;

    use super::*;
    use crate::testkit::{episode, exec, exit, feed, sample, seg, sys, trace};

    /// Symbols for process 100 (procctx start 100, as testkit's exec gives it): user stacks
    /// 0.. from `user`, kernel stacks from `kernel` (`(id, frames)`).
    fn symbols(user: &[&[&str]], kernel: &[(u32, &[&str])]) -> Symbols {
        let proc = ProcKey {
            pid: 100,
            start: 100,
        };
        let names = |frames: &[&str]| frames.iter().map(|&f| f.to_owned()).collect();
        Symbols {
            user: (0..)
                .zip(user)
                .map(|(id, frames)| (UserKey { proc, image: 0, id }, names(frames)))
                .collect(),
            kernel: kernel.iter().map(|&(id, frames)| (id, names(frames))).collect(),
        }
    }

    /// Folds `[0, end)` of `trace` (root process 100).
    fn folded(trace: &Trace, end: u64, symbols: &Symbols) -> Vec<(String, u64)> {
        let attribution = attribute::attribute(trace, trace.root.expect("root"), 0, end);
        let folded = fold(trace, &attribution, symbols);
        assert_eq!(folded.stacks.values().sum::<u64>(), end, "the stacks tile the window");
        folded.stacks.into_iter().collect()
    }

    #[test]
    fn on_cpu_time_is_split_across_the_samples_of_the_segment_it_stands_for() {
        let mut t = trace(100);
        feed(&mut t, &exec(0, 100, 100, "app", seg(0, 0, 0)));
        // On-CPU 600 and preempted 400 in [0, 1000): the on-CPU span is [0, 600), but the
        // samples spread over the whole segment, all three on-CPU.
        feed(&mut t, &sample(100, 100, 100, [1, 0]));
        feed(&mut t, &sample(300, 100, 100, [1, 0]));
        feed(&mut t, &sample(700, 100, 100, [2, 0]));
        let mut nap = episode(100, 100, seg(0, 600, 400), sys(SYS_nanosleep), [1_000, 1_900, 2_000]);
        (nap.user_stack, nap.kernel_stack) = (3, 4);
        feed(&mut t, &nap);
        // No sample in the last stretch: the nearest one (700) stands for it.
        feed(&mut t, &exit(2_500, 100, 100, seg(2_000, 500, 0), 0, true));
        let symbols = symbols(
            &[&["main", "hot"], &["main", "warm"], &["main", "nap"]],
            &[(3, &["do_nanosleep"])],
        );
        assert_eq!(
            folded(&t, 2_500, &symbols),
            [
                ("on-CPU (app);app;main;hot".to_owned(), 400),
                ("on-CPU (app);app;main;warm".to_owned(), 200 + 500),
                ("timer sleep (app);app;main;nap;do_nanosleep_[k]".to_owned(), 900),
                ("waiting for a CPU (app);app;[runqueue]".to_owned(), 400 + 100),
            ]
        );
    }

    #[test]
    fn missing_samples_lost_stacks_and_untraced_time_are_named() {
        let mut t = trace(100);
        feed(&mut t, &exec(0, 100, 100, "app", seg(0, 0, 0)));
        // The thread names itself "worker"; both its stacks were lost in kernel.
        let mut lost = sample(100, 100, 100, [-libc::EEXIST, -libc::ENOMEM]);
        lost.comm[..6].copy_from_slice(b"worker");
        feed(&mut t, &lost);
        let nap = episode(100, 100, seg(0, 1_000, 0), sys(SYS_nanosleep), [1_000, 10_000_000, 10_000_000]);
        feed(&mut t, &nap);
        // 10 ms on-CPU, farther than a sampling period from any sample.
        feed(&mut t, &exit(20_000_000, 100, 100, seg(10_000_000, 10_000_000, 0), 0, true));
        assert_eq!(
            folded(&t, 20_000_500, &Symbols::default()),
            [
                ("on-CPU (app);app;worker;[no sample]".to_owned(), 10_000_000),
                ("on-CPU (app);app;worker;[stack lost];[stack lost]_[k]".to_owned(), 1_000),
                ("other (untraced)".to_owned(), 500),
                ("timer sleep (app);app;worker;[no stack]".to_owned(), 9_999_000),
            ]
        );
    }

    #[test]
    fn folded_counts_are_rounded_microseconds_without_empty_lines() {
        let mut folded = Folded::default();
        for (stack, ns) in [("a;b", 1_499), ("a;c", 1_500), ("a;d", 499)] {
            folded.stacks.insert(stack.to_owned(), ns);
        }
        let mut out = Vec::new();
        folded.write_folded(&mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "a;b 1\na;c 2\n");
        assert_eq!(frame("f;g\nh"), "f:g h");
    }
}
