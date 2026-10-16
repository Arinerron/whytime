//! `--perfetto FILE`: the observation window as a Chrome Trace Event JSON file, which
//! ui.perfetto.dev and chrome://tracing open.
//!
//! Every traced thread is a track (pid and tid as the kernel numbered them; a process or
//! thread whose id an earlier one in the trace already had gets a synthetic id above
//! `pid_max`) with a complete slice for each on-CPU (mixed), runqueue and blocked segment,
//! named by class and subject, and process-scoped instants for fork, exec and exit. A
//! synthetic `critical path` process holds the attribution's spans on one track. Times are
//! whole microseconds from the window start: each slice runs from the microsecond its start
//! falls in to the one its end falls in, so slices on a track never overlap, the critical
//! path's add up to the window, and stretches shorter than that are left out.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};

use serde::{Serialize, Serializer};

use crate::attribute::Attribution;
use crate::classify::{Class, Subject};
use crate::report::exit_code;
use crate::timeline::{Holder, Proc, SegKind, Trace};

/// `PID_MAX_LIMIT` (2^22): no task has this id or any above. The critical path's track;
/// replacement ids for reused pids and tids count up from the next one.
const SYNTHETIC: u32 = 1 << 22;

/// Longest process name, in characters.
const MAX_NAME_CHARS: usize = 80;

/// Bytes of events gathered before they go to the output.
const CHUNK: usize = 64 * 1024;

/// One trace event (Chrome Trace Event format); `N` is its name.
#[derive(Serialize)]
struct Event<'a, N, A> {
    name: N,
    /// Category: the class, `process` or `__metadata`.
    cat: &'a str,
    /// Phase: `X` complete slice, `i` instant, `M` metadata.
    ph: &'static str,
    /// Microseconds from the window start.
    ts: u64,
    /// Slice length in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    dur: Option<u64>,
    pid: u32,
    tid: u32,
    /// Instant scope (`p`: the process).
    #[serde(skip_serializing_if = "Option::is_none")]
    s: Option<&'static str>,
    args: A,
}

/// Arguments of a `process_name`/`thread_name` metadata event.
#[derive(Serialize)]
struct Name<'a> {
    name: &'a str,
}

/// Arguments of a `process_sort_index` metadata event.
#[derive(Serialize)]
struct SortIndex {
    sort_index: i64,
}

/// Arguments of a thread's segment slice; each kind fills its own.
#[derive(Default, Serialize)]
struct SegArgs<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    run_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preempted_ns: Option<u64>,
    /// Who held the CPU (mixed: during the longest preemption).
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_held_by: Option<Shown<HolderName<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Shown<&'a Subject>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    syscall: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    waker_tid: Option<u32>,
    /// `comm` of a waker outside the traced tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    waker: Option<&'a str>,
}

/// Arguments of a critical-path slice.
#[derive(Serialize)]
struct SpanArgs<'a> {
    class: &'static str,
    subject: &'a str,
    pid: u32,
    tid: u32,
    comm: &'a str,
    depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_held_by: Option<Shown<HolderName<'a>>>,
}

/// Arguments of a fork instant.
#[derive(Serialize)]
struct ForkArgs {
    parent: Option<u32>,
}

/// Arguments of an exec instant.
#[derive(Serialize)]
struct ExecArgs<'a> {
    comm: &'a str,
    argv: String,
}

/// Arguments of an exit instant.
#[derive(Serialize)]
struct ExitArgs {
    code: Option<i32>,
}

/// A `Display` value serialized as a JSON string, without an intermediate `String`.
struct Shown<T>(T);

impl<T: fmt::Display> Serialize for Shown<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

/// A CPU holder as `comm (tgid)`.
struct HolderName<'a>(&'a Holder);

impl fmt::Display for HolderName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0.comm, self.0.tgid)
    }
}

/// A slice name: `class subject`, or the class alone for an empty subject.
struct Label<'a, S: ?Sized> {
    class: Class,
    subject: &'a S,
    empty: bool,
}

impl<S: fmt::Display + ?Sized> fmt::Display for Label<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class.name())?;
        if self.empty {
            Ok(())
        } else {
            write!(f, " {}", self.subject)
        }
    }
}

/// serde_json writes JSON a few bytes at a time; a `memcpy` call for each piece (musl's)
/// costs more than the copy, so short pieces are pushed byte by byte.
struct Chunk(Vec<u8>);

impl Write for Chunk {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() <= 16 {
            for &byte in bytes {
                self.0.push(byte);
            }
        } else {
            self.0.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The `traceEvents` array being written.
struct Events<'w> {
    w: &'w mut dyn Write,
    chunk: Chunk,
    first: bool,
}

impl Events<'_> {
    fn push<N: Serialize, A: Serialize>(&mut self, event: &Event<'_, N, A>) -> io::Result<()> {
        if !self.first {
            self.chunk.0.push(b',');
        }
        self.first = false;
        self.chunk.0.push(b'\n');
        serde_json::to_writer(&mut self.chunk, event)?;
        if self.chunk.0.len() >= CHUNK {
            self.w.write_all(&self.chunk.0)?;
            self.chunk.0.clear();
        }
        Ok(())
    }

    /// A `process_name` or `thread_name` metadata event.
    fn name(&mut self, kind: &'static str, (pid, tid): (u32, u32), name: &str) -> io::Result<()> {
        self.push(&Event {
            name: kind,
            cat: "__metadata",
            ph: "M",
            ts: 0,
            dur: None,
            pid,
            tid,
            s: None,
            args: Name { name },
        })
    }

    /// A `process_sort_index` metadata event.
    fn sort_index(&mut self, pid: u32, sort_index: i64) -> io::Result<()> {
        self.push(&Event {
            name: "process_sort_index",
            cat: "__metadata",
            ph: "M",
            ts: 0,
            dur: None,
            pid,
            tid: pid,
            s: None,
            args: SortIndex { sort_index },
        })
    }

    /// A process-scoped instant.
    fn instant<N: Serialize, A: Serialize>(
        &mut self,
        name: N,
        ts: u64,
        (pid, tid): (u32, u32),
        args: A,
    ) -> io::Result<()> {
        self.push(&Event {
            name,
            cat: "process",
            ph: "i",
            ts,
            dur: None,
            pid,
            tid,
            s: Some("p"),
            args,
        })
    }

    /// Writes what is left and closes the array and the object.
    fn finish(self) -> io::Result<()> {
        self.w.write_all(&self.chunk.0)?;
        self.w.write_all(b"\n]}\n")
    }
}

/// Writes the window `[start, end)` of `trace` and its critical path as Chrome Trace Event
/// JSON.
pub fn write(
    w: &mut dyn Write,
    trace: &Trace,
    attribution: &Attribution,
    (start, end): (u64, u64),
) -> io::Result<()> {
    let us = |ts: u64| (ts.clamp(start, end) - start) / 1_000;
    let in_window = |ts: u64| (start..=end).contains(&ts);
    let (pids, tids) = ids(trace);

    w.write_all(b"{\"displayTimeUnit\":\"ms\",\"traceEvents\":[")?;
    let mut out = Events {
        w,
        chunk: Chunk(Vec::with_capacity(CHUNK + 1024)),
        first: true,
    };
    let critical = (SYNTHETIC, SYNTHETIC);
    out.name("process_name", critical, "critical path")?;
    out.sort_index(SYNTHETIC, -1)?;
    out.name("thread_name", critical, "critical path")?;
    for span in &attribution.spans {
        let (ts, to) = (us(span.start), us(span.end));
        if to == ts {
            continue;
        }
        let proc = &trace.procs[span.proc];
        let name = Label {
            class: span.class,
            subject: span.subject.as_str(),
            empty: span.subject.is_empty(),
        };
        out.push(&Event {
            name: Shown(name),
            cat: span.class.name(),
            ph: "X",
            ts,
            dur: Some(to - ts),
            pid: critical.0,
            tid: critical.1,
            s: None,
            args: SpanArgs {
                class: span.class.name(),
                subject: &span.subject,
                pid: proc.key.pid,
                tid: trace.threads[span.thread].tid,
                comm: proc.comm_at(span.start),
                depth: span.depth,
                cpu_held_by: span.holder.map(|id| Shown(HolderName(trace.holder(id)))),
            },
        })?;
    }

    for (p, proc) in trace.procs.iter().enumerate() {
        let pid = pids[p];
        let main = proc.threads.first().map_or(pid, |&t| tids[t]);
        out.name("process_name", (pid, main), &process_name(proc))?;
        out.sort_index(pid, i64::try_from(p).unwrap_or(i64::MAX))?;
        let first = &proc.images[0];
        if !first.exec && proc.birth > start && proc.birth <= end {
            let parent = trace
                .table
                .get_key(proc.key)
                .and_then(|info| info.ppid);
            out.instant("fork", us(proc.birth), (pid, main), ForkArgs { parent })?;
        }
        for image in proc.images.iter().filter(|image| image.exec && in_window(image.from)) {
            let argv = String::from_utf8_lossy(&image.argv).replace('\0', " ");
            let args = ExecArgs {
                comm: &image.comm,
                argv: argv.trim_end().to_owned(),
            };
            let name = format!("exec {}", image.comm);
            out.instant(name, us(image.from), (pid, main), args)?;
        }
        if let Some(death) = proc.death.filter(|&death| in_window(death)) {
            let code = trace
                .table
                .get_key(proc.key)
                .and_then(|info| info.exit?.code)
                .map(exit_code);
            out.instant("exit", us(death), (pid, main), ExitArgs { code })?;
        }

        for &t in &proc.threads {
            let thread = &trace.threads[t];
            let (pid, tid) = (pid, tids[t]);
            out.name("thread_name", (pid, tid), proc.comm_at(thread.birth))?;
            let segs = &thread.segs;
            for seg in &segs[segs.partition_point(|s| s.end <= start)..] {
                if seg.start >= end {
                    break;
                }
                let (ts, to) = (us(seg.start), us(seg.end));
                if to == ts {
                    continue;
                }
                let held = |id| Shown(HolderName(trace.holder(id)));
                let (class, subject, args) = match &seg.kind {
                    &SegKind::Mixed { run, rq, holder } => {
                        let args = SegArgs {
                            run_ns: Some(run),
                            preempted_ns: Some(rq),
                            cpu_held_by: holder.map(held),
                            ..SegArgs::default()
                        };
                        (Class::Cpu, &Subject::Process, args)
                    }
                    &SegKind::Runq(holder) => {
                        let args = SegArgs {
                            cpu_held_by: holder.map(held),
                            ..SegArgs::default()
                        };
                        (Class::Runqueue, &Subject::Process, args)
                    }
                    SegKind::Blocked(block) => {
                        let subject = &block.what.subject;
                        let args = SegArgs {
                            subject: (*subject != Subject::Process).then_some(Shown(subject)),
                            syscall: block.syscall,
                            waker_tid: (block.waker_tid != 0).then_some(block.waker_tid),
                            waker: block.waker_comm.as_deref(),
                            ..SegArgs::default()
                        };
                        (block.what.class, subject, args)
                    }
                };
                // `Subject::Process` displays as nothing: the track names the process.
                let name = Label {
                    class,
                    subject,
                    empty: *subject == Subject::Process,
                };
                out.push(&Event {
                    name: Shown(name),
                    cat: class.name(),
                    ph: "X",
                    ts,
                    dur: Some(to - ts),
                    pid,
                    tid,
                    s: None,
                    args,
                })?;
            }
        }
    }
    out.finish()
}

/// Track ids: each process's pid and each thread's tid, unless an earlier process or thread
/// of the trace had it (the kernel reused it); those get fresh ids above [`SYNTHETIC`].
fn ids(trace: &Trace) -> (Vec<u32>, Vec<u32>) {
    let mut next = SYNTHETIC;
    let mut fresh = |seen: &mut HashSet<u32>, id: u32| {
        if seen.insert(id) {
            id
        } else {
            next += 1;
            next
        }
    };
    let mut seen = HashSet::new();
    let pids = trace
        .procs
        .iter()
        .map(|proc| fresh(&mut seen, proc.key.pid))
        .collect();
    let mut seen = HashSet::new();
    let tids = trace
        .threads
        .iter()
        .map(|thread| fresh(&mut seen, thread.tid))
        .collect();
    (pids, tids)
}

/// The process's last program and its arguments, like `ps` shows them.
fn process_name(proc: &Proc) -> String {
    let image = &proc.images[proc.images.len() - 1];
    let mut name = image.comm.to_string();
    for arg in image.args() {
        name.push(' ');
        name.push_str(&String::from_utf8_lossy(arg));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        name = name.chars().take(MAX_NAME_CHARS - 1).chain(['…']).collect();
    }
    name
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use libc::{SYS_nanosleep, SYS_wait4};
    use serde_json::Value;

    use super::*;
    use crate::attribute::attribute;
    use crate::testkit::{episode, exec, exit, feed, fork, seg, sys, trace};

    /// `sh` forks and execs `sort`, which computes (preempted at times), sleeps, computes and
    /// exits; `sh` waits for it, then computes. Times in microseconds.
    fn sh_waits_on_sort() -> Trace {
        let us = |n: u64| n * 1_000;
        let mut t = trace(100);
        feed(&mut t, &exec(us(1_000), 100, 100, "sh", seg(us(1_000), 0, 0)));
        feed(&mut t, &fork(us(1_100), 100, 100, 200, 200));
        feed(&mut t, &exec(us(1_200), 200, 200, "sort", seg(us(1_100), us(100), 0)));
        let mut ran = seg(us(1_200), us(1_000), us(500));
        (ran.preempt_max_ns, ran.preempt_tgid) = (us(300), 999);
        ran.preempt_comm[..6].copy_from_slice(b"chrome");
        let mut nap = episode(200, 200, ran, sys(SYS_nanosleep), [us(2_700), us(3_000), us(3_100)]);
        nap.run_holder_comm[..9].copy_from_slice(b"swapper/1");
        feed(&mut t, &nap);
        feed(&mut t, &exit(us(3_900), 200, 200, seg(us(3_100), us(800), 0), 0, true));
        let times = [us(1_150), us(3_900), us(4_000)];
        let mut wait = episode(100, 100, seg(us(1_000), us(150), 0), sys(SYS_wait4), times);
        (wait.waker_tid, wait.waker_tgid) = (200, 200);
        feed(&mut t, &wait);
        feed(&mut t, &exit(us(5_000), 100, 100, seg(us(4_000), us(1_000), 0), 0, true));
        t
    }

    #[test]
    fn the_export_is_trace_event_json_with_disjoint_slices_and_the_whole_critical_path() {
        let t = sh_waits_on_sort();
        let (start, end) = (1_000_000, 5_000_000);
        let attribution = attribute(&t, 0, start, end);
        let mut bytes = Vec::new();
        write(&mut bytes, &t, &attribution, (start, end)).unwrap();
        let json: Value = serde_json::from_slice(&bytes).expect("valid JSON");
        let events = json["traceEvents"].as_array().expect("traceEvents");

        let mut tracks: HashMap<(u64, u64), Vec<(u64, u64)>> = HashMap::new();
        for event in events.iter().filter(|e| e["ph"] == "X") {
            let at = |key: &str| event[key].as_u64().expect(key);
            assert!(at("dur") > 0, "{event}");
            tracks
                .entry((at("pid"), at("tid")))
                .or_default()
                .push((at("ts"), at("dur")));
        }
        for slices in tracks.values_mut() {
            slices.sort_unstable();
            for pair in slices.windows(2) {
                assert!(pair[0].0 + pair[0].1 <= pair[1].0, "overlap: {pair:?}");
            }
        }
        let critical = u64::from(SYNTHETIC);
        let path = &tracks[&(critical, critical)];
        assert_eq!(path.iter().map(|&(_, dur)| dur).sum::<u64>(), 4_000);
        // sh's track, sort's track and the critical path.
        assert_eq!(tracks.len(), 3);

        let named = |kind: &str, pid: u64| {
            events
                .iter()
                .find(|e| e["ph"] == "M" && e["name"] == kind && e["pid"] == pid)
                .and_then(|e| e["args"]["name"].as_str())
        };
        assert_eq!(named("process_name", critical), Some("critical path"));
        assert_eq!(named("process_name", 100), Some("sh"));
        assert_eq!(named("process_name", 200), Some("sort"));
        let instants: Vec<_> = events
            .iter()
            .filter(|e| e["ph"] == "i")
            .map(|e| {
                let name = e["name"].as_str().unwrap();
                (name, e["pid"].as_u64().unwrap(), e["ts"].as_u64().unwrap())
            })
            .collect();
        assert!(instants.contains(&("exec sh", 100, 0)));
        assert!(instants.contains(&("fork", 200, 100)));
        assert!(instants.contains(&("exec sort", 200, 200)));
        assert!(instants.contains(&("exit", 200, 2_900)));
        assert!(instants.contains(&("exit", 100, 4_000)));

        // sort's preempted share of its first stretch names the holder.
        let slice = |name: &str| {
            events
                .iter()
                .find(|e| e["ph"] == "X" && e["pid"] == critical && e["name"] == name)
                .unwrap_or_else(|| panic!("no {name} slice"))
        };
        assert_eq!(slice("runqueue sort")["args"]["cpu_held_by"], "chrome (999)");
        assert_eq!(slice("child sort")["args"]["pid"], 200);
    }
}
