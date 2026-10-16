//! Trace files: `whytime --record FILE` writes one, `whytime report FILE` replays it.
//!
//! A trace file holds every input the report is computed from, so replaying it through the
//! same [`Trace`], attribution and report code prints the identical report offline, without
//! BPF and without the traced processes: the raw ring buffer records in arrival order (with
//! the file paths the kernel captured and the resolver traffic hostnames come from), the
//! answer to every external lookup the pipeline made ([`FdTarget`], the classifier's
//! `/proc/<pid>/fd/<fd>` fallback for paths the kernel could not capture, keyed by
//! `(dev, ino)` like its cache), the final sweep of the `tasks` map, and the run's context
//! (command line, root pid, home directory for `~`, optional probe availability, `AT_CLKTCK`
//! for procctx, architecture for syscall numbers, how the window ended, dropped records and
//! lost resolver captures). Attach mode (`-p`) adds what it read from `/proc`
//! before the window: the [`ProcSeed`]s it fed [`Trace::seed`], the window start, and how
//! many blocked threads had an unreadable syscall. procctx needs nothing else: whytime only
//! calls its event handlers and `get_key`, which never read `/proc`.
//!
//! # Format (version 4)
//!
//! Little-endian. A 24-byte preamble, then frames.
//!
//! | Bytes | Preamble field |
//! |---|---|
//! | 8 | magic `WHYTRACE` |
//! | 4 | format version ([`VERSION`]) |
//! | 4 | zero |
//! | 8 | `whytime_bpf::ABI_HASH` of the recording whytime (layout of records and `task_state`) |
//!
//! A frame is `kind: u32, len: u32`, then `len` payload bytes. In payloads, `bytes` is a
//! `u32` length and the bytes, and `opt T` is a presence byte (0 or 1) followed by `T` if 1.
//!
//! | Kind | Frame | Payload |
//! |---|---|---|
//! | 1 | header: first, once | root pid `u32`, probes attached `u8` × 4 (syscalls, readiness, faults, dns), `AT_CLKTCK` `u64`, arch `bytes`, home `opt bytes`, argc `u32`, argc × arg `bytes`, attached `opt u64` (present in attach mode, where the root pid is the target: blocked threads whose syscall was unreadable) |
//! | 2 | record | one ring buffer record, verbatim |
//! | 3 | lookup | `/proc/<pid>/fd/<fd>`: dev `u32`, ino `u64`, found `u8`, then the link target (rest of the payload) |
//! | 7 | mapping | `/proc/<pid>/maps`: dev `u32`, ino `u64`, found `u8`, then the mapped path (rest of the payload) |
//! | 4 | task | tid `u32`, `task_state` (one entry of the final `tasks` sweep) |
//! | 5 | end: last, once | window start `opt u64`, window end `u64`, ended by `u8` (0 exit, 1 duration, 2 interrupt), exit code `opt i32`, dropped `u64`, resolver captures lost `u64` |
//! | 6 | seed: attach mode only, once, before any record | window start `u64`, count `u32`, then per process: pid `u32`, start `u64` (procctx key), ppid `u32`, seeded at `u64`, comm `bytes`, argv `bytes` (NUL-separated), thread count `u32`, threads × (tid `u32`, entry time `u64`) |
//!
//! Frames are written as the run goes; tasks and the end frame when the window ends, so a
//! file without an end frame was cut short and is rejected. Bump [`VERSION`] when the
//! framing or a payload changes. A different ABI hash means the record layouts changed: the
//! frames still parse, but the records would be misread, so such files are rejected too.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Write as _};
use std::num::NonZeroU64;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use procctx::ProcKey;
use whytime_abi::TaskState;

use crate::classify::{Classifier, FdTarget};
use crate::report::{Attached, EndedBy};
use crate::sys::SyscallTable;
use crate::timeline::{self, ProcSeed, Trace};

/// Trace file magic.
const MAGIC: [u8; 8] = *b"WHYTRACE";
/// Preamble length (magic, version, zero, ABI hash): the header frame's offset.
const PREAMBLE: usize = MAGIC.len() + 16;
/// Format version written and read.
pub const VERSION: u32 = 4;
/// Architecture whose syscall numbers this build classifies.
const ARCH: &str = std::env::consts::ARCH;

const F_HEADER: u32 = 1;
const F_RECORD: u32 = 2;
const F_LOOKUP: u32 = 3;
const F_TASK: u32 = 4;
const F_END: u32 = 5;
const F_SEED: u32 = 6;
const F_MAPPING: u32 = 7;

/// Which optional program sets were attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probes {
    /// Syscall tracepoints.
    pub syscalls: bool,
    /// Poll/epoll readiness fentry programs.
    pub readiness: bool,
    /// Page-fault fentry/fexit programs.
    pub faults: bool,
    /// The resolver capture (`sys_exit` copying resolver replies).
    pub dns: bool,
}

/// What the recording run knew when the window opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// `std::env::consts::ARCH` of the recording whytime: syscall numbers depend on it.
    pub arch: String,
    /// The command line (attach mode: the target's).
    pub command: Vec<OsString>,
    /// COMMAND's pid (attach mode: the target's).
    pub root_pid: u32,
    /// Home directory abbreviated to `~`.
    pub home: Option<PathBuf>,
    /// Which optional program sets were attached.
    pub probes: Probes,
    /// `AT_CLKTCK`, procctx's start clock resolution.
    pub ticks_per_sec: NonZeroU64,
    /// Attach mode: the target (`root_pid`) and how it was seeded.
    pub attached: Option<Attached>,
}

/// Attach mode's start: what `/proc` showed of the running tree.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seeding {
    /// Window start, the end of seeding.
    start: u64,
    /// The processes [`Trace::seed`] was given, parents first.
    procs: Vec<ProcSeed>,
}

/// How the window ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct End {
    /// Window start the live trace saw (the root's exec, or the end of attach's seeding).
    pub start: Option<u64>,
    /// Window end: the time the sweep closed open intervals at.
    pub end: u64,
    /// Why it ended.
    pub ended_by: EndedBy,
    /// COMMAND's exit code, when it exited.
    pub exit_code: Option<i32>,
    /// Records or tasks lost in kernel.
    pub dropped: u64,
    /// Resolver sockets or payloads the kernel could not capture.
    pub dns_lost: u64,
}

/// Why a trace file cannot be replayed.
#[derive(Debug)]
pub enum Error {
    /// Not a trace file.
    Magic,
    /// A format version this whytime does not read.
    Version(u32),
    /// Recorded by a whytime with other record layouts.
    Abi {
        /// Hash in the file.
        file: u64,
        /// This build's hash.
        ours: u64,
    },
    /// Recorded on another architecture, whose syscall numbers differ.
    Arch(String),
    /// The file ends before its end frame.
    Truncated,
    /// Structurally invalid.
    Malformed {
        /// Byte offset of the offending frame or field.
        at: usize,
        /// What is wrong.
        what: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Magic => f.write_str("not a whytime trace file"),
            Self::Version(version) => write!(
                f,
                "trace format version {version} is not supported (this whytime reads version \
                 {VERSION})"
            ),
            Self::Abi { file, ours } => write!(
                f,
                "recorded with wire ABI {file:#018x}, but this whytime uses {ours:#018x}: the \
                 record layout changed, so the trace cannot be replayed; record it again with \
                 this whytime"
            ),
            Self::Arch(arch) => write!(
                f,
                "recorded on {arch}, but this whytime is built for {ARCH} (syscall numbers \
                 differ); replay it with a whytime built for {arch}"
            ),
            Self::Truncated => f.write_str(
                "truncated: the recording ended before the observation window did (whytime was \
                 interrupted or failed)",
            ),
            Self::Malformed { at, what } => write!(f, "malformed trace at byte {at}: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// Writes a trace file as the run goes. Clones share the file; the first write error sticks
/// and is returned by [`finish`](Self::finish).
#[derive(Clone, Debug)]
pub struct Recorder(Rc<RefCell<Sink>>);

/// The file behind a [`Recorder`].
#[derive(Debug)]
struct Sink {
    /// Buffered trace file.
    out: BufWriter<File>,
    /// First write error; later frames are dropped.
    error: Option<io::Error>,
}

impl Recorder {
    /// Creates (truncates) `path` and writes the preamble. A regular file is handed to
    /// `owner` (uid, gid), so a trace recorded under sudo belongs to the invoking user.
    pub fn create(path: &Path, owner: Option<(u32, u32)>) -> io::Result<Self> {
        let file = File::create(path)?;
        if let Some((uid, gid)) = owner
            && file.metadata()?.is_file()
        {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
        let mut out = BufWriter::new(file);
        out.write_all(&MAGIC)?;
        out.write_all(&VERSION.to_le_bytes())?;
        out.write_all(&0_u32.to_le_bytes())?;
        out.write_all(&whytime_bpf::ABI_HASH.to_le_bytes())?;
        Ok(Self(Rc::new(RefCell::new(Sink { out, error: None }))))
    }

    /// Writes the header frame.
    pub fn header(&self, header: &Header) {
        let mut p = Enc::default();
        p.u32(header.root_pid)
            .u8(u8::from(header.probes.syscalls))
            .u8(u8::from(header.probes.readiness))
            .u8(u8::from(header.probes.faults))
            .u8(u8::from(header.probes.dns))
            .u64(header.ticks_per_sec.get())
            .bytes(header.arch.as_bytes());
        match &header.home {
            Some(home) => p.u8(1).bytes(home.as_os_str().as_bytes()),
            None => p.u8(0),
        };
        p.u32(u32::try_from(header.command.len()).unwrap_or(u32::MAX));
        for arg in &header.command {
            p.bytes(arg.as_bytes());
        }
        let unreadable = header
            .attached
            .map(|attached| u64::try_from(attached.unreadable).unwrap_or(u64::MAX));
        p.opt(unreadable, Enc::u64);
        self.frame(F_HEADER, &[&p.0]);
    }

    /// Writes attach mode's seeding: the arguments of [`Trace::seed`].
    pub fn seed(&self, seeds: &[ProcSeed], start: u64) {
        let mut p = Enc::default();
        p.u64(start)
            .u32(u32::try_from(seeds.len()).unwrap_or(u32::MAX));
        for seed in seeds {
            p.u32(seed.key.pid)
                .u64(seed.key.start)
                .u32(seed.ppid)
                .u64(seed.birth)
                .bytes(seed.comm.as_bytes())
                .bytes(&seed.argv)
                .u32(u32::try_from(seed.threads.len()).unwrap_or(u32::MAX));
            for &(tid, birth) in &seed.threads {
                p.u32(tid).u64(birth);
            }
        }
        self.frame(F_SEED, &[&p.0]);
    }

    /// Writes one ring buffer record.
    pub fn record(&self, bytes: &[u8]) {
        self.frame(F_RECORD, &[bytes]);
    }

    /// Writes the answer of an [`FdTarget`] lookup, as frame `kind` ([`F_LOOKUP`] for
    /// descriptor links, [`F_MAPPING`] for mappings).
    fn lookup(&self, kind: u32, dev: u32, ino: u64, target: Option<&Path>) {
        let (found, path) = target.map_or((0, &[][..]), |path| (1, path.as_os_str().as_bytes()));
        self.frame(
            kind,
            &[&dev.to_le_bytes(), &ino.to_le_bytes(), &[found], path],
        );
    }

    /// Writes the final `tasks` sweep and the end frame, and flushes.
    pub fn finish(&self, tasks: &[(u32, TaskState)], end: &End) -> io::Result<()> {
        for (tid, state) in tasks {
            self.frame(F_TASK, &[&tid.to_le_bytes(), wire::as_bytes(state)]);
        }
        let mut p = Enc::default();
        p.opt(end.start, Enc::u64)
            .u64(end.end)
            .u8(match end.ended_by {
                EndedBy::Exit => 0,
                EndedBy::Duration => 1,
                EndedBy::Interrupt => 2,
            })
            .opt(end.exit_code, Enc::i32)
            .u64(end.dropped)
            .u64(end.dns_lost);
        self.frame(F_END, &[&p.0]);
        let mut sink = self.0.borrow_mut();
        if sink.error.is_none()
            && let Err(err) = sink.out.flush()
        {
            sink.error = Some(err);
        }
        sink.error.take().map_or(Ok(()), Err)
    }

    fn frame(&self, kind: u32, parts: &[&[u8]]) {
        let mut sink = self.0.borrow_mut();
        if sink.error.is_some() {
            return;
        }
        let len = parts.iter().map(|part| part.len()).sum::<usize>();
        let written = match u32::try_from(len) {
            Ok(len) => write_frame(&mut sink.out, kind, len, parts),
            Err(_) => Err(io::Error::other("trace frame over 4 GiB")),
        };
        if let Err(err) = written {
            sink.error = Some(err);
        }
    }
}

/// Writes one frame whose payload is `parts` concatenated (`len` bytes).
fn write_frame(out: &mut impl io::Write, kind: u32, len: u32, parts: &[&[u8]]) -> io::Result<()> {
    out.write_all(&kind.to_le_bytes())?;
    out.write_all(&len.to_le_bytes())?;
    parts.iter().try_for_each(|part| out.write_all(part))
}

/// The live [`FdTarget`] `T`, recording every answer.
#[derive(Debug)]
pub struct Logged<T> {
    inner: T,
    recorder: Recorder,
}

impl<T> Logged<T> {
    /// Records `inner`'s answers to `recorder`.
    pub fn new(inner: T, recorder: Recorder) -> Self {
        Self { inner, recorder }
    }
}

impl<T: FdTarget> FdTarget for Logged<T> {
    fn fd_target(&self, tgid: u32, fd: i32, dev: u32, ino: u64) -> Option<PathBuf> {
        let target = self.inner.fd_target(tgid, fd, dev, ino);
        self.recorder.lookup(F_LOOKUP, dev, ino, target.as_deref());
        target
    }

    fn mapped_file(&self, tgid: u32, dev: u32, ino: u64) -> Option<PathBuf> {
        let target = self.inner.mapped_file(tgid, dev, ino);
        self.recorder.lookup(F_MAPPING, dev, ino, target.as_deref());
        target
    }
}

/// Lookup answers by `(dev, ino)`.
type Answers = HashMap<(u32, u64), Option<PathBuf>>;

/// [`FdTarget`] answering from a trace file: descriptor links, then mappings.
#[derive(Debug)]
struct Replayed(Answers, Answers);

impl FdTarget for Replayed {
    fn fd_target(&self, _tgid: u32, _fd: i32, dev: u32, ino: u64) -> Option<PathBuf> {
        self.0.get(&(dev, ino)).cloned().flatten()
    }

    fn mapped_file(&self, _tgid: u32, dev: u32, ino: u64) -> Option<PathBuf> {
        self.1.get(&(dev, ino)).cloned().flatten()
    }
}

/// A parsed trace file.
#[derive(Debug)]
struct Recording<'a> {
    /// Header frame.
    header: Header,
    /// Seed frame (attach mode).
    seeding: Option<Seeding>,
    /// Ring buffer records in arrival order.
    records: Vec<&'a [u8]>,
    /// Descriptor link answers by `(dev, ino)`.
    lookups: Answers,
    /// Mapping answers by `(dev, ino)`.
    mappings: Answers,
    /// The final `tasks` sweep.
    tasks: Vec<(u32, TaskState)>,
    /// End frame.
    end: End,
}

/// A trace file replayed into the state the report is computed from.
#[derive(Debug)]
pub struct Replay {
    /// The rebuilt trace, swept at `end.end`.
    pub trace: Trace,
    /// Header frame.
    pub header: Header,
    /// End frame.
    pub end: End,
}

/// Parses and checks a whole trace file.
fn parse(bytes: &[u8]) -> Result<Recording<'_>, Error> {
    if bytes.len() < MAGIC.len() && MAGIC.starts_with(bytes) {
        return Err(Error::Truncated);
    }
    if !bytes.starts_with(&MAGIC) {
        return Err(Error::Magic);
    }
    let mut file = Dec::file(bytes);
    file.take(MAGIC.len())?;
    let version = file.u32()?;
    if version != VERSION {
        return Err(Error::Version(version));
    }
    file.u32()?;
    let abi = file.u64()?;
    if abi != whytime_bpf::ABI_HASH {
        return Err(Error::Abi {
            file: abi,
            ours: whytime_bpf::ABI_HASH,
        });
    }

    let mut header = None;
    let mut seeding = None;
    let mut end = None;
    let mut records = Vec::new();
    let mut lookups = HashMap::new();
    let mut mappings = HashMap::new();
    let mut tasks = Vec::new();
    while !file.bytes.is_empty() {
        let at = file.at;
        if end.is_some() {
            return Err(malformed(at, "data after the end frame"));
        }
        let kind = file.u32()?;
        let len = file.u32()?;
        let payload = file.take(usize::try_from(len).map_err(|_| Error::Truncated)?)?;
        let mut p = Dec::payload(payload, at + 8);
        match kind {
            F_HEADER if header.is_none() => header = Some(p.header()?),
            F_HEADER => return Err(malformed(at, "second header frame")),
            _ if header.is_none() => return Err(malformed(at, "first frame is not the header")),
            F_SEED if header.as_ref().is_some_and(|h| h.attached.is_none()) => {
                return Err(malformed(at, "seed frame in a trace that did not attach"));
            }
            F_SEED if seeding.is_some() => return Err(malformed(at, "second seed frame")),
            F_SEED if !records.is_empty() => return Err(malformed(at, "seed frame after a record")),
            F_SEED => seeding = Some(p.seeding()?),
            F_RECORD => records.push(payload),
            F_LOOKUP | F_MAPPING => {
                let key = (p.u32()?, p.u64()?);
                let found = p.flag()?;
                let target = found.then(|| PathBuf::from(OsStr::from_bytes(p.bytes)));
                let answers = if kind == F_LOOKUP { &mut lookups } else { &mut mappings };
                answers.insert(key, target);
            }
            F_TASK => {
                let tid = p.u32()?;
                let state = wire::read::<TaskState>(p.take(size_of::<TaskState>())?)
                    .ok_or_else(|| malformed(p.at, "task state too short"))?;
                p.done()?;
                tasks.push((tid, state));
            }
            F_END => end = Some(p.end()?),
            _ => return Err(malformed(at, "unknown frame kind")),
        }
    }
    let (Some(header), Some(end)) = (header, end) else {
        return Err(Error::Truncated);
    };
    if header.attached.is_some() && seeding.is_none() {
        return Err(malformed(PREAMBLE, "attached trace without a seed frame"));
    }
    Ok(Recording {
        header,
        seeding,
        records,
        lookups,
        mappings,
        tasks,
        end,
    })
}

/// Replays a trace file: the same ingest and sweep as the live run, with recorded lookups.
pub fn replay(bytes: &[u8]) -> Result<Replay, Error> {
    let Recording {
        header,
        seeding,
        records,
        lookups,
        mappings,
        tasks,
        end,
    } = parse(bytes)?;
    if header.arch != ARCH {
        return Err(Error::Arch(header.arch));
    }
    let classifier = Classifier::new(
        SyscallTable::new(),
        header.home.clone(),
        Box::new(Replayed(lookups, mappings)),
    );
    let mut trace = Trace::new(
        header.root_pid,
        classifier,
        timeline::proc_table(header.ticks_per_sec),
    );
    if let Some(seeding) = seeding {
        trace.seed(&seeding.procs, seeding.start);
    }
    let mut scratch = Vec::new();
    for record in records {
        trace.ingest(aligned(&mut scratch, record));
    }
    trace.sweep(&tasks, end.end);
    if trace.window.start != end.start {
        log::warn!(
            "replay diverged: window start {:?} recorded, {:?} replayed",
            end.start,
            trace.window.start
        );
    }
    Ok(Replay { trace, header, end })
}

/// `bytes` copied to 8-byte aligned memory, as the ring buffer hands records out
/// (`wire::from_bytes` requires it). `scratch` is reused across calls.
fn aligned<'s>(scratch: &'s mut Vec<u64>, bytes: &[u8]) -> &'s [u8] {
    scratch.clear();
    scratch.extend(bytes.chunks(8).map(|chunk| {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        u64::from_ne_bytes(word)
    }));
    // SAFETY: the words hold `bytes` in order (native byte order round-trips), `u8` has no
    // alignment or validity requirements, and `bytes.len() <= 8 * scratch.len()`.
    unsafe { std::slice::from_raw_parts(scratch.as_ptr().cast::<u8>(), bytes.len()) }
}

/// Builds a frame payload.
#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn i32(&mut self, value: i32) -> &mut Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn bytes(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.u32(len);
        self.0
            .extend_from_slice(&value[..usize::try_from(len).unwrap_or(0)]);
        self
    }

    fn opt<T>(&mut self, value: Option<T>, put: fn(&mut Self, T) -> &mut Self) -> &mut Self {
        match value {
            Some(value) => put(self.u8(1), value),
            None => self.u8(0),
        }
    }
}

/// Reads the file or a frame payload; `at` is the absolute offset for errors. Running out of
/// bytes means truncation in the file and malformation in a payload.
struct Dec<'a> {
    bytes: &'a [u8],
    at: usize,
    payload: bool,
}

impl<'a> Dec<'a> {
    fn file(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            payload: false,
        }
    }

    fn payload(bytes: &'a [u8], at: usize) -> Self {
        Self {
            bytes,
            at,
            payload: true,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.bytes.len() < n {
            return Err(if self.payload {
                malformed(self.at, "frame payload too short")
            } else {
                Error::Truncated
            });
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        self.at += n;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut array = [0; N];
        array.copy_from_slice(self.take(N)?);
        Ok(array)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(u64::from_le_bytes)
    }

    fn i32(&mut self) -> Result<i32, Error> {
        self.array().map(i32::from_le_bytes)
    }

    fn flag(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed(self.at - 1, "flag is not 0 or 1")),
        }
    }

    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u32()?;
        self.take(usize::try_from(len).map_err(|_| malformed(self.at, "length overflow"))?)
    }

    fn opt<T>(&mut self, get: fn(&mut Self) -> Result<T, Error>) -> Result<Option<T>, Error> {
        if self.flag()? { get(self).map(Some) } else { Ok(None) }
    }

    fn done(&self) -> Result<(), Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(malformed(self.at, "trailing bytes in frame"))
        }
    }

    fn header(&mut self) -> Result<Header, Error> {
        let root_pid = self.u32()?;
        let probes = Probes {
            syscalls: self.flag()?,
            readiness: self.flag()?,
            faults: self.flag()?,
            dns: self.flag()?,
        };
        let ticks_per_sec =
            NonZeroU64::new(self.u64()?).ok_or_else(|| malformed(self.at - 8, "zero AT_CLKTCK"))?;
        let arch = String::from_utf8(self.blob()?.to_vec())
            .map_err(|_| malformed(self.at, "architecture is not UTF-8"))?;
        let home = self
            .opt(Self::blob)?
            .map(|home| PathBuf::from(OsStr::from_bytes(home)));
        let argc = self.u32()?;
        // Not preallocated: `argc` is untrusted until every argument has been read.
        let mut command = Vec::new();
        for _ in 0..argc {
            command.push(OsString::from_vec(self.blob()?.to_vec()));
        }
        let attached = match self.opt(Self::u64)? {
            Some(unreadable) => Some(Attached {
                pid: root_pid,
                unreadable: usize::try_from(unreadable)
                    .map_err(|_| malformed(self.at - 8, "unreadable count overflow"))?,
            }),
            None => None,
        };
        self.done()?;
        Ok(Header {
            arch,
            command,
            root_pid,
            home,
            probes,
            ticks_per_sec,
            attached,
        })
    }

    fn seeding(&mut self) -> Result<Seeding, Error> {
        let start = self.u64()?;
        let count = self.u32()?;
        // Not preallocated: the counts are untrusted until every entry has been read.
        let mut procs = Vec::new();
        for _ in 0..count {
            let key = ProcKey {
                pid: self.u32()?,
                start: self.u64()?,
            };
            let ppid = self.u32()?;
            let birth = self.u64()?;
            let comm = String::from_utf8(self.blob()?.to_vec())
                .map_err(|_| malformed(self.at, "comm is not UTF-8"))?;
            let argv = self.blob()?.to_vec();
            let mut threads = Vec::new();
            for _ in 0..self.u32()? {
                threads.push((self.u32()?, self.u64()?));
            }
            procs.push(ProcSeed {
                key,
                ppid,
                comm,
                argv,
                birth,
                threads,
            });
        }
        self.done()?;
        Ok(Seeding { start, procs })
    }

    fn end(&mut self) -> Result<End, Error> {
        let start = self.opt(Self::u64)?;
        let end = self.u64()?;
        let ended_by = match self.u8()? {
            0 => EndedBy::Exit,
            1 => EndedBy::Duration,
            2 => EndedBy::Interrupt,
            _ => return Err(malformed(self.at - 1, "unknown window end reason")),
        };
        let exit_code = self.opt(Self::i32)?;
        let dropped = self.u64()?;
        let dns_lost = self.u64()?;
        self.done()?;
        Ok(End {
            start,
            end,
            ended_by,
            exit_code,
            dropped,
            dns_lost,
        })
    }
}

/// [`Error::Malformed`] at byte `at`.
fn malformed(at: usize, what: &'static str) -> Error {
    Error::Malformed { at, what }
}

#[cfg(test)]
mod tests {
    use libc::{SYS_fsync, SYS_recvfrom};
    use whytime_abi::{DNS_UDP, ST_RUNNING};

    use super::*;
    use crate::testkit::{dns, episode, exec, seg, sys, task};

    const DEV: u32 = (8 << 20) | 1;
    const INO: u64 = 42;

    /// What `/proc` would answer during the recorded run: one file.
    #[derive(Debug)]
    struct OneFile;

    impl FdTarget for OneFile {
        fn fd_target(&self, _tgid: u32, _fd: i32, dev: u32, ino: u64) -> Option<PathBuf> {
            (dev == DEV && ino == INO).then(|| PathBuf::from("/home/u/proj/data.db"))
        }

        fn mapped_file(&self, _tgid: u32, dev: u32, ino: u64) -> Option<PathBuf> {
            (dev == DEV && ino == INO + 1).then(|| PathBuf::from("/home/u/maps/lib.so"))
        }
    }

    /// Records a small run the way `whytime --record` does (with `attached`, the way
    /// `whytime -p 100 --record` does); returns the live JSON report and the trace file.
    fn record_run(name: &str, arch: &str, attached: bool) -> (String, Vec<u8>) {
        let path = std::env::temp_dir().join(format!(
            "whytime-record-test-{}-{name}.wt",
            std::process::id()
        ));
        let recorder = Recorder::create(&path, None).expect("creating the trace file");
        let header = Header {
            arch: arch.to_owned(),
            command: vec!["app".into(), "--flag".into()],
            root_pid: 100,
            home: Some(PathBuf::from("/home/u")),
            probes: Probes {
                syscalls: true,
                readiness: true,
                faults: true,
                dns: true,
            },
            ticks_per_sec: NonZeroU64::new(100).expect("non-zero"),
            attached: attached.then_some(Attached {
                pid: 100,
                unreadable: 1,
            }),
        };
        recorder.header(&header);
        let files = Logged::new(OneFile, recorder.clone());
        let classifier = Classifier::new(SyscallTable::new(), header.home.clone(), Box::new(files));
        let mut trace = Trace::new(100, classifier, timeline::proc_table(header.ticks_per_sec));
        let live = |trace: &mut Trace, bytes: &[u8]| crate::ingest(trace, Some(&recorder), bytes);
        if attached {
            let seed = |pid, ppid, comm: &str, threads| ProcSeed {
                key: ProcKey { pid, start: 500 },
                ppid,
                comm: comm.to_owned(),
                argv: format!("{comm}\0--flag\0").into_bytes(),
                birth: 900,
                threads,
            };
            let seeds = [
                seed(100, 1, "app", vec![(100, 910), (101, 920)]),
                seed(200, 100, "helper", vec![(200, 930)]),
            ];
            recorder.seed(&seeds, 1_000);
            trace.seed(&seeds, 1_000);
        } else {
            live(&mut trace, wire::as_bytes(&exec(1_000, 100, 100, "app", seg(1_000, 0, 0))));
        }

        let mut fsync = sys(SYS_fsync);
        fsync.fd = 3;
        fsync.mode = 0o100_000;
        fsync.dev = DEV;
        fsync.ino = INO;
        let first = episode(100, 100, seg(1_000, 100, 0), fsync, [1_100, 1_900, 1_900]);
        live(&mut trace, wire::as_bytes(&first));
        // Undecodable records are counted in the report, so they are recorded too.
        live(&mut trace, &[1, 2, 3]);
        let second = episode(100, 100, seg(1_900, 100, 0), fsync, [2_000, 2_400, 2_500]);
        live(&mut trace, wire::as_bytes(&second));
        // A block inside a page fault on a mapped file: its path comes from the mappings.
        let mut fault = episode(100, 100, seg(2_500, 100, 0), sys(SYS_fsync), [2_600, 2_800, 2_800]);
        fault.flags = whytime_abi::EPF_FAULT;
        fault.fault.mode = 0o100_000;
        fault.fault.dev = DEV;
        fault.fault.ino = INO + 1;
        live(&mut trace, wire::as_bytes(&fault));
        // A DNS answer (db.internal A 10.0.0.9, as a UDP resolver sends it), then a block on a
        // socket connected to 10.0.0.9:5432: the hostname comes from the recorded records.
        let mut answer = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        answer.extend_from_slice(b"\x02db\x08internal\x00\x00\x01\x00\x01");
        answer.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 9]);
        live(&mut trace, wire::as_bytes(&dns(100, 77, DNS_UDP, false, &answer)));
        let mut recv = sys(SYS_recvfrom);
        recv.mode = 0o140_000;
        recv.family = 2;
        recv.port = 5432;
        recv.addr[..4].copy_from_slice(&[10, 0, 0, 9]);
        recv.ino = 78;
        let net = episode(100, 100, seg(2_800, 0, 0), recv, [2_800, 2_900, 2_900]);
        live(&mut trace, wire::as_bytes(&net));
        let mut running = task(100, ST_RUNNING, seg(2_900, 0, 0));
        running.last_ts = 2_900;
        let tasks = [(100, running)];
        trace.sweep(&tasks, 3_000);
        let end = End {
            start: trace.window.start,
            end: 3_000,
            ended_by: if attached {
                EndedBy::Interrupt
            } else {
                EndedBy::Duration
            },
            exit_code: None,
            dropped: 2,
            dns_lost: 0,
        };
        recorder.finish(&tasks, &end).expect("writing the trace file");

        let mut json = Vec::new();
        let meta = crate::meta(&header, &end);
        crate::write_report(&mut json, &trace, end.end, meta, true).expect("rendering");
        let bytes = std::fs::read(&path).expect("reading the trace file back");
        std::fs::remove_file(&path).expect("removing the trace file");
        (String::from_utf8(json).expect("UTF-8 JSON"), bytes)
    }

    fn replayed_json(bytes: &[u8]) -> String {
        let replay = replay(bytes).expect("replaying");
        let meta = crate::meta(&replay.header, &replay.end);
        let mut json = Vec::new();
        crate::write_report(&mut json, &replay.trace, replay.end.end, meta, true)
            .expect("rendering");
        String::from_utf8(json).expect("UTF-8 JSON")
    }

    /// Offset of the frame after the one at `at`.
    fn next_frame(bytes: &[u8], at: usize) -> usize {
        let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().expect("4 bytes"));
        at + 8 + usize::try_from(len).expect("frame length")
    }

    #[test]
    fn a_recorded_run_replays_to_the_identical_report() {
        let (live, bytes) = record_run("identical", ARCH, false);
        let replayed = replayed_json(&bytes);
        assert_eq!(replayed, live);
        // The path came from the recorded lookup and the recorded home, not this machine.
        assert!(replayed.contains("\"subject\": \"~/proj\""), "{replayed}");
        // The page fault's file came from the recorded mapping.
        assert!(replayed.contains("\"subject\": \"~/maps\""), "{replayed}");
        // The peer's name came from the recorded resolver answer.
        assert!(replayed.contains("\"subject\": \"db.internal:5432\""), "{replayed}");
        assert!(replayed.contains("\"addr\": \"10.0.0.9:5432\""), "{replayed}");
        assert!(replayed.contains("\"events\": 7"), "{replayed}");
    }

    #[test]
    fn an_attached_run_replays_its_seeded_tree_to_the_identical_report() {
        let (live, bytes) = record_run("attached", ARCH, true);
        let replayed = replayed_json(&bytes);
        assert_eq!(replayed, live);
        assert!(replayed.contains("\"attached_pid\": 100"), "{replayed}");
        assert!(replayed.contains("\"ended_by\": \"interrupt\""), "{replayed}");
        // The seeded child, its argv from /proc, and the unreadable-syscall note.
        assert!(replayed.contains("\"comm\": \"helper\""), "{replayed}");
        assert!(replayed.contains("\"--flag\""), "{replayed}");
        assert!(replayed.contains("1 thread(s) blocked at attach"), "{replayed}");
    }

    #[test]
    fn a_trace_from_another_record_layout_names_both_hashes() {
        let (_, mut bytes) = record_run("abi", ARCH, false);
        bytes[16] ^= 0xff;
        let err = replay(&bytes).expect_err("an ABI mismatch");
        let Error::Abi { file, ours } = err else {
            panic!("not an ABI error: {err}");
        };
        assert_eq!(ours, whytime_bpf::ABI_HASH);
        assert_ne!(file, ours);
        let message = err.to_string();
        assert!(message.contains(&format!("{file:#018x}")), "{message}");
        assert!(message.contains(&format!("{ours:#018x}")), "{message}");
    }

    #[test]
    fn a_trace_from_another_architecture_is_refused() {
        let (_, bytes) = record_run("arch", "riscv64", false);
        assert!(matches!(replay(&bytes), Err(Error::Arch(arch)) if arch == "riscv64"));
    }

    #[test]
    fn cut_short_files_are_truncated_and_damaged_ones_malformed() {
        let (_, bytes) = record_run("damaged", ARCH, false);
        let (_, attached) = record_run("damaged-attached", ARCH, true);
        for bytes in [&bytes, &attached] {
            for len in 0..bytes.len() {
                assert!(
                    matches!(replay(&bytes[..len]), Err(Error::Truncated)),
                    "a file cut to {len} of {} bytes",
                    bytes.len()
                );
            }
        }

        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert!(matches!(replay(&magic), Err(Error::Magic)));
        let mut version = bytes.clone();
        version[8..12].copy_from_slice(&9_u32.to_le_bytes());
        assert!(matches!(replay(&version), Err(Error::Version(9))));
        let mut kind = bytes.clone();
        kind[24..28].copy_from_slice(&99_u32.to_le_bytes());
        assert!(matches!(replay(&kind), Err(Error::Malformed { at: 24, .. })));
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&F_RECORD.to_le_bytes());
        trailing.extend_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(replay(&trailing), Err(Error::Malformed { at, .. }) if at == bytes.len()));

        // The seed frame follows the header; an attached trace needs it, others refuse it.
        let seed_at = next_frame(&attached, PREAMBLE);
        let seed = seed_at..next_frame(&attached, seed_at);
        let mut unseeded = attached.clone();
        unseeded.drain(seed.clone());
        assert!(matches!(replay(&unseeded), Err(Error::Malformed { at: PREAMBLE, .. })));
        let mut wrapped = bytes.clone();
        let after_header = next_frame(&bytes, PREAMBLE);
        wrapped.splice(after_header..after_header, attached[seed].iter().copied());
        assert!(
            matches!(replay(&wrapped), Err(Error::Malformed { at, .. }) if at == after_header)
        );
    }
}
