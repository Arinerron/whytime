//! Stacks for flamegraphs, when stack capture is on (`--flamegraph`, `--folded`).
//!
//! The kernel side records stacks as references into its `stacks` map: the user and kernel
//! stack of every block (episode records and the final sweep) and of every on-CPU sample
//! (sample records). A user address only means something in its process's address space at
//! that time, so the [`Collector`] normalizes each user stack as its record arrives, while
//! the process still runs: every address becomes (mapped file, file offset) through a cache
//! of the process image's `/proc/PID/maps` (read at exec, copied at fork, re-read on a miss
//! while that image is current), and each mapped file is opened then (through
//! `/proc/PID/map_files`, else `/proc/PID/root`, and checked against the mapping's dev:ino), so
//! a file deleted or replaced later still symbolizes correctly. At the window's end the
//! stacks no record carried (threads blocked at the end) are read too, then every frame is
//! symbolized: user frames from the files' ELF symbol tables (`.symtab`, else `.dynsym`; Rust
//! and C++ names demangled), kernel frames from `/proc/kallsyms`. The resulting [`Symbols`]
//! are all a flamegraph takes from outside the trace; trace files record them.
//!
//! Frames that cannot be named say why: `[file]` (an address in a mapped file without a
//! covering symbol, e.g. a stripped binary), `[vdso]`, `[unknown]` (no executable mapping:
//! JIT code, or a broken frame-pointer chain), `[kernel]` (the kernel stack, when
//! `/proc/kallsyms` hides addresses).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::MetadataExt as _;

use aya::maps::{MapData, StackTraceMap};
use object::{Object as _, ObjectSegment as _, SymbolKind};
use procctx::ProcKey;
use whytime_abi::{
    EV_EPISODE, EV_EXEC, EV_EXIT, EV_FORK, EV_SAMPLE, EpisodeRecord, EvHeader, ExitRecord,
    ForkRecord, SampleRecord,
};

use crate::timeline::{SegKind, StackIds, Trace};

/// A user stack: the process lifetime and image it was taken in (see [`StackIds::image`])
/// and its id in the kernel's `stacks` map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserKey {
    /// The process.
    pub proc: ProcKey,
    /// Its image.
    pub image: u32,
    /// Stack id.
    pub id: u32,
}

impl UserKey {
    /// The user stack `ids` refers to in process `proc`, if it refers to one.
    pub fn of(proc: ProcKey, ids: StackIds) -> Option<Self> {
        Some(Self {
            proc,
            image: ids.image,
            id: stack_id(ids.user)?,
        })
    }
}

/// The `stacks` map id an encoded stack reference (`TaskState::user_stack`) names.
pub fn stack_id(encoded: i32) -> Option<u32> {
    u32::try_from(encoded).ok()?.checked_sub(1)
}

/// Symbolized stacks, frames outermost first: everything a flamegraph needs besides the
/// trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Symbols {
    /// User stacks.
    pub user: BTreeMap<UserKey, Vec<String>>,
    /// Kernel stacks by `stacks` map id, BPF and tracing frames removed.
    pub kernel: BTreeMap<u32, Vec<String>>,
}

/// Where a user address points.
#[derive(Clone, Copy, Debug)]
enum Loc {
    /// At `offset` in mapped file `file` (an index into [`Collector::files`]).
    File { file: usize, offset: u64 },
    /// In a named special mapping (`[vdso]`).
    Special(&'static str),
    /// In no executable mapping.
    Unknown,
}

/// What a mapping maps.
#[derive(Clone, Debug)]
enum Backing {
    /// A file: dev (`st_dev` encoding), inode, path as `/proc/PID/maps` shows it.
    File { dev: u64, ino: u64, path: String },
    /// A named special mapping.
    Special(&'static str),
    /// Anonymous memory, heap, stack.
    Anon,
}

/// One line of `/proc/PID/maps`.
#[derive(Clone, Debug)]
struct Mapping {
    start: u64,
    end: u64,
    /// File offset of `start`.
    offset: u64,
    exec: bool,
    backing: Backing,
}

/// The memory map of one process image.
#[derive(Debug)]
struct Image {
    /// Which process and image.
    key: (ProcKey, u32),
    /// Mappings by start address.
    maps: Vec<Mapping>,
}

/// A mapped file, opened while a process mapped it.
#[derive(Debug)]
struct MappedFile {
    /// Its base name, for frames without a symbol.
    name: String,
    /// The open file, checked to be the mapped one; `None` if it could not be opened.
    file: Option<File>,
}

/// Collects and normalizes stacks during a live run.
pub struct Collector {
    map: StackTraceMap<MapData>,
    /// The current image of each live process, by pid.
    images: HashMap<u32, Image>,
    /// Normalized user stacks, outermost frame first.
    stacks: HashMap<UserKey, Vec<Loc>>,
    files: Vec<MappedFile>,
    /// `(dev, ino)` → index into `files`.
    file_ids: HashMap<(u64, u64), usize>,
    /// The kernel's symbols, read while whytime's programs are loaded.
    kallsyms: Kallsyms,
}

impl std::fmt::Debug for Collector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Collector")
            .field("images", &self.images.len())
            .field("stacks", &self.stacks.len())
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl Collector {
    /// A collector reading the kernel's `stacks` map.
    pub fn new(map: StackTraceMap<MapData>) -> Self {
        Self {
            map,
            images: HashMap::new(),
            stacks: HashMap::new(),
            files: Vec::new(),
            file_ids: HashMap::new(),
            kallsyms: Kallsyms::default(),
        }
    }

    /// Reads `/proc/kallsyms` for [`finish`](Self::finish). Called before the programs are
    /// detached: kernel stacks taken at `sched_switch` start in whytime's own BPF program,
    /// whose frames are only named (and then dropped) while it is loaded.
    pub fn read_kallsyms(&mut self) {
        self.kallsyms = Kallsyms::read();
        if !self.kallsyms.readable() {
            log::warn!(
                "kernel addresses are hidden (/proc/kallsyms): kernel frames show as [kernel]; \
                 run with sudo or set kernel.kptr_restrict=0 and kernel.perf_event_paranoid=1"
            );
        }
    }

    /// Follows a ring buffer record `trace` has just ingested: tracks process images, and
    /// normalizes a user stack it carries the first time it is seen.
    pub fn observe(&mut self, trace: &Trace, bytes: &[u8]) {
        let Some(hdr) = wire::from_bytes::<EvHeader>(bytes) else {
            return;
        };
        match hdr.kind {
            EV_EXEC => {
                if let Some(key) = trace.current_image(hdr.tgid) {
                    self.read_maps(hdr.tgid, key);
                }
            }
            EV_FORK => {
                let Some(r) = wire::from_bytes::<ForkRecord>(bytes) else {
                    return;
                };
                // A new process starts as a copy of its parent's address space.
                if r.child_tgid != hdr.tgid
                    && let Some(key) = trace.current_image(r.child_tgid)
                    && let Some(maps) = self.images.get(&hdr.tgid).map(|image| image.maps.clone())
                {
                    self.images.insert(r.child_tgid, Image { key, maps });
                }
            }
            EV_EXIT => {
                if wire::from_bytes::<ExitRecord>(bytes).is_some_and(|r| r.group_dead != 0) {
                    self.images.remove(&hdr.tgid);
                }
            }
            EV_EPISODE | EV_SAMPLE => {
                let user = if hdr.kind == EV_SAMPLE {
                    wire::from_bytes::<SampleRecord>(bytes).map(|r| r.user_stack)
                } else {
                    wire::from_bytes::<EpisodeRecord>(bytes).map(|r| r.user_stack)
                };
                // The image the timeline filed the stack under: the process's current one.
                let Some((proc, image)) = trace.current_image(hdr.tgid) else {
                    return;
                };
                if let Some(id) = user.and_then(stack_id) {
                    let key = UserKey { proc, image, id };
                    if !self.stacks.contains_key(&key) {
                        self.resolve(key, true);
                    }
                }
            }
            _ => {}
        }
    }

    /// Reads the stacks the trace refers to that no record brought (and kernel stacks), then
    /// symbolizes everything. Stacks that cannot be read are left out (`[stack lost]`).
    pub fn finish(mut self, trace: &Trace) -> Symbols {
        let (users, kernels) = referenced(trace);
        for &key in &users {
            if !self.stacks.contains_key(&key) {
                let current = trace.current_image(key.proc.pid) == Some((key.proc, key.image));
                self.resolve(key, current);
            }
        }
        let mut elves: Vec<Option<Option<ElfSymbols>>> = Vec::new();
        elves.resize_with(self.files.len(), || None);
        let mut symbols = Symbols::default();
        for key in users {
            // A valid id never names an empty stack (that is -EFAULT): empty = unreadable.
            let Some(locs) = self.stacks.get(&key).filter(|locs| !locs.is_empty()) else {
                continue;
            };
            let frames = locs
                .iter()
                .map(|loc| match *loc {
                    Loc::File { file, offset } => {
                        let elf = elves[file].get_or_insert_with(|| {
                            self.files[file].file.as_ref().and_then(ElfSymbols::load)
                        });
                        elf.as_ref()
                            .and_then(|elf| elf.name(offset))
                            .unwrap_or_else(|| format!("[{}]", self.files[file].name))
                    }
                    Loc::Special(name) => name.to_owned(),
                    Loc::Unknown => "[unknown]".to_owned(),
                })
                .collect();
            symbols.user.insert(key, collapse_unknown(frames));
        }
        for id in kernels {
            let ips = self.read_stack(id);
            if !ips.is_empty() {
                symbols.kernel.insert(id, self.kallsyms.symbolize(&ips));
            }
        }
        symbols
    }

    /// The addresses of stack `id`, innermost first; empty when it cannot be read.
    fn read_stack(&self, id: u32) -> Vec<u64> {
        match self.map.get(&id, 0) {
            Ok(stack) => stack.frames().iter().map(|frame| frame.ip).collect(),
            Err(err) => {
                log::debug!("reading stack {id}: {err}");
                Vec::new()
            }
        }
    }

    /// Reads and normalizes user stack `key`; `current` says its image is the process's
    /// current one, so `/proc/PID/maps` describes it.
    fn resolve(&mut self, key: UserKey, current: bool) {
        let pid = key.proc.pid;
        let image = (key.proc, key.image);
        let ips = self.read_stack(key.id);
        let mut refreshed = false;
        let mut locs = Vec::with_capacity(ips.len());
        for (depth, &ip) in ips.iter().enumerate() {
            // Return addresses point past their call instruction; the byte before is in it.
            let addr = if depth == 0 { ip } else { ip.saturating_sub(1) };
            let mut found = self.mapping(pid, image, addr);
            if found.is_none() && current && !refreshed {
                // A library mapped since the maps were read (dlopen), or none read yet.
                refreshed = true;
                self.read_maps(pid, image);
                found = self.mapping(pid, image, addr);
            }
            locs.push(found.map_or(Loc::Unknown, |mapping| self.locate(pid, &mapping, addr)));
        }
        locs.reverse();
        self.stacks.insert(key, locs);
    }

    /// The mapping of `image` (process `pid`) containing `addr`.
    fn mapping(&self, pid: u32, image: (ProcKey, u32), addr: u64) -> Option<Mapping> {
        let current = self.images.get(&pid).filter(|current| current.key == image)?;
        let i = current.maps.partition_point(|m| m.start <= addr);
        let mapping = current.maps.get(i.checked_sub(1)?)?;
        (addr < mapping.end).then(|| mapping.clone())
    }

    /// Reads `/proc/PID/maps` as the map of `image`; keeps the old map if it cannot.
    fn read_maps(&mut self, pid: u32, image: (ProcKey, u32)) {
        match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(text) => {
                let mut maps: Vec<Mapping> = text.lines().filter_map(parse_mapping).collect();
                maps.sort_by_key(|m| m.start);
                self.images.insert(pid, Image { key: image, maps });
            }
            Err(err) => log::debug!("reading /proc/{pid}/maps: {err}"),
        }
    }

    /// Where `addr` in `mapping` of process `pid` points.
    fn locate(&mut self, pid: u32, mapping: &Mapping, addr: u64) -> Loc {
        if !mapping.exec {
            return Loc::Unknown;
        }
        match &mapping.backing {
            Backing::File { dev, ino, path } => {
                let file = match self.file_ids.get(&(*dev, *ino)) {
                    Some(&file) => file,
                    None => {
                        let file = self.files.len();
                        self.files.push(open_mapped(pid, mapping, *dev, *ino, path));
                        self.file_ids.insert((*dev, *ino), file);
                        file
                    }
                };
                Loc::File {
                    file,
                    offset: addr - mapping.start + mapping.offset,
                }
            }
            Backing::Special(name) => Loc::Special(name),
            Backing::Anon => Loc::Unknown,
        }
    }
}

/// Every user stack and kernel stack id the trace refers to.
fn referenced(trace: &Trace) -> (BTreeSet<UserKey>, BTreeSet<u32>) {
    let mut users = BTreeSet::new();
    let mut kernels = BTreeSet::new();
    for thread in &trace.threads {
        let proc = trace.procs[thread.proc].key;
        let blocks = thread.segs.iter().filter_map(|seg| match &seg.kind {
            SegKind::Blocked(block) => Some(block.stacks),
            _ => None,
        });
        for ids in thread.samples.iter().map(|s| s.stacks).chain(blocks) {
            users.extend(UserKey::of(proc, ids));
            kernels.extend(stack_id(ids.kernel));
        }
    }
    (users, kernels)
}

/// Parses one `/proc/PID/maps` line: `start-end perms offset major:minor inode [path]`.
fn parse_mapping(line: &str) -> Option<Mapping> {
    let mut fields = line.splitn(6, ' ');
    let (start, end) = fields.next()?.split_once('-')?;
    let perms = fields.next()?;
    let offset = u64::from_str_radix(fields.next()?, 16).ok()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let ino: u64 = fields.next()?.parse().ok()?;
    let path = fields.next().unwrap_or("").trim_start();
    let backing = if ino != 0 && path.starts_with('/') {
        Backing::File {
            dev: libc::makedev(
                u32::from_str_radix(major, 16).ok()?,
                u32::from_str_radix(minor, 16).ok()?,
            ),
            ino,
            path: path.to_owned(),
        }
    } else {
        match path {
            "[vdso]" => Backing::Special("[vdso]"),
            "[vsyscall]" => Backing::Special("[vsyscall]"),
            _ => Backing::Anon,
        }
    };
    Some(Mapping {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        offset,
        exec: perms.as_bytes().get(2) == Some(&b'x'),
        backing,
    })
}

/// Opens the file of `mapping` in process `pid`: the mapping itself through
/// `/proc/PID/map_files` (needs `CAP_SYS_ADMIN`; works for deleted files), else its path
/// inside the process's root, accepted only if it still is inode `dev:ino`.
fn open_mapped(pid: u32, mapping: &Mapping, dev: u64, ino: u64, path: &str) -> MappedFile {
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    let name = path.rsplit('/').next().unwrap_or(path).to_owned();
    let is_it = |file: &File| {
        file.metadata()
            .is_ok_and(|meta| meta.dev() == dev && meta.ino() == ino)
    };
    let mapped = File::open(format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        mapping.start, mapping.end
    ))
    .ok();
    let file = mapped.or_else(|| {
        File::open(format!("/proc/{pid}/root{path}"))
            .ok()
            .filter(is_it)
    });
    if file.is_none() {
        log::debug!("cannot open {path} as mapped by pid {pid}");
    }
    MappedFile { name, file }
}

/// Runs of `[unknown]` frames (a broken frame-pointer chain) as one frame.
fn collapse_unknown(mut frames: Vec<String>) -> Vec<String> {
    frames.dedup_by(|a, b| a == "[unknown]" && b == "[unknown]");
    frames
}

/// The function symbols of an ELF file, for file-offset lookups.
#[derive(Debug)]
struct ElfSymbols {
    /// `PT_LOAD` segments: file offset, file size, virtual address.
    segments: Vec<(u64, u64, u64)>,
    /// Function symbols by address: address, size (0 = up to the next one), raw name.
    symbols: Vec<(u64, u64, String)>,
}

impl ElfSymbols {
    /// Reads the segments and function symbols (`.symtab`, else `.dynsym`) of `file`.
    fn load(file: &File) -> Option<Self> {
        let cache = object::ReadCache::new(file);
        let elf = object::File::parse(&cache).ok()?;
        let segments = elf
            .segments()
            .map(|segment| {
                let (offset, size) = segment.file_range();
                (offset, size, segment.address())
            })
            .collect();
        let mut symbols = functions(elf.symbols());
        if symbols.is_empty() {
            symbols = functions(elf.dynamic_symbols());
        }
        // Sized symbols first among equal addresses (aliases), so a lookup lands on one.
        symbols.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        symbols.dedup_by_key(|s| s.0);
        Some(Self { segments, symbols })
    }

    /// The demangled function at file `offset`.
    fn name(&self, offset: u64) -> Option<String> {
        let &(seg_offset, _, vaddr) = self
            .segments
            .iter()
            .find(|&&(start, size, _)| (start..start + size).contains(&offset))?;
        let addr = offset - seg_offset + vaddr;
        let i = self.symbols.partition_point(|s| s.0 <= addr);
        let (start, size, name) = self.symbols.get(i.checked_sub(1)?)?;
        (*size == 0 || addr < start + size).then(|| demangle(name))
    }
}

/// The defined, addressed function symbols among `symbols`: address, size, raw name.
fn functions<'data>(
    symbols: impl Iterator<Item = impl object::ObjectSymbol<'data>>,
) -> Vec<(u64, u64, String)> {
    symbols
        .filter(|s| s.kind() == SymbolKind::Text && s.is_definition() && s.address() != 0)
        .filter_map(|s| Some((s.address(), s.size(), s.name().ok()?.to_owned())))
        .collect()
}

/// `name` demangled (Rust legacy and v0 without the hash, C++ Itanium), else as is.
fn demangle(name: &str) -> String {
    if let Ok(rust) = rustc_demangle::try_demangle(name) {
        return format!("{rust:#}");
    }
    if name.starts_with("_Z")
        && let Ok(symbol) = cpp_demangle::Symbol::new(name)
        && let Ok(cpp) = symbol.demangle()
    {
        return cpp;
    }
    name.to_owned()
}

/// The kernel's function symbols (`/proc/kallsyms`, text symbols only).
#[derive(Debug, Default)]
pub struct Kallsyms {
    /// Address and name, by address.
    symbols: Vec<(u64, String)>,
}

impl Kallsyms {
    /// Reads `/proc/kallsyms`; empty when unreadable or when the kernel hides addresses
    /// (`kernel.kptr_restrict`, or `perf_event_paranoid` > 1 without `CAP_SYSLOG`).
    pub fn read() -> Self {
        let Ok(file) = File::open("/proc/kallsyms") else {
            return Self::default();
        };
        let mut symbols = Vec::new();
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let mut fields = line.split_ascii_whitespace();
            let (Some(addr), Some(kind), Some(name)) = (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if !matches!(kind, "t" | "T" | "w" | "W") {
                continue;
            }
            match u64::from_str_radix(addr, 16) {
                Ok(0) => return Self::default(),
                Ok(addr) => symbols.push((addr, name.to_owned())),
                Err(_) => {}
            }
        }
        symbols.sort_unstable();
        Self { symbols }
    }

    /// Whether kernel addresses can be named.
    pub fn readable(&self) -> bool {
        !self.symbols.is_empty()
    }

    /// Kernel stack `ips` (innermost first) as frames, outermost first, without the BPF
    /// program and tracing frames above the traced kernel function. One `[kernel]` frame
    /// when unreadable.
    fn symbolize(&self, ips: &[u64]) -> Vec<String> {
        if ips.is_empty() {
            return Vec::new();
        }
        if !self.readable() {
            return vec!["[kernel]".to_owned()];
        }
        let mut frames: Vec<String> = ips
            .iter()
            .enumerate()
            .map(|(depth, &ip)| {
                let addr = if depth == 0 { ip } else { ip.saturating_sub(1) };
                let i = self.symbols.partition_point(|s| s.0 <= addr);
                i.checked_sub(1)
                    .map_or_else(|| "[unknown]".to_owned(), |i| self.symbols[i].1.clone())
            })
            .collect();
        // Through the outermost tracing frame near the leaf: whytime's program itself may be
        // misnamed (with net.core.bpf_jit_kallsyms=0 it has no symbol of its own).
        let tracing = frames
            .iter()
            .take(TRACING_DEPTH)
            .rposition(|name| is_tracing(name))
            .map_or(0, |i| i + 1);
        frames.drain(..tracing);
        frames.reverse();
        collapse_unknown(frames)
    }
}

/// Innermost frames searched for tracing glue: whytime's program, `bpf_trace_run*`, the
/// tracepoint's iterator, plus slack.
const TRACING_DEPTH: usize = 8;

/// Frames of a BPF program and the tracing glue that ran it: the inner end of stacks taken at
/// `sched_switch`, above `__schedule`.
fn is_tracing(name: &str) -> bool {
    ["bpf_prog_", "bpf_trace_run", "__bpf_trace_", "__traceiter_"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
