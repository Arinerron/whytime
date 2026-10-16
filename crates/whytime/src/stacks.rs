//! Stacks for flamegraphs, when stack capture is on (`--flamegraph`, `--folded`).
//!
//! The kernel side refers to stacks: the user and kernel stack of every block (episode
//! records and the final sweep) and of every on-CPU sample (sample records). A reference is
//! an id in one of two stack maps, picked by the capture's generation, or, when that map could
//! not take the stack (bucket collision, full map), a copy in a STACK record sent just before,
//! named by thread and capture time ([`StackKey`]).
//!
//! Generations keep the maps from filling with stale stacks over a long run. Every
//! [`FLIP_NS`] (or when the current map looks a quarter full) the [`Collector`] flips: the
//! programs move to the other, empty map, and once no program uses the old one (an RCU grace
//! period), the old generation's stacks that blocked threads still refer to are read (their
//! episodes come later), the records already reserved are committed (a second grace period)
//! and drained, which reads every stack they refer to, and the old map is emptied for the
//! generation after next.
//!
//! A user address only means something in its process's address space at that time, so the
//! Collector normalizes each user stack as its record arrives, while the process still runs:
//! every address becomes (mapped file, file offset) through a cache of the process image's
//! `/proc/PID/maps` (read at exec, copied at fork, re-read on a miss while that image is
//! current), and each mapped file is opened then (through `/proc/PID/map_files`, else
//! `/proc/PID/root`, and checked against the mapping's dev:ino), so a file deleted or replaced
//! later still symbolizes correctly. Kernel stacks are read as their records arrive too. At
//! the window's end the stacks no record carried (threads blocked at the end) are read, then
//! every distinct stack is symbolized once: user frames from the files' ELF symbol tables
//! (`.symtab`, else `.dynsym`; Rust and C++ names demangled), kernel frames from
//! `/proc/kallsyms`. The resulting [`Symbols`] are all a flamegraph takes from outside the
//! trace; trace files record them.
//!
//! Frames that cannot be named say why: `[file]` (an address in a mapped file without a
//! covering symbol, e.g. a stripped binary), `[vdso]`, `[unknown]` (no executable mapping:
//! JIT code, or a broken frame-pointer chain), `[kernel]` (the kernel stack, when
//! `/proc/kallsyms` hides addresses).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::hash::Hash;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::MetadataExt as _;

use object::{Object as _, ObjectSegment as _, SymbolKind};
use procctx::ProcKey;
use whytime_abi::{
    EV_EPISODE, EV_EXEC, EV_EXIT, EV_FORK, EV_SAMPLE, EV_STACK, EpisodeRecord, EvHeader,
    ExitRecord, ForkRecord, ST_BLOCKED, ST_WOKEN, STACK_INLINE, SampleRecord, StackRecord,
    TaskState,
};

use crate::timeline::{SegKind, StackIds, Trace};
use crate::tracer::{StackMaps, slot};

/// Time between stack generation flips.
const FLIP_NS: u64 = 1_000_000_000;
/// Shortest time between flips started because the map looked a quarter full.
const EARLY_FLIP_NS: u64 = 10_000_000;
/// Test-only override of [`FLIP_NS`] in milliseconds (`WHYTIME_STACK_FLIP_MS`, 1 to 60000).
const FLIP_ENV: &str = "WHYTIME_STACK_FLIP_MS";

/// A stack the kernel captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StackKey {
    /// Stack `id` in `generation`'s stack map.
    Map {
        /// Generation.
        generation: u32,
        /// Stack id.
        id: u32,
    },
    /// The copy in a STACK record of thread `tid`'s stack captured at `at`.
    Inline {
        /// Thread.
        tid: u32,
        /// Capture time.
        at: u64,
        /// Kernel (else user) stack.
        kernel: bool,
    },
}

impl StackKey {
    /// The stack a reference (`TaskState::user_stack` encoding) names, if any: taken by
    /// thread `tid` at `at` in `generation`, a `kernel` or user stack.
    pub fn of(encoded: i32, generation: u32, tid: u32, at: u64, kernel: bool) -> Option<Self> {
        if encoded == STACK_INLINE {
            return Some(Self::Inline { tid, at, kernel });
        }
        let id = u32::try_from(encoded).ok()?.checked_sub(1)?;
        Some(Self::Map { generation, id })
    }

    /// The kernel stack `ids` (taken by thread `tid`) refers to, if any.
    pub fn kernel(tid: u32, ids: StackIds) -> Option<Self> {
        Self::of(ids.kernel, ids.generation, tid, ids.at, true)
    }
}

/// A user stack: the process lifetime and image it was taken in (see [`StackIds::image`])
/// and the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserKey {
    /// The process.
    pub proc: ProcKey,
    /// Its image.
    pub image: u32,
    /// The stack.
    pub stack: StackKey,
}

impl UserKey {
    /// The user stack `ids` (taken by thread `tid` of process `proc`) refers to, if any.
    pub fn of(proc: ProcKey, tid: u32, ids: StackIds) -> Option<Self> {
        Some(Self {
            proc,
            image: ids.image,
            stack: StackKey::of(ids.user, ids.generation, tid, ids.at, false)?,
        })
    }
}

/// Symbolized stacks, frames outermost first: everything a flamegraph needs besides the
/// trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Symbols {
    /// Distinct stacks' frames (one entry serves every key with those frames).
    pub stacks: Vec<Vec<String>>,
    /// User stacks: index into `stacks`.
    pub user: BTreeMap<UserKey, u32>,
    /// Kernel stacks, BPF and tracing frames removed: index into `stacks`.
    pub kernel: BTreeMap<StackKey, u32>,
}

impl Symbols {
    /// Adds a stack's frames; returns its index.
    pub fn push(&mut self, frames: Vec<String>) -> u32 {
        self.stacks.push(frames);
        u32::try_from(self.stacks.len() - 1).unwrap_or(u32::MAX)
    }

    /// The frames of user stack `key`.
    pub fn user(&self, key: &UserKey) -> Option<&[String]> {
        self.frames(self.user.get(key))
    }

    /// The frames of kernel stack `key`.
    pub fn kernel(&self, key: &StackKey) -> Option<&[String]> {
        self.frames(self.kernel.get(key))
    }

    fn frames(&self, index: Option<&u32>) -> Option<&[String]> {
        let index = usize::try_from(*index?).ok()?;
        self.stacks.get(index).map(Vec::as_slice)
    }
}

/// Distinct values, numbered in insertion order.
#[derive(Debug)]
struct Interner<T> {
    values: Vec<T>,
    ids: HashMap<T, u32>,
}

impl<T: Clone + Eq + Hash> Interner<T> {
    fn new() -> Self {
        Self {
            values: Vec::new(),
            ids: HashMap::new(),
        }
    }

    /// The number of `value`, added if new.
    fn id(&mut self, value: T) -> u32 {
        if let Some(&id) = self.ids.get(&value) {
            return id;
        }
        let id = u32::try_from(self.values.len()).unwrap_or(u32::MAX);
        self.ids.insert(value.clone(), id);
        self.values.push(value);
        id
    }
}

/// Where a user address points.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// Collects and normalizes stacks during a live run, and flips stack generations.
#[derive(Debug)]
pub struct Collector {
    maps: StackMaps,
    /// The generation the programs store into.
    generation: u32,
    /// Per map slot, the oldest generation whose stacks it may hold: generation `g`'s ids
    /// can be read while `since[slot(g)] <= g`.
    since: [u32; 2],
    /// Whether every barrier of the flip in progress worked, so the old map may be emptied.
    barriers_held: bool,
    /// Time between flips.
    interval: u64,
    /// When the last flip ended, and when the next is due.
    flipped_at: u64,
    flip_at: u64,
    /// Ids of the current generation read so far: a lower bound of its map's fill.
    fresh: HashSet<u32>,
    /// Flips done and stacks they emptied (debug log).
    flips: u32,
    cleared: usize,
    /// The current image of each live process, by pid.
    images: HashMap<u32, Image>,
    /// Old generations' stacks that blocked threads referred to at a flip, innermost first.
    kept: HashMap<StackKey, Vec<u64>>,
    /// Normalized user stacks: index into `locs`; `None` when unreadable.
    user: HashMap<UserKey, Option<u32>>,
    /// Distinct normalized user stacks, outermost frame first.
    locs: Interner<Vec<Loc>>,
    /// Kernel stacks: index into `kips`; `None` when unreadable.
    kernel: HashMap<StackKey, Option<u32>>,
    /// Distinct kernel stacks' addresses, innermost first.
    kips: Interner<Vec<u64>>,
    files: Vec<MappedFile>,
    /// `(dev, ino)` → index into `files`.
    file_ids: HashMap<(u64, u64), usize>,
    /// The kernel's symbols, read while whytime's programs are loaded.
    kallsyms: Kallsyms,
}

impl Collector {
    /// A collector reading the stack maps `maps` (generation 0 current), starting at `now`.
    pub fn new(maps: StackMaps, now: u64) -> Self {
        let interval = std::env::var(FLIP_ENV)
            .ok()
            .and_then(|ms| ms.parse::<u64>().ok())
            .map_or(FLIP_NS, |ms| ms.clamp(1, 60_000) * 1_000_000);
        Self {
            maps,
            generation: 0,
            since: [0, 1],
            barriers_held: true,
            interval,
            flipped_at: now,
            flip_at: now.saturating_add(interval),
            fresh: HashSet::new(),
            flips: 0,
            cleared: 0,
            images: HashMap::new(),
            kept: HashMap::new(),
            user: HashMap::new(),
            locs: Interner::new(),
            kernel: HashMap::new(),
            kips: Interner::new(),
            files: Vec::new(),
            file_ids: HashMap::new(),
            kallsyms: Kallsyms::default(),
        }
    }

    /// Whether a flip is due at `now`: the interval passed, or the current map looks a
    /// quarter full.
    pub fn flip_due(&self, now: u64) -> bool {
        let filling = self.fresh.len().saturating_mul(4)
            >= usize::try_from(self.maps.capacity).unwrap_or(usize::MAX);
        now >= self.flip_at || (filling && now >= self.flipped_at.saturating_add(EARLY_FLIP_NS))
    }

    /// When the next flip is due (the event loop wakes up for it).
    pub fn next_flip(&self) -> u64 {
        self.flip_at
    }

    /// Starts a flip at `now`: the programs store into the next generation's (empty) map
    /// from now on, and once this returns none still uses the old one. Then
    /// [`keep`](Self::keep), drain the ring through [`observe`](Self::observe), and
    /// [`retire`](Self::retire). False when the generation could not be changed (no flip;
    /// the next try is an interval later).
    pub fn advance(&mut self, now: u64) -> bool {
        let next = self.generation + 1;
        if let Err(err) = self.maps.set_generation(next) {
            log::debug!("starting stack generation {next}: {err}");
            self.flipped_at = now;
            self.flip_at = now.saturating_add(self.interval);
            return false;
        }
        self.generation = next;
        self.barriers_held = self.barrier();
        true
    }

    /// Reads the old generation's stacks that threads blocked in it still refer to (their
    /// episodes, or the sweep, come later), then waits until every record already reserved is
    /// committed, so the drain that follows sees every other reference.
    pub fn keep(&mut self, tasks: &[(u32, TaskState)]) {
        let old = self.generation - 1;
        for (_, state) in tasks {
            if !matches!(state.state, ST_BLOCKED | ST_WOKEN) || state.stack_gen != old {
                continue;
            }
            for encoded in [state.user_stack, state.kernel_stack] {
                // Copies (STACK_INLINE) are not in a map: their records came at the block.
                let Some(key @ StackKey::Map { id, .. }) = StackKey::of(encoded, old, 0, 0, false)
                else {
                    continue;
                };
                if !self.kept.contains_key(&key)
                    && let Some(ips) = self.read_map(old, id)
                {
                    self.kept.insert(key, ips);
                }
            }
        }
        self.barriers_held &= self.barrier();
    }

    /// Ends a flip at `now`: empties the old generation's map for the generation after next,
    /// unless a barrier failed (its stacks then stay: only more collisions).
    pub fn retire(&mut self, now: u64) {
        let old = self.generation - 1;
        if self.barriers_held {
            self.cleared += self.maps.clear(old);
            self.since[slot(old)] = old + 2;
        }
        self.fresh.clear();
        self.flips += 1;
        self.flipped_at = now;
        self.flip_at = now.saturating_add(self.interval);
    }

    /// Waits for running programs; false (logged) when it could not.
    fn barrier(&mut self) -> bool {
        match self.maps.barrier() {
            Ok(()) => true,
            Err(err) => {
                log::debug!("stack map barrier: {err}");
                false
            }
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

    /// Follows a ring buffer record `trace` has just ingested: tracks process images, keeps
    /// stack copies, and reads the stacks a record refers to the first time they are seen.
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
            EV_STACK => {
                if let Some(r) = wire::from_bytes::<StackRecord>(bytes) {
                    self.copy(trace, hdr, r);
                }
            }
            EV_EPISODE | EV_SAMPLE => {
                let refs = if hdr.kind == EV_SAMPLE {
                    wire::from_bytes::<SampleRecord>(bytes)
                        .map(|r| (r.user_stack, r.kernel_stack, r.stack_gen, hdr.ts))
                } else {
                    wire::from_bytes::<EpisodeRecord>(bytes)
                        .map(|r| (r.user_stack, r.kernel_stack, r.stack_gen, r.block_ts))
                };
                let Some((user, kernel, generation, at)) = refs else {
                    return;
                };
                if let Some(stack) = StackKey::of(kernel, generation, hdr.tid, at, true) {
                    self.resolve_kernel(stack);
                }
                // The image the timeline filed the stack under: the process's current one.
                if let Some((proc, image)) = trace.current_image(hdr.tgid)
                    && let Some(stack) = StackKey::of(user, generation, hdr.tid, at, false)
                {
                    self.resolve_user(UserKey { proc, image, stack }, true);
                }
            }
            _ => {}
        }
    }

    /// Keeps the stack copy `r` (thread and capture time in `hdr`) under its
    /// [`StackKey::Inline`]; a user stack is normalized now, in the process's current image.
    fn copy(&mut self, trace: &Trace, hdr: &EvHeader, r: &StackRecord) {
        let nr = usize::try_from(r.nr).map_or(0, |nr| nr.min(r.ips.len()));
        let ips = &r.ips[..nr];
        let kernel = r.kernel != 0;
        let stack = StackKey::Inline {
            tid: hdr.tid,
            at: hdr.ts,
            kernel,
        };
        if kernel {
            let id = (!ips.is_empty()).then(|| self.kips.id(ips.to_vec()));
            self.kernel.insert(stack, id);
        } else if let Some((proc, image)) = trace.current_image(hdr.tgid) {
            let id = (!ips.is_empty()).then(|| {
                let locs = self.normalize(proc.pid, (proc, image), ips, true);
                self.locs.id(locs)
            });
            self.user.insert(UserKey { proc, image, stack }, id);
        }
    }

    /// Reads the stacks the trace refers to that no record brought (threads blocked at the
    /// end), then symbolizes every distinct stack once. Stacks that cannot be read are left
    /// out (`[stack lost]`).
    pub fn finish(mut self, trace: &Trace) -> Symbols {
        log::debug!(
            "stack generations: {} flips emptied {} map entries; {} stacks kept across flips",
            self.flips,
            self.cleared,
            self.kept.len()
        );
        let (users, kernels) = referenced(trace);
        for &key in &users {
            let current = trace.current_image(key.proc.pid) == Some((key.proc, key.image));
            self.resolve_user(key, current);
        }
        for &key in &kernels {
            self.resolve_kernel(key);
        }
        let mut elves: Vec<Option<Option<ElfSymbols>>> = Vec::new();
        elves.resize_with(self.files.len(), || None);
        let mut names = Interner::new();
        let mut user_names: HashMap<u32, u32> = HashMap::new();
        let mut symbols = Symbols::default();
        for key in users {
            let Some(&Some(locs)) = self.user.get(&key) else {
                continue;
            };
            let index = *user_names.entry(locs).or_insert_with(|| {
                let frames = self.locs.values[usize::try_from(locs).unwrap_or(usize::MAX)]
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
                names.id(collapse_unknown(frames))
            });
            symbols.user.insert(key, index);
        }
        let mut kernel_names: HashMap<u32, u32> = HashMap::new();
        for key in kernels {
            let Some(&Some(ips)) = self.kernel.get(&key) else {
                continue;
            };
            let index = *kernel_names.entry(ips).or_insert_with(|| {
                let ips = &self.kips.values[usize::try_from(ips).unwrap_or(usize::MAX)];
                names.id(self.kallsyms.symbolize(ips))
            });
            symbols.kernel.insert(key, index);
        }
        symbols.stacks = names.values;
        symbols
    }

    /// The addresses of `stack`, innermost first: kept at a flip, or read from its
    /// generation's map while it holds that generation. `None` when unreadable (copies are
    /// taken as their STACK record arrives, never here).
    fn raw(&mut self, stack: StackKey) -> Option<Vec<u64>> {
        let StackKey::Map { generation, id } = stack else {
            return None;
        };
        match self.kept.get(&stack) {
            Some(ips) => Some(ips.clone()),
            None => self.read_map(generation, id),
        }
        .filter(|ips| !ips.is_empty())
    }

    /// Stack `id` of `generation`, if its map still holds that generation.
    fn read_map(&mut self, generation: u32, id: u32) -> Option<Vec<u64>> {
        if generation > self.generation || self.since[slot(generation)] > generation {
            return None;
        }
        if generation == self.generation {
            self.fresh.insert(id);
        }
        self.maps.read(generation, id)
    }

    /// Reads kernel stack `stack` unless known.
    fn resolve_kernel(&mut self, stack: StackKey) {
        if self.kernel.contains_key(&stack) {
            return;
        }
        let id = self.raw(stack).map(|ips| self.kips.id(ips));
        self.kernel.insert(stack, id);
    }

    /// Reads and normalizes user stack `key` unless known; `current` says its image is the
    /// process's current one, so `/proc/PID/maps` describes it.
    fn resolve_user(&mut self, key: UserKey, current: bool) {
        if self.user.contains_key(&key) {
            return;
        }
        let id = self.raw(key.stack).map(|ips| {
            let locs = self.normalize(key.proc.pid, (key.proc, key.image), &ips, current);
            self.locs.id(locs)
        });
        self.user.insert(key, id);
    }

    /// User addresses `ips` (innermost first) of process `pid`'s `image` as locations,
    /// outermost first.
    fn normalize(
        &mut self,
        pid: u32,
        image: (ProcKey, u32),
        ips: &[u64],
        current: bool,
    ) -> Vec<Loc> {
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
        locs
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

/// Every user and kernel stack the trace refers to.
fn referenced(trace: &Trace) -> (BTreeSet<UserKey>, BTreeSet<StackKey>) {
    let mut users = BTreeSet::new();
    let mut kernels = BTreeSet::new();
    for thread in &trace.threads {
        let proc = trace.procs[thread.proc].key;
        let blocks = thread.segs.iter().filter_map(|seg| match &seg.kind {
            SegKind::Blocked(block) => Some(block.stacks),
            _ => None,
        });
        for ids in thread.samples.iter().map(|s| s.stacks).chain(blocks) {
            users.extend(UserKey::of(proc, thread.tid, ids));
            kernels.extend(StackKey::kernel(thread.tid, ids));
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
