//! Turns "thread blocked in syscall N on descriptor D" into a resource class and subject.
//!
//! File paths come from the kernel, which walks the file's dentries when the syscall first
//! blocks, so they survive the process. When that walk could not reach the root, the path
//! comes from `/proc/<pid>/fd/<fd>` while the record is processed, trusted only if the file it
//! names has the device and inode the kernel reported; then from the walk's trailing
//! components (`…/dir`); otherwise the subject is `dev M:m ino N`. The `/proc` lookup is the
//! classifier's only outside input, behind [`FdTarget`] so trace files can record and replay
//! it ([`crate::record`]).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use whytime_abi::{
    ANON_INODE_FS_MAGIC, NR_NONE, SYSD_DESCRIBED, SYSD_PATH_ROOTED, SYSD_PATH_TRUNCATED,
    SysDetail, SysInfo,
};

use crate::sys::{Kind, SyscallTable};

/// Where wall time went. Serialized in lower case (`"fsync"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// The wrapped command's own process was on a CPU.
    Cpu,
    /// The command waited for a descendant that was on a CPU.
    Child,
    /// Runnable, waiting for a CPU (preempted, or woken and not yet scheduled).
    Runqueue,
    /// Timer sleep.
    Sleep,
    /// Waiting for data to become durable: `fsync` and friends, `O_SYNC`/`O_DSYNC` writes.
    Fsync,
    /// Other file and filesystem I/O.
    File,
    /// Waiting for asynchronous I/O completions (`io_uring_enter`, `io_getevents`).
    Aio,
    /// Internet sockets.
    Net,
    /// Pipes, FIFOs, UNIX and other local sockets, eventfds, SysV and POSIX IPC.
    Ipc,
    /// Futex waits: locks, condition variables, thread joins.
    Futex,
    /// File lock waits (`flock`, `fcntl(F_SETLKW)`).
    Lock,
    /// `poll`/`select`/`epoll_wait` with no single resource behind it.
    Poll,
    /// Waiting for a signal.
    Signal,
    /// Terminal and other character-device I/O.
    Tty,
    /// Anything else, including time whytime could not observe.
    Other,
}

/// The resource a block waited on, beyond its class.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// Nothing beyond the class: the blocked process names it.
    Process,
    /// Directory of the file (tilde-abbreviated), or the file itself for devices and
    /// directories.
    Path(Arc<str>),
    /// A file whose path could not be resolved.
    Inode {
        /// Kernel `dev_t`.
        dev: u32,
        /// Inode number.
        ino: u64,
    },
    /// Peer of an internet socket.
    Peer(SocketAddr),
    /// An internet socket without a peer (listening or not yet connected).
    Unconnected,
    /// The syscall, when it explains more than the class.
    Syscall(&'static str),
    /// A kernel object whytime names by kind (`inotify`, `fanotify`).
    Named(&'static str),
    /// A syscall number whytime has no name for.
    UnknownSyscall(i32),
    /// Off-CPU outside any syscall: page faults, reclaim, kernel locks.
    NoSyscall,
    /// Stopped by a signal or a tracer.
    Stopped,
    /// Blocked since before attach, in a syscall `/proc` would not show.
    Unreadable,
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process => Ok(()),
            Self::Path(path) => f.write_str(path),
            Self::Inode { dev, ino } => write!(f, "dev {}:{} ino {ino}", dev >> 20, dev & 0xf_ffff),
            Self::Peer(addr) => write!(f, "{addr}"),
            Self::Unconnected => f.write_str("unconnected socket"),
            Self::Syscall(name) => write!(f, "in {name}"),
            Self::Named(name) => f.write_str(name),
            Self::UnknownSyscall(nr) => write!(f, "in syscall {nr}"),
            Self::NoSyscall => f.write_str("outside syscalls (page faults, kernel locks)"),
            Self::Stopped => f.write_str("stopped (signal or tracer)"),
            Self::Unreadable => f.write_str("blocked since attach, syscall unreadable"),
        }
    }
}

/// A classified block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocked {
    /// Resource class.
    pub class: Class,
    /// Resource within the class.
    pub subject: Subject,
    /// Socket inode for internet sockets, to count distinct connections.
    pub socket: Option<u64>,
}

const S_IFSOCK: u32 = 0o140_000;
const S_IFREG: u32 = 0o100_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;
const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const TASK_STOPPED: u32 = 0x4;
const TASK_TRACED: u32 = 0x8;
/// `O_DSYNC`; `O_SYNC` includes it.
const O_DSYNC: u32 = 0o10_000;
/// [`SysInfo::nr`] of a thread found blocked at attach whose `/proc/<tid>/syscall` could not
/// be read. Only attach mode writes it; the kernel side never does.
pub const NR_UNREADABLE: i32 = -2;

/// What a descriptor's `/proc` link names: the classifier's only external lookup.
pub trait FdTarget: fmt::Debug {
    /// The target of `/proc/<tgid>/fd/<fd>`, if that link still names the file with inode
    /// `ino` on `dev` (kernel `dev_t`).
    fn fd_target(&self, tgid: u32, fd: i32, dev: u32, ino: u64) -> Option<PathBuf>;
}

/// [`FdTarget`] reading `/proc`.
#[derive(Debug)]
pub struct ProcFd;

impl FdTarget for ProcFd {
    fn fd_target(&self, tgid: u32, fd: i32, dev: u32, ino: u64) -> Option<PathBuf> {
        let link = PathBuf::from(format!("/proc/{tgid}/fd/{fd}"));
        let meta = std::fs::metadata(&link).ok()?;
        let dev = u64::from(dev);
        let same_file = meta.ino() == ino
            && libc::major(meta.dev()) == u32::try_from(dev >> 20).ok()?
            && libc::minor(meta.dev()) == u32::try_from(dev & 0xf_ffff).ok()?;
        if !same_file {
            return None;
        }
        std::fs::read_link(&link).ok()
    }
}

/// Subject path of one `(dev, ino)`, as far as it is known.
#[derive(Clone, Debug)]
enum Known {
    /// The whole path, from the kernel walk or `/proc`.
    Full(Arc<str>),
    /// Trailing components only (`…/dir`); `/proc` failed. A whole kernel path replaces it.
    Tail(Arc<str>),
    /// Nothing; `/proc` failed.
    Unresolved,
}

/// Classifies blocks, resolving and caching file paths.
#[derive(Debug)]
pub struct Classifier {
    syscalls: SyscallTable,
    home: Option<PathBuf>,
    files: Box<dyn FdTarget>,
    /// `(dev, ino)` → subject path.
    paths: HashMap<(u32, u64), Known>,
}

impl Classifier {
    /// `home` is abbreviated to `~` in paths; `files` resolves descriptors the kernel's path
    /// walk could not.
    pub fn new(syscalls: SyscallTable, home: Option<PathBuf>, files: Box<dyn FdTarget>) -> Self {
        Self {
            syscalls,
            home,
            files,
            paths: HashMap::new(),
        }
    }

    /// Classifies a block of process `tgid` in `sys` (with the kernel's `detail` on it),
    /// entered with scheduler state `block_state`.
    pub fn classify(
        &mut self,
        tgid: u32,
        sys: &SysInfo,
        detail: &SysDetail,
        block_state: u32,
    ) -> Blocked {
        let plain = |class, subject| Blocked {
            class,
            subject,
            socket: None,
        };
        if sys.nr == NR_UNREADABLE {
            return plain(Class::Other, Subject::Unreadable);
        }
        if sys.nr == NR_NONE {
            let subject = if block_state & (TASK_STOPPED | TASK_TRACED) != 0 {
                Subject::Stopped
            } else {
                Subject::NoSyscall
            };
            return plain(Class::Other, subject);
        }
        let Some(syscall) = self.syscalls.get(sys.nr) else {
            return plain(Class::Other, Subject::UnknownSyscall(sys.nr));
        };
        let fd = Descriptor { sys, detail };
        match syscall.kind {
            Kind::Sleep => plain(Class::Sleep, Subject::Process),
            Kind::Futex => plain(Class::Futex, Subject::Process),
            Kind::Wait => plain(Class::Child, Subject::Process),
            Kind::Poll => plain(Class::Poll, Subject::Process),
            Kind::Signal => plain(Class::Signal, Subject::Process),
            Kind::Aio => plain(Class::Aio, Subject::Process),
            Kind::Ipc => plain(Class::Ipc, Subject::Process),
            Kind::PathFs => plain(Class::File, Subject::Syscall(syscall.name)),
            Kind::Other => plain(Class::Other, Subject::Syscall(syscall.name)),
            Kind::Fsync => plain(Class::Fsync, self.file_or_syscall(tgid, fd, syscall.name)),
            Kind::Lock => plain(Class::Lock, self.file_or_syscall(tgid, fd, syscall.name)),
            Kind::Fcntl if waits_for_lock(detail.args[1]) => {
                plain(Class::Lock, self.file_or_syscall(tgid, fd, syscall.name))
            }
            Kind::Connect | Kind::Fcntl => self.by_descriptor(tgid, fd, syscall.name, false),
            Kind::FdIo { write } => self.by_descriptor(tgid, fd, syscall.name, write),
        }
    }

    fn by_descriptor(
        &mut self,
        tgid: u32,
        fd: Descriptor<'_>,
        name: &'static str,
        write: bool,
    ) -> Blocked {
        let sys = fd.sys;
        let (class, subject) = if fd.is_anon() {
            anon_inode(fd.leaf(), name)
        } else {
            match fd.mode() {
                S_IFREG | S_IFBLK | S_IFDIR => {
                    let durable = write && sys.f_flags & O_DSYNC != 0;
                    let class = if durable { Class::Fsync } else { Class::File };
                    (class, self.file_subject(tgid, fd))
                }
                S_IFSOCK => match sys.family {
                    AF_INET | AF_INET6 => {
                        let subject = peer(sys).map_or(Subject::Unconnected, Subject::Peer);
                        return Blocked {
                            class: Class::Net,
                            subject,
                            socket: Some(sys.ino),
                        };
                    }
                    AF_UNIX => (Class::Ipc, Subject::Process),
                    _ => (Class::Ipc, Subject::Syscall(name)),
                },
                S_IFIFO => (Class::Ipc, Subject::Process),
                S_IFCHR => (Class::Tty, Subject::Process),
                _ => (Class::Other, Subject::Syscall(name)),
            }
        };
        Blocked {
            class,
            subject,
            socket: None,
        }
    }

    /// The file's subject for regular files, directories and block devices, else the syscall.
    fn file_or_syscall(&mut self, tgid: u32, fd: Descriptor<'_>, name: &'static str) -> Subject {
        if !fd.is_anon() && matches!(fd.mode(), S_IFREG | S_IFBLK | S_IFDIR) {
            self.file_subject(tgid, fd)
        } else {
            Subject::Syscall(name)
        }
    }

    /// The directory holding the descriptor's file (or the device/directory itself).
    fn file_subject(&mut self, tgid: u32, fd: Descriptor<'_>) -> Subject {
        let Descriptor { sys, detail } = fd;
        let key = (sys.dev, sys.ino);
        let rooted = detail.flags & SYSD_PATH_ROOTED != 0;
        let tried = match self.paths.get(&key) {
            Some(Known::Full(path)) => return Subject::Path(Arc::clone(path)),
            Some(Known::Tail(path)) if !rooted => return Subject::Path(Arc::clone(path)),
            known => known.is_some(),
        };
        let found = if rooted {
            Known::Full(self.shown(&fd.kernel_path(), sys.mode))
        } else if let Some(path) = (!tried).then(|| self.resolve(tgid, sys)).flatten() {
            Known::Full(path)
        } else if let Some(tail) = fd.kernel_tail() {
            Known::Tail(tail.into())
        } else {
            Known::Unresolved
        };
        self.paths.insert(key, found.clone());
        match found {
            Known::Full(path) | Known::Tail(path) => Subject::Path(path),
            Known::Unresolved => Subject::Inode {
                dev: sys.dev,
                ino: sys.ino,
            },
        }
    }

    /// What [`FdTarget`] says `sys.fd` of `tgid` names, if it is a location.
    fn resolve(&self, tgid: u32, sys: &SysInfo) -> Option<Arc<str>> {
        let target = self.files.fd_target(tgid, sys.fd, sys.dev, sys.ino)?;
        let target = target.to_string_lossy();
        // Pseudo files (`anon_inode:[pidfd]`) have no location.
        if !target.starts_with('/') {
            return None;
        }
        let path = Path::new(target.strip_suffix(" (deleted)").unwrap_or(&target));
        Some(self.shown(path, sys.mode))
    }

    /// How a file's path is shown: its directory for regular files, `~`-abbreviated.
    fn shown(&self, path: &Path, mode: u32) -> Arc<str> {
        let shown = if mode == S_IFREG {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        Arc::from(abbreviate_home(shown, self.home.as_deref()))
    }
}

/// What the kernel reported about a blocked syscall's descriptor.
#[derive(Clone, Copy)]
struct Descriptor<'a> {
    sys: &'a SysInfo,
    detail: &'a SysDetail,
}

impl<'a> Descriptor<'a> {
    /// The kernel described this syscall's descriptor; otherwise `sys` beyond `nr` and the
    /// path are left over from an earlier syscall.
    fn described(self) -> bool {
        self.detail.flags & SYSD_DESCRIBED != 0
    }

    /// `S_IFMT` bits; 0 when unknown.
    fn mode(self) -> u32 {
        if self.described() { self.sys.mode } else { 0 }
    }

    /// An anonymous inode (eventfd, timerfd, ...), recognized by filesystem rather than by
    /// mode, which carries no usable file type for them.
    fn is_anon(self) -> bool {
        self.described() && self.detail.magic == ANON_INODE_FS_MAGIC
    }

    /// Captured name components, leaf first.
    fn components(self) -> impl DoubleEndedIterator<Item = &'a [u8]> {
        let detail = self.detail;
        let len = usize::try_from(detail.path_len).map_or(0, |n| n.min(detail.path.len()));
        let len = if self.described() { len } else { 0 };
        detail.path[..len].split(|&b| b == 0).filter(|c| !c.is_empty())
    }

    /// The file's own name (`[eventfd]` for anonymous inodes).
    fn leaf(self) -> Option<&'a [u8]> {
        self.components().next()
    }

    /// The absolute path of a walk that reached the root.
    fn kernel_path(self) -> PathBuf {
        let mut path = Vec::with_capacity(self.detail.path.len());
        for name in self.components().rev() {
            path.push(b'/');
            path.extend_from_slice(name);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        PathBuf::from(OsStr::from_bytes(&path))
    }

    /// `…/a/b` from a truncated walk: the trailing directories (regular files lose their own
    /// name, as in [`Classifier::shown`]); `None` if nothing is left.
    fn kernel_tail(self) -> Option<String> {
        if self.detail.flags & SYSD_PATH_TRUNCATED == 0 {
            return None;
        }
        let skip = usize::from(self.sys.mode == S_IFREG);
        let names: Vec<_> = self.components().skip(skip).collect();
        if names.is_empty() {
            return None;
        }
        let mut tail = String::from("…");
        for name in names.iter().rev() {
            tail.push('/');
            tail.push_str(&String::from_utf8_lossy(name));
        }
        Some(tail)
    }
}

/// Blocks on anonymous-inode descriptors, by the name the kernel gave the file.
fn anon_inode(leaf: Option<&[u8]>, name: &'static str) -> (Class, Subject) {
    match leaf {
        Some(b"[timerfd]") => (Class::Sleep, Subject::Process),
        Some(b"[eventfd]") => (Class::Ipc, Subject::Process),
        Some(b"[signalfd]") => (Class::Signal, Subject::Process),
        Some(b"inotify") => (Class::Poll, Subject::Named("inotify")),
        Some(b"[fanotify]") => (Class::Poll, Subject::Named("fanotify")),
        _ => (Class::Other, Subject::Syscall(name)),
    }
}

/// `fcntl` commands that wait for a record lock. `cmd` is an `int`: only the low half of the
/// register counts.
fn waits_for_lock(cmd: u64) -> bool {
    let cmd = cmd & u64::from(u32::MAX);
    [libc::F_SETLKW, libc::F_OFD_SETLKW]
        .into_iter()
        .any(|lock| u64::from(lock.cast_unsigned()) == cmd)
}

/// `path` with a leading `home` replaced by `~`.
fn abbreviate_home(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// The socket peer the kernel reported, if any.
fn peer(sys: &SysInfo) -> Option<SocketAddr> {
    let ip = match sys.family {
        AF_INET => IpAddr::V4(Ipv4Addr::new(
            sys.addr[0],
            sys.addr[1],
            sys.addr[2],
            sys.addr[3],
        )),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(sys.addr)).to_canonical(),
        _ => return None,
    };
    (sys.port != 0 || !ip.is_unspecified()).then_some(SocketAddr::new(ip, sys.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(nr: libc::c_long) -> SysInfo {
        SysInfo {
            nr: i32::try_from(nr).unwrap(),
            fd: 3,
            mode: 0,
            f_flags: 0,
            ino: 0,
            dev: 0,
            family: 0,
            port: 0,
            addr: [0; 16],
        }
    }

    /// A description with `flags` and the leaf-first `names` as the captured path.
    fn detail(flags: u32, names: &[&str]) -> SysDetail {
        let mut detail = SysDetail {
            args: [3, 0, 0],
            magic: 0,
            flags: SYSD_DESCRIBED | flags,
            path_len: 0,
            _pad: 0,
            path: [0; whytime_abi::PATH_BYTES as usize],
        };
        let mut at = 0;
        for name in names {
            detail.path[at..at + name.len()].copy_from_slice(name.as_bytes());
            at += name.len() + 1;
        }
        detail.path_len = u32::try_from(at).unwrap();
        detail
    }

    fn file(nr: libc::c_long, ino: u64) -> SysInfo {
        let mut s = sys(nr);
        s.mode = S_IFREG;
        s.dev = (259 << 20) | 3;
        s.ino = ino;
        s
    }

    /// Descriptor targets by `(dev, ino)`; no `/proc` involved.
    #[derive(Debug, Default)]
    struct Files(HashMap<(u32, u64), PathBuf>);

    impl FdTarget for Files {
        fn fd_target(&self, _tgid: u32, _fd: i32, dev: u32, ino: u64) -> Option<PathBuf> {
            self.0.get(&(dev, ino)).cloned()
        }
    }

    fn classifier_with(files: Files) -> Classifier {
        Classifier::new(
            SyscallTable::new(),
            Some(PathBuf::from("/home/u")),
            Box::new(files),
        )
    }

    /// A classifier whose `/proc` lookups all fail.
    fn classifier() -> Classifier {
        classifier_with(Files::default())
    }

    #[test]
    fn unrooted_files_fall_back_to_the_fd_link_and_pseudo_files_have_no_location() {
        let dev = (8 << 20) | 1;
        let mut files = Files::default();
        files
            .0
            .insert((dev, 10), PathBuf::from("/home/u/proj/.git/index (deleted)"));
        files.0.insert((dev, 11), PathBuf::from("/dev/sda1"));
        files.0.insert((dev, 12), PathBuf::from("anon_inode:[pidfd]"));
        let mut c = classifier_with(files);
        let none = detail(0, &[]);
        let mut s = sys(libc::SYS_fsync);
        s.mode = S_IFREG;
        s.dev = dev;
        s.ino = 10;
        let b = c.classify(1, &s, &none, 2);
        assert_eq!(b.class, Class::Fsync);
        assert_eq!(b.subject.to_string(), "~/proj/.git");
        s.mode = S_IFBLK;
        s.ino = 11;
        assert_eq!(c.classify(1, &s, &none, 2).subject.to_string(), "/dev/sda1");
        s.mode = S_IFREG;
        s.ino = 12;
        assert_eq!(c.classify(1, &s, &none, 2).subject.to_string(), "dev 8:1 ino 12");
    }

    #[test]
    fn socket_reads_name_the_inet_peer_and_ipv4_mapped_addresses_print_as_ipv4() {
        let mut s = sys(libc::SYS_read);
        s.mode = S_IFSOCK;
        s.family = AF_INET6;
        s.port = 443;
        s.addr = Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped().octets();
        s.ino = 77;
        let b = classifier().classify(1, &s, &detail(0, &[]), 1);
        assert_eq!(b.class, Class::Net);
        assert_eq!(b.subject.to_string(), "93.184.216.34:443");
        assert_eq!(b.socket, Some(77));
    }

    #[test]
    fn sync_writes_count_as_fsync_but_plain_writes_as_file() {
        let mut s = sys(libc::SYS_write);
        s.mode = S_IFREG;
        s.dev = (8 << 20) | 1;
        s.ino = 12;
        let d = detail(0, &[]);
        let mut c = classifier();
        assert_eq!(c.classify(1, &s, &d, 2).class, Class::File);
        s.f_flags = u32::try_from(libc::O_SYNC).unwrap();
        let b = c.classify(1, &s, &d, 2);
        assert_eq!(b.class, Class::Fsync);
        assert_eq!(b.subject.to_string(), "dev 8:1 ino 12");
    }

    #[test]
    fn rooted_kernel_paths_name_the_directory_of_a_file_or_the_directory_itself() {
        let mut c = classifier();
        let rooted = detail(SYSD_PATH_ROOTED, &["a.log", "proj", "u", "home"]);
        let b = c.classify(1, &file(libc::SYS_read, 1), &rooted, 2);
        assert_eq!((b.class, b.subject.to_string()), (Class::File, "~/proj".to_owned()));

        let mut dir = file(libc::SYS_getdents64, 2);
        dir.mode = S_IFDIR;
        let b = c.classify(1, &dir, &detail(SYSD_PATH_ROOTED, &["log", "var"]), 2);
        assert_eq!(b.subject.to_string(), "/var/log");

        let b = c.classify(1, &file(libc::SYS_read, 3), &detail(SYSD_PATH_ROOTED, &["f"]), 2);
        assert_eq!(b.subject.to_string(), "/");
    }

    #[test]
    fn truncated_walks_keep_their_tail_until_a_whole_path_arrives() {
        let mut c = classifier();
        let s = file(libc::SYS_read, 5);
        let cut = detail(SYSD_PATH_TRUNCATED, &["f.o", "obj", "deep"]);
        assert_eq!(c.classify(1, &s, &cut, 2).subject.to_string(), "…/deep/obj");
        // Unresolvable and not captured: the cached tail still names it.
        assert_eq!(
            c.classify(1, &s, &detail(0, &[]), 2).subject.to_string(),
            "…/deep/obj"
        );
        let whole = detail(SYSD_PATH_ROOTED, &["f.o", "obj", "deep", "src"]);
        assert_eq!(c.classify(1, &s, &whole, 2).subject.to_string(), "/src/deep/obj");
        assert_eq!(
            c.classify(1, &s, &detail(0, &[]), 2).subject.to_string(),
            "/src/deep/obj"
        );
        // Only the leaf survived: no directory to show.
        let leaf = detail(SYSD_PATH_TRUNCATED, &["x"]);
        let b = c.classify(1, &file(libc::SYS_read, 6), &leaf, 2);
        assert_eq!(b.subject.to_string(), "dev 259:3 ino 6");
    }

    #[test]
    fn flock_and_fcntl_lock_waits_are_lock_on_the_files_directory() {
        let mut c = classifier();
        let path = detail(SYSD_PATH_ROOTED, &["lock", "app", "u", "home"]);
        let b = c.classify(1, &file(libc::SYS_flock, 7), &path, 1);
        assert_eq!((b.class, b.subject.to_string()), (Class::Lock, "~/app".to_owned()));

        let mut setlkw = path;
        // An `int` command: garbage in the upper half of the register is ignored.
        setlkw.args[1] = 0xdead_beef_0000_0000 | u64::from(libc::F_SETLKW.cast_unsigned());
        let b = c.classify(1, &file(libc::SYS_fcntl, 7), &setlkw, 1);
        assert_eq!((b.class, b.subject.to_string()), (Class::Lock, "~/app".to_owned()));
        setlkw.args[1] = u64::from(libc::F_OFD_SETLKW.cast_unsigned());
        assert_eq!(c.classify(1, &file(libc::SYS_fcntl, 7), &setlkw, 1).class, Class::Lock);

        let mut getfl = path;
        getfl.args[1] = u64::from(libc::F_GETFL.cast_unsigned());
        assert_eq!(c.classify(1, &file(libc::SYS_fcntl, 7), &getfl, 1).class, Class::File);
    }

    #[test]
    fn anonymous_inodes_are_classified_by_their_name() {
        let mut c = classifier();
        let cases = [
            ("[timerfd]", Class::Sleep, ""),
            ("[eventfd]", Class::Ipc, ""),
            ("[signalfd]", Class::Signal, ""),
            ("inotify", Class::Poll, "inotify"),
            ("[fanotify]", Class::Poll, "fanotify"),
            ("[userfaultfd]", Class::Other, "in read"),
        ];
        // Whatever file type the kernel puts in their mode (none on 7.2).
        for mode in [S_IFREG, 0] {
            for (name, class, subject) in cases {
                let mut s = file(libc::SYS_read, 1);
                s.mode = mode;
                let mut d = detail(0, &[name]);
                d.magic = ANON_INODE_FS_MAGIC;
                let b = c.classify(1, &s, &d, 1);
                assert_eq!((b.class, b.subject.to_string()), (class, subject.to_owned()));
            }
        }
    }

    #[test]
    fn async_io_and_sysv_posix_ipc_waits_have_their_class() {
        let mut c = classifier();
        let none = detail(0, &[]);
        for (nr, class) in [
            (libc::SYS_io_uring_enter, Class::Aio),
            (libc::SYS_io_getevents, Class::Aio),
            (libc::SYS_semtimedop, Class::Ipc),
            (libc::SYS_msgrcv, Class::Ipc),
            (libc::SYS_mq_timedreceive, Class::Ipc),
        ] {
            assert_eq!(c.classify(1, &sys(nr), &none, 1).class, class);
        }
    }

    #[test]
    fn descriptor_fields_from_an_earlier_syscall_are_ignored() {
        let mut stale = detail(SYSD_PATH_ROOTED, &["f", "tmp"]);
        stale.flags = 0;
        let b = classifier().classify(1, &file(libc::SYS_read, 9), &stale, 1);
        assert_eq!((b.class, b.subject), (Class::Other, Subject::Syscall("read")));
    }

    #[test]
    fn blocks_outside_syscalls_distinguish_stops() {
        let mut c = classifier();
        let mut s = sys(0);
        s.nr = NR_NONE;
        let none = detail(0, &[]);
        assert_eq!(c.classify(1, &s, &none, 2).subject, Subject::NoSyscall);
        assert_eq!(
            c.classify(1, &s, &none, TASK_STOPPED).subject,
            Subject::Stopped
        );
    }

    #[test]
    fn home_prefix_is_abbreviated_on_component_boundaries() {
        let home = Some(Path::new("/home/u"));
        assert_eq!(
            abbreviate_home(Path::new("/home/u/.npm/x"), home),
            "~/.npm/x"
        );
        assert_eq!(abbreviate_home(Path::new("/home/u"), home), "~");
        assert_eq!(
            abbreviate_home(Path::new("/home/user2/x"), home),
            "/home/user2/x"
        );
    }
}
