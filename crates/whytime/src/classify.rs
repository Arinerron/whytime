//! Turns "thread blocked in syscall N on descriptor D" into a resource class and subject.
//!
//! Runs as records arrive, while the blocked process and its descriptor most likely still
//! exist, because file paths come from `/proc/<pid>/fd/<fd>` (and, for page faults, from
//! `/proc/<pid>/maps`). A path is trusted only if the file it names has the device and inode
//! the kernel reported; otherwise the subject falls back to `dev M:m ino N`.
//!
//! Besides the syscall, a block may carry what ended or caused it: the descriptor whose
//! readiness ended a poll/select/epoll wait, the mapped file of a page fault, and the `comm`
//! of a waker outside the traced tree (see [`BlockInfo`]).

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use whytime_abi::{NR_NONE, SysInfo};

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
    /// Internet sockets.
    Net,
    /// Pipes, FIFOs, UNIX and other local sockets.
    Ipc,
    /// Futex waits: locks, condition variables, thread joins.
    Futex,
    /// `poll`/`select`/`epoll_wait` with no single resource behind it.
    Poll,
    /// Waiting for a signal.
    Signal,
    /// Terminal and other character-device I/O.
    Tty,
    /// Blocked inside a page fault: reading a mapped file, swap-in, or the memory locks
    /// around them. Takes precedence over the syscall the fault interrupted.
    Fault,
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
    /// A syscall number whytime has no name for.
    UnknownSyscall(i32),
    /// Off-CPU outside any syscall: page faults, reclaim, kernel locks.
    NoSyscall,
    /// Stopped by a signal or a tracer.
    Stopped,
    /// A process-context task outside the traced tree ended the wait (its `comm`).
    Waker(Arc<str>),
    /// A page fault on memory no file backs.
    AnonMemory,
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
            Self::UnknownSyscall(nr) => write!(f, "in syscall {nr}"),
            Self::NoSyscall => f.write_str("outside syscalls (page faults, kernel locks)"),
            Self::Stopped => f.write_str("stopped (signal or tracer)"),
            Self::Waker(comm) => write!(f, "woken by {comm}"),
            Self::AnonMemory => f.write_str("anonymous memory (swap)"),
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

/// What the kernel recorded about one block, besides the thread and its process.
#[derive(Clone, Copy, Debug)]
pub struct BlockInfo<'a> {
    /// The syscall in flight.
    pub sys: &'a SysInfo,
    /// `prev_state` at the switch-out.
    pub block_state: u32,
    /// The file whose readiness ended a poll/select/epoll wait.
    pub ready: Option<&'a SysInfo>,
    /// The file mapped at the page fault the thread blocked in (`mode` 0: anonymous memory).
    pub fault: Option<&'a SysInfo>,
    /// `comm` of the waker when it is a process-context task outside the traced tree.
    pub waker: Option<&'a Arc<str>>,
}

/// Classifies blocks, resolving and caching file paths.
#[derive(Debug)]
pub struct Classifier {
    syscalls: SyscallTable,
    proc_root: PathBuf,
    home: Option<PathBuf>,
    /// `(dev, ino)` → subject path; `None` when resolution failed.
    paths: HashMap<(u32, u64), Option<Arc<str>>>,
}

impl Classifier {
    /// `home` is abbreviated to `~` in paths.
    pub fn new(syscalls: SyscallTable, home: Option<PathBuf>) -> Self {
        Self {
            syscalls,
            proc_root: PathBuf::from("/proc"),
            home,
            paths: HashMap::new(),
        }
    }

    /// Classifies a block of process `tgid` in `sys`, entered with scheduler state
    /// `block_state`.
    pub fn classify(&mut self, tgid: u32, sys: &SysInfo, block_state: u32) -> Blocked {
        let plain = |class, subject| Blocked {
            class,
            subject,
            socket: None,
        };
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
        match syscall.kind {
            Kind::Sleep => plain(Class::Sleep, Subject::Process),
            Kind::Futex => plain(Class::Futex, Subject::Process),
            Kind::Wait => plain(Class::Child, Subject::Process),
            Kind::Poll => plain(Class::Poll, Subject::Process),
            Kind::Signal => plain(Class::Signal, Subject::Process),
            Kind::PathFs => plain(Class::File, Subject::Syscall(syscall.name)),
            Kind::Other => plain(Class::Other, Subject::Syscall(syscall.name)),
            Kind::Fsync => match sys.mode {
                S_IFREG | S_IFBLK | S_IFDIR => plain(Class::Fsync, self.file_subject(tgid, sys)),
                _ => plain(Class::Fsync, Subject::Syscall(syscall.name)),
            },
            Kind::Connect => self.by_descriptor(tgid, sys, syscall.name, false),
            Kind::FdIo { write } => self.by_descriptor(tgid, sys, syscall.name, write),
        }
    }

    /// Classifies a block of process `tgid`. A page fault takes precedence over the syscall
    /// it interrupted; a readiness wait takes the class of the descriptor that became ready
    /// (sockets, FIFOs, character devices; anything else stays `poll`); `ipc` and `poll`
    /// waits ended by a waker outside the traced tree are named after it.
    pub fn classify_block(&mut self, tgid: u32, block: &BlockInfo<'_>) -> Blocked {
        if let Some(fault) = block.fault {
            return Blocked {
                class: Class::Fault,
                subject: self.fault_subject(tgid, fault),
                socket: None,
            };
        }
        let mut blocked = self.classify(tgid, block.sys, block.block_state);
        // Without the syscall programs (nr unknown) readiness alone says it was a poll.
        if let Some(ready) = block.ready
            && (blocked.class == Class::Poll || block.sys.nr == NR_NONE)
        {
            blocked = match ready.mode {
                S_IFSOCK | S_IFIFO | S_IFCHR => {
                    let name = self.syscalls.get(block.sys.nr).map_or("poll", |s| s.name);
                    self.by_descriptor(tgid, ready, name, false)
                }
                _ => Blocked {
                    class: Class::Poll,
                    subject: Subject::Process,
                    socket: None,
                },
            };
        }
        if matches!(blocked.class, Class::Ipc | Class::Poll)
            && blocked.subject == Subject::Process
            && let Some(waker) = block.waker
        {
            blocked.subject = Subject::Waker(Arc::clone(waker));
        }
        blocked
    }

    fn by_descriptor(
        &mut self,
        tgid: u32,
        sys: &SysInfo,
        name: &'static str,
        write: bool,
    ) -> Blocked {
        let (class, subject) = match sys.mode {
            S_IFREG | S_IFBLK | S_IFDIR => {
                let durable = write && sys.f_flags & O_DSYNC != 0;
                let class = if durable { Class::Fsync } else { Class::File };
                (class, self.file_subject(tgid, sys))
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
        };
        Blocked {
            class,
            subject,
            socket: None,
        }
    }

    /// The directory holding the descriptor's file (or the device/directory itself).
    fn file_subject(&mut self, tgid: u32, sys: &SysInfo) -> Subject {
        self.cached_path(sys, |classifier| classifier.resolve(tgid, sys))
    }

    /// The directory holding the file mapped at a page fault, or anonymous memory.
    fn fault_subject(&mut self, tgid: u32, fault: &SysInfo) -> Subject {
        if fault.mode == 0 {
            return Subject::AnonMemory;
        }
        self.cached_path(fault, |classifier| classifier.resolve_mapped(tgid, fault))
    }

    /// The subject path of `(file.dev, file.ino)`, resolved with `resolve` on a cache miss;
    /// `dev M:m ino N` when that fails.
    fn cached_path(
        &mut self,
        file: &SysInfo,
        resolve: impl FnOnce(&Self) -> Option<String>,
    ) -> Subject {
        let key = (file.dev, file.ino);
        let cached = if let Some(cached) = self.paths.get(&key) {
            cached.clone()
        } else {
            let resolved = resolve(self).map(Arc::from);
            self.paths.insert(key, resolved.clone());
            resolved
        };
        cached.map_or(
            Subject::Inode {
                dev: file.dev,
                ino: file.ino,
            },
            Subject::Path,
        )
    }

    fn resolve(&self, tgid: u32, sys: &SysInfo) -> Option<String> {
        let link = self.proc_root.join(format!("{tgid}/fd/{}", sys.fd));
        let meta = std::fs::metadata(&link).ok()?;
        let dev = u64::from(sys.dev);
        let same_file = meta.ino() == sys.ino
            && libc::major(meta.dev()) == u32::try_from(dev >> 20).ok()?
            && libc::minor(meta.dev()) == u32::try_from(dev & 0xf_ffff).ok()?;
        if !same_file {
            return None;
        }
        let target = std::fs::read_link(&link).ok()?;
        Some(self.shown_path(&target.to_string_lossy(), sys.mode))
    }

    /// The path of the mapping of `(file.dev, file.ino)` in `/proc/<tgid>/maps`.
    fn resolve_mapped(&self, tgid: u32, file: &SysInfo) -> Option<String> {
        let maps = std::fs::read_to_string(self.proc_root.join(format!("{tgid}/maps"))).ok()?;
        let path = maps
            .lines()
            .find_map(|line| mapped_path(line, file.dev, file.ino))?;
        Some(self.shown_path(path, file.mode))
    }

    /// How a resolved file path is shown: the directory of a regular file, else the path
    /// itself, without a ` (deleted)` mark, home abbreviated.
    fn shown_path(&self, target: &str, mode: u32) -> String {
        let path = Path::new(target.strip_suffix(" (deleted)").unwrap_or(target));
        let shown = if mode == S_IFREG {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        abbreviate_home(shown, self.home.as_deref())
    }
}

/// The path of a `/proc/<pid>/maps` line (`start-end perms offset MM:mm inode   path`) that
/// maps kernel device `dev` (`major << 20 | minor`) and inode `ino`.
fn mapped_path(line: &str, dev: u32, ino: u64) -> Option<&str> {
    let mut fields = line.splitn(6, ' ');
    let (major, minor) = fields.nth(3)?.split_once(':')?;
    let same_file = fields.next()?.parse::<u64>().ok()? == ino
        && u32::from_str_radix(major, 16).ok()? == dev >> 20
        && u32::from_str_radix(minor, 16).ok()? == dev & 0xf_ffff;
    let path = fields.next()?.trim_start();
    (same_file && path.starts_with('/')).then_some(path)
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

    fn classifier() -> Classifier {
        let mut c = Classifier::new(SyscallTable::new(), Some(PathBuf::from("/home/u")));
        // Fixture-free: no /proc lookups succeed under this root.
        c.proc_root = PathBuf::from("/nonexistent");
        c
    }

    #[test]
    fn socket_reads_name_the_inet_peer_and_ipv4_mapped_addresses_print_as_ipv4() {
        let mut s = sys(libc::SYS_read);
        s.mode = S_IFSOCK;
        s.family = AF_INET6;
        s.port = 443;
        s.addr = Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped().octets();
        s.ino = 77;
        let b = classifier().classify(1, &s, 1);
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
        let mut c = classifier();
        assert_eq!(c.classify(1, &s, 2).class, Class::File);
        s.f_flags = u32::try_from(libc::O_SYNC).unwrap();
        let b = c.classify(1, &s, 2);
        assert_eq!(b.class, Class::Fsync);
        assert_eq!(b.subject.to_string(), "dev 8:1 ino 12");
    }

    #[test]
    fn blocks_outside_syscalls_distinguish_stops() {
        let mut c = classifier();
        let mut s = sys(0);
        s.nr = NR_NONE;
        assert_eq!(c.classify(1, &s, 2).subject, Subject::NoSyscall);
        assert_eq!(c.classify(1, &s, TASK_STOPPED).subject, Subject::Stopped);
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

    fn block(sys: &SysInfo) -> BlockInfo<'_> {
        BlockInfo {
            sys,
            block_state: 1,
            ready: None,
            fault: None,
            waker: None,
        }
    }

    fn file(mode: u32, dev: u32, ino: u64) -> SysInfo {
        SysInfo {
            nr: NR_NONE,
            fd: -1,
            mode,
            dev,
            ino,
            ..sys(0)
        }
    }

    #[test]
    fn a_page_fault_outranks_the_syscall_it_interrupted() {
        let mut c = classifier();
        let mut read = sys(libc::SYS_read);
        read.mode = S_IFIFO;
        let mapped = file(S_IFREG, (259 << 20) | 2, 99);
        let b = c.classify_block(
            1,
            &BlockInfo {
                fault: Some(&mapped),
                ..block(&read)
            },
        );
        assert_eq!(b.class, Class::Fault);
        assert_eq!(b.subject.to_string(), "dev 259:2 ino 99");
        let anon = file(0, 0, 0);
        let b = c.classify_block(
            1,
            &BlockInfo {
                fault: Some(&anon),
                ..block(&read)
            },
        );
        assert_eq!(
            (b.class, b.subject.to_string()),
            (Class::Fault, "anonymous memory (swap)".to_owned())
        );
    }

    #[test]
    fn fault_subjects_are_the_mapped_files_directory_from_proc_maps() {
        let root = std::env::temp_dir().join(format!("whytime-maps-{}", std::process::id()));
        std::fs::create_dir_all(root.join("7")).unwrap();
        std::fs::write(
            root.join("7/maps"),
            "7f0e1c000000-7f0e1e000000 r--s 00000000 103:02 1311                       \
             /home/u/big data/x.bin (deleted)\n",
        )
        .unwrap();
        let mut c = classifier();
        c.proc_root.clone_from(&root);
        let mapped = file(S_IFREG, (0x103 << 20) | 2, 1311);
        let subject = c.fault_subject(7, &mapped);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(subject.to_string(), "~/big data");
    }

    #[test]
    fn maps_lines_match_by_device_and_inode() {
        let line = "7f0e1c000000-7f0e1e000000 r--s 00000000 103:02 1311    /usr/lib/libx.so";
        assert_eq!(
            mapped_path(line, (0x103 << 20) | 2, 1311),
            Some("/usr/lib/libx.so")
        );
        assert_eq!(mapped_path(line, (0x103 << 20) | 2, 1312), None);
        assert_eq!(mapped_path(line, (8 << 20) | 2, 1311), None);
        let stack = "7ffd4b5e9000-7ffd4b60a000 rw-p 00000000 00:00 0          [stack]";
        assert_eq!(mapped_path(stack, 0, 0), None);
    }

    #[test]
    fn poll_waits_take_the_class_of_the_ready_descriptor() {
        let mut c = classifier();
        let poll = sys(libc::SYS_ppoll);
        let mut sock = file(S_IFSOCK, 8, 5);
        sock.family = AF_INET;
        sock.addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        sock.port = 8080;
        let b = c.classify_block(
            1,
            &BlockInfo {
                ready: Some(&sock),
                ..block(&poll)
            },
        );
        assert_eq!(
            (b.class, b.subject.to_string(), b.socket),
            (Class::Net, "127.0.0.1:8080".to_owned(), Some(5))
        );
        // Anonymous inodes (eventfd, timerfd, inotify) have no file type in kernel.
        let eventfd = file(0, 17, 2115);
        let b = c.classify_block(
            1,
            &BlockInfo {
                ready: Some(&eventfd),
                ..block(&poll)
            },
        );
        assert_eq!((b.class, b.subject), (Class::Poll, Subject::Process));
    }

    #[test]
    fn ipc_and_poll_waits_woken_from_outside_the_tree_name_the_waker() {
        let mut c = classifier();
        let waker: Arc<str> = Arc::from("dbus-daemon");
        let woken = |c: &mut Classifier, sys: &SysInfo| {
            let b = c.classify_block(
                1,
                &BlockInfo {
                    waker: Some(&waker),
                    ..block(sys)
                },
            );
            (b.class, b.subject.to_string())
        };
        let mut fifo = sys(libc::SYS_read);
        fifo.mode = S_IFIFO;
        let woken_by = "woken by dbus-daemon".to_owned();
        assert_eq!(woken(&mut c, &fifo), (Class::Ipc, woken_by.clone()));
        assert_eq!(
            woken(&mut c, &sys(libc::SYS_epoll_pwait)),
            (Class::Poll, woken_by)
        );
        // Other classes keep their subject.
        assert_eq!(
            woken(&mut c, &sys(libc::SYS_nanosleep)),
            (Class::Sleep, String::new())
        );
    }
}
