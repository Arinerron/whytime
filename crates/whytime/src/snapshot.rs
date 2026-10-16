//! What `/proc` says about the threads of a process tree whytime attaches to.
//!
//! The kernel side learns about a thread at fork or exec. A thread that predates the attach
//! gets its `tasks` entry from here instead ([`task_state`]), built so that its first
//! in-kernel interval reads as if it had been tracked all along: a runnable thread is
//! on-CPU from the attach on, an off-CPU one blocked since the attach in the syscall
//! `/proc/<tid>/syscall` shows. For descriptor syscalls the descriptor is described like
//! the BPF program's first-block description would (`/proc/<tid>/fd`, `fdinfo`, `statfs` for
//! the filesystem, the socket tables under `/proc/<pid>/net` for peers), so the first block
//! classifies like any other. No path is captured except an anonymous inode's name: file
//! subjects come from the classifier's `/proc` fallback when the record is processed.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;

use procctx::StatLine;
use whytime_abi::{
    ANON_INODE_FS_MAGIC, CpuSegment, NR_NONE, PATH_BYTES, ST_BLOCKED, ST_RUNNING, SYSD_DESCRIBED,
    SYSF_FD0, SysDetail, SysInfo, TaskState,
};

use crate::classify::NR_UNREADABLE;
use crate::sys::SyscallTable;

const S_IFMT: u32 = 0o170_000;
const S_IFSOCK: u32 = 0o140_000;
const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
// `prev_state` bits sched_switch reports, by `/proc` state letter.
const TASK_INTERRUPTIBLE: u32 = 0x1;
const TASK_UNINTERRUPTIBLE: u32 = 0x2;
const TASK_STOPPED: u32 = 0x4;
const TASK_TRACED: u32 = 0x8;
const TASK_PARKED: u32 = 0x40;
const TASK_NOLOAD: u32 = 0x400;

/// A thread as `/proc` shows it at attach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Existing {
    /// `starttime` in clock ticks, to tell it from a later thread with the same tid.
    pub start_ticks: u64,
    /// What it is doing.
    pub activity: Activity,
}

/// What a pre-existing thread is doing at attach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    /// Runnable: on a CPU, or waiting for one.
    Running,
    /// Off-CPU.
    Blocked {
        /// `prev_state` as `sched_switch` would have reported it.
        block_state: u32,
        /// The syscall it sleeps in.
        sys: SysInfo,
        /// Its first arguments and, when described, filesystem and anonymous-inode name.
        detail: SysDetail,
    },
}

/// The `tasks` entry of a thread that predates attach, created at `now`.
///
/// Sets `seg` (empty, from `now`), `last_ts` (`now`), `tgid` and `state`: `ST_RUNNING` for
/// a runnable thread (if it was waiting for a CPU instead, that wait is folded into its
/// first segment), `ST_BLOCKED` for an off-CPU one, with `block_ts` = `now` (the true start
/// is unknown), `block_state`, `sys` and `detail`. Everything else is zero, `sys` of a
/// runnable thread is "no syscall" (as in a fresh kernel-side entry).
pub fn task_state(tgid: u32, now: u64, activity: &Activity) -> TaskState {
    let (state, block_ts, block_state, sys, detail) = match *activity {
        Activity::Running => (ST_RUNNING, 0, 0, no_syscall(), no_detail()),
        Activity::Blocked {
            block_state,
            sys,
            detail,
        } => (ST_BLOCKED, now, block_state, sys, detail),
    };
    TaskState {
        seg: CpuSegment {
            start: now,
            run_ns: 0,
            rq_ns: 0,
            preempt_max_ns: 0,
            preempt_tgid: 0,
            _pad: 0,
            preempt_comm: [0; 16],
        },
        last_ts: now,
        block_ts,
        wake_ts: 0,
        sys,
        tgid,
        state,
        block_state,
        waker_tid: 0,
        waker_tgid: 0,
        _pad: 0,
        detail,
        ready: no_syscall(),
        fault: no_syscall(),
        fault_file: 0,
        in_fault: 0,
        has_ready: 0,
        pend_tgid: 0,
        _pad2: 0,
        pend_comm: [0; 16],
        waker_comm: [0; 16],
        // Blocked before attach: no stack was captured.
        user_stack: 0,
        kernel_stack: 0,
        stack_gen: 0,
        _pad3: 0,
    }
}

/// Reads pre-existing threads; socket tables are read once per network namespace.
#[derive(Debug)]
pub struct Snapshot<'a> {
    syscalls: &'a SyscallTable,
    /// Network namespace inode → socket inode → family and peer.
    sockets: HashMap<u64, HashMap<u64, Peer>>,
    /// Off-CPU threads whose syscall could not be read (no ptrace access).
    pub unreadable: usize,
}

/// A socket as the BPF program describes it: family and peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    family: u16,
    /// Network order, IPv4 in the first 4 bytes.
    addr: [u8; 16],
    /// Host order.
    port: u16,
}

/// A line of `/proc/<tid>/syscall`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyscallLine {
    /// The thread is runnable.
    Running,
    /// Off-CPU outside any syscall (page fault, signal stop).
    Outside,
    /// In syscall `nr` with arguments 0..3 `args`.
    In { nr: i32, args: [u64; 3] },
}

impl<'a> Snapshot<'a> {
    /// A snapshot classifying syscalls with `syscalls`.
    pub fn new(syscalls: &'a SyscallTable) -> Self {
        Self {
            syscalls,
            sockets: HashMap::new(),
            unreadable: 0,
        }
    }

    /// Thread `tid` of process `tgid`; `None` once it has exited.
    pub fn thread(&mut self, tgid: u32, tid: u32) -> Option<Existing> {
        let dir = format!("/proc/{tgid}/task/{tid}");
        let stat = read_stat(&dir, tid)?;
        let existing = |activity| {
            Some(Existing {
                start_ticks: stat.start_ticks,
                activity,
            })
        };
        let stopped = |block_state| Activity::Blocked {
            block_state,
            sys: no_syscall(),
            detail: no_detail(),
        };
        let block_state = match stat.state {
            b'R' => return existing(Activity::Running),
            b'Z' | b'X' | b'x' => return None,
            // Stops happen outside syscalls (after sys_exit), as the kernel side records.
            b'T' => return existing(stopped(TASK_STOPPED)),
            b't' => return existing(stopped(TASK_TRACED)),
            b'S' => TASK_INTERRUPTIBLE,
            b'I' => TASK_UNINTERRUPTIBLE | TASK_NOLOAD,
            b'P' => TASK_PARKED,
            _ => TASK_UNINTERRUPTIBLE,
        };
        let (sys, detail) = match fs::read_to_string(format!("{dir}/syscall")) {
            Ok(text) => match parse_syscall(&text) {
                Some(SyscallLine::Running) => return existing(Activity::Running),
                Some(SyscallLine::Outside) => (no_syscall(), no_detail()),
                Some(SyscallLine::In { nr, args }) => self.syscall(tgid, &dir, nr, args),
                None => self.unread(),
            },
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                return None;
            }
            // EACCES/EPERM: reading it needs ptrace access to the thread.
            Err(_) => self.unread(),
        };
        existing(Activity::Blocked {
            block_state,
            sys,
            detail,
        })
    }

    fn unread(&mut self) -> (SysInfo, SysDetail) {
        self.unreadable += 1;
        let sys = SysInfo {
            nr: NR_UNREADABLE,
            ..no_syscall()
        };
        (sys, no_detail())
    }

    /// Syscall `nr` with arguments `args`, as the BPF program leaves it after the syscall's
    /// first block: arguments saved, `SYSD_DESCRIBED`, and for descriptor syscalls the
    /// descriptor described. A descriptor `/proc` cannot show stays undescribed (the kernel
    /// describes it if the syscall blocks again).
    fn syscall(&mut self, tgid: u32, dir: &str, nr: i32, args: [u64; 3]) -> (SysInfo, SysDetail) {
        let mut sys = SysInfo { nr, ..no_syscall() };
        let mut detail = SysDetail {
            args,
            ..no_detail()
        };
        let described = if self.syscalls.flags(nr) & SYSF_FD0 == 0 {
            true
        } else {
            // A negative descriptor fails before blocking, so only valid ones reach here.
            sys.fd = i32::try_from(args[0]).unwrap_or(-1);
            self.describe(tgid, dir, &mut sys, &mut detail)
        };
        if described {
            detail.flags = SYSD_DESCRIBED;
        }
        (sys, detail)
    }

    /// Fills inode type and identity, open flags and, for sockets, family and peer of
    /// `sys.fd`, and the filesystem magic (plus the name of an anonymous inode, which the
    /// kernel's path walk would capture) into `detail`. False if the descriptor is gone.
    fn describe(&mut self, tgid: u32, dir: &str, sys: &mut SysInfo, detail: &mut SysDetail) -> bool {
        let link = format!("{dir}/fd/{}", sys.fd);
        let Ok(meta) = fs::metadata(&link) else {
            return false;
        };
        sys.mode = meta.mode() & S_IFMT;
        sys.ino = meta.ino();
        sys.dev = kernel_dev(meta.dev());
        sys.f_flags = fs::read_to_string(format!("{dir}/fdinfo/{}", sys.fd))
            .ok()
            .and_then(|info| fdinfo_flags(&info))
            .unwrap_or(0);
        if sys.mode == S_IFSOCK
            && let Some(peer) = self.peer(tgid, sys.ino)
        {
            sys.family = peer.family;
            sys.addr = peer.addr;
            sys.port = peer.port;
        }
        detail.magic = fs_magic(&link).unwrap_or(0);
        if detail.magic == ANON_INODE_FS_MAGIC
            && let Ok(target) = fs::read_link(&link)
            && let Some(name) = target.as_os_str().as_bytes().strip_prefix(b"anon_inode:")
            && name.len() < detail.path.len()
        {
            // A pseudo-filesystem name, as the walk leaves it: no SYSD_PATH_* flag.
            detail.path[..name.len()].copy_from_slice(name);
            detail.path_len = u32::try_from(name.len() + 1).unwrap_or(0);
        }
        true
    }

    /// The socket with inode `ino` in `tgid`'s network namespace.
    fn peer(&mut self, tgid: u32, ino: u64) -> Option<Peer> {
        let Ok(netns) = fs::metadata(format!("/proc/{tgid}/ns/net")) else {
            return socket_table(tgid).get(&ino).copied();
        };
        self.sockets
            .entry(netns.ino())
            .or_insert_with(|| socket_table(tgid))
            .get(&ino)
            .copied()
    }
}

/// Thread ids of process `tgid` (empty once it is gone).
pub fn threads(tgid: u32) -> Vec<u32> {
    fs::read_dir(format!("/proc/{tgid}/task")).map_or_else(
        |_| Vec::new(),
        |dir| {
            dir.filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                .collect()
        },
    )
}

/// Whether thread `tid` of `tgid`, started at `start_ticks`, is still alive.
pub fn thread_alive(tgid: u32, tid: u32, start_ticks: u64) -> bool {
    read_stat(&format!("/proc/{tgid}/task/{tid}"), tid)
        .is_some_and(|stat| stat.start_ticks == start_ticks && !stat.has_exited())
}

/// Whether process `pid`, started at `start_ticks`, still has a live thread.
pub fn process_alive(pid: u32, start_ticks: u64) -> bool {
    read_stat(&format!("/proc/{pid}"), pid)
        .is_some_and(|stat| stat.start_ticks == start_ticks && !exited(&stat))
}

/// Whether the process of `stat` has exited. A zombie leader alone does not say so: the
/// leader may have called `pthread_exit` while other threads run on.
pub fn exited(stat: &StatLine) -> bool {
    stat.has_exited() && threads(stat.pid).len() <= 1
}

fn read_stat(dir: &str, pid: u32) -> Option<StatLine> {
    let line = fs::read(format!("{dir}/stat")).ok()?;
    StatLine::parse(pid, &line).ok()
}

/// "Not in a syscall", as the BPF program's `clear_sys` writes it.
fn no_syscall() -> SysInfo {
    SysInfo {
        nr: NR_NONE,
        fd: -1,
        mode: 0,
        f_flags: 0,
        ino: 0,
        dev: 0,
        family: 0,
        port: 0,
        addr: [0; 16],
    }
}

/// No syscall arguments, nothing described: a fresh kernel-side entry's detail.
fn no_detail() -> SysDetail {
    SysDetail {
        args: [0; 3],
        magic: 0,
        flags: 0,
        path_len: 0,
        _pad: 0,
        path: [0; PATH_BYTES as usize],
    }
}

/// `f_type` (the superblock's `s_magic`, low 32 bits as the BPF program reads it) of the
/// filesystem holding the file `path` names; for a `/proc` fd link, the descriptor's file.
fn fs_magic(path: &str) -> Option<u32> {
    let path = CString::new(path).ok()?;
    // SAFETY: `statfs` is plain data; statfs fills it from a NUL-terminated path.
    let st = unsafe {
        let mut st: libc::statfs = std::mem::zeroed();
        if libc::statfs(path.as_ptr(), &raw mut st) != 0 {
            return None;
        }
        st
    };
    u32::try_from(st.f_type & 0xffff_ffff).ok()
}

/// `running`, `-1 SP PC` (outside syscalls), or `NR ARG0..ARG5 SP PC`.
fn parse_syscall(text: &str) -> Option<SyscallLine> {
    let mut words = text.split_ascii_whitespace();
    let first = words.next()?;
    if first == "running" {
        return Some(SyscallLine::Running);
    }
    let nr: i32 = first.parse().ok()?;
    if nr < 0 {
        return Some(SyscallLine::Outside);
    }
    let mut args = [0; 3];
    for arg in &mut args {
        *arg = u64::from_str_radix(words.next()?.strip_prefix("0x")?, 16).ok()?;
    }
    Some(SyscallLine::In { nr, args })
}

/// The octal `flags:` line of `/proc/<pid>/fdinfo/<fd>` (`file->f_flags`).
fn fdinfo_flags(info: &str) -> Option<u32> {
    let flags = info.lines().find_map(|line| line.strip_prefix("flags:"))?;
    u32::from_str_radix(flags.trim(), 8).ok()
}

/// A user-space `st_dev` in the kernel's internal `dev_t` encoding (`major << 20 | minor`),
/// which the BPF program reads from `i_sb->s_dev`.
fn kernel_dev(dev: u64) -> u32 {
    (libc::major(dev) << 20) | libc::minor(dev)
}

/// Socket inode → family and peer, from `tgid`'s view of `/proc/net`.
fn socket_table(tgid: u32) -> HashMap<u64, Peer> {
    let mut peers = HashMap::new();
    for (file, family) in [
        ("tcp", AF_INET),
        ("udp", AF_INET),
        ("tcp6", AF_INET6),
        ("udp6", AF_INET6),
    ] {
        let Ok(text) = fs::read_to_string(format!("/proc/{tgid}/net/{file}")) else {
            continue;
        };
        peers.extend(text.lines().skip(1).filter_map(|line| inet_socket(line, family)));
    }
    if let Ok(text) = fs::read_to_string(format!("/proc/{tgid}/net/unix")) {
        let unix = Peer {
            family: AF_UNIX,
            addr: [0; 16],
            port: 0,
        };
        peers.extend(text.lines().skip(1).filter_map(|line| {
            let ino = line.split_ascii_whitespace().nth(6)?.parse().ok()?;
            Some((ino, unix))
        }));
    }
    peers
}

/// `(inode, peer)` from a `/proc/net/{tcp,udp}[6]` line: `sl local remote st tx:rx tr:when
/// retrnsmt uid timeout inode ...`, the remote address as `%08X` words of its in-memory
/// (network order) value, then `:%04X` port in host order.
fn inet_socket(line: &str, family: u16) -> Option<(u64, Peer)> {
    let mut words = line.split_ascii_whitespace();
    let remote = words.nth(2)?;
    let ino: u64 = words.nth(6)?.parse().ok()?;
    let (hex, port) = remote.split_once(':')?;
    let words_expected = if family == AF_INET { 1 } else { 4 };
    if ino == 0 || hex.len() != 8 * words_expected {
        return None;
    }
    let mut addr = [0; 16];
    for (word, out) in hex.as_bytes().chunks(8).zip(addr.chunks_mut(4)) {
        let value = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
        out.copy_from_slice(&value.to_ne_bytes());
    }
    Some((
        ino,
        Peer {
            family,
            addr,
            port: u16::from_str_radix(port, 16).ok()?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::classify::{Class, Classifier, ProcFd};

    #[test]
    fn syscall_lines_parse_running_outside_and_in_syscall() {
        assert_eq!(parse_syscall("running\n"), Some(SyscallLine::Running));
        assert_eq!(
            parse_syscall("-1 0x7ffc8c0 0x7f00\n"),
            Some(SyscallLine::Outside)
        );
        assert_eq!(
            parse_syscall("0 0x3 0x7ffd 0x2000 0x0 0x0 0x0 0x7ffc 0x7f12\n"),
            Some(SyscallLine::In {
                nr: 0,
                args: [3, 0x7ffd, 0x2000]
            })
        );
        assert_eq!(parse_syscall(""), None);
    }

    #[test]
    fn inet_lines_decode_network_order_words_and_host_order_ports() {
        let v4 = "   1: 0100007F:A2B4 0100007F:1F90 01 00000000:00000000 00:00000000 \
                  00000000  1000        0 424242 1 0000000000000000 20 4 30 10 -1";
        let (ino, peer) = inet_socket(v4, AF_INET).unwrap();
        assert_eq!(ino, 424_242);
        assert_eq!(peer.port, 8080);
        assert_eq!(&peer.addr[..4], &Ipv4Addr::LOCALHOST.octets());

        let v6 = "   0: 00000000000000000000000001000000:0050 \
                  B80D0120000000000000000001000000:01BB 01 00000000:00000000 00:00000000 \
                  00000000  1000        0 77 1 0000000000000000 20 4 30 10 -1";
        let (ino, peer) = inet_socket(v6, AF_INET6).unwrap();
        assert_eq!(ino, 77);
        assert_eq!(peer.port, 443);
        let expected: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(peer.addr, expected.octets());

        // TIME_WAIT sockets have no inode; v4 widths in a v6 table are malformed.
        assert_eq!(inet_socket(&v4.replace(" 424242 ", " 0 "), AF_INET), None);
        assert_eq!(inet_socket(v4, AF_INET6), None);
    }

    #[test]
    fn fdinfo_flags_are_octal() {
        let info = "pos:\t0\nflags:\t0110001\nmnt_id:\t30\nino:\t12\n";
        assert_eq!(fdinfo_flags(info), Some(0o110_001));
    }

    /// Polls until thread `tid` of this process is off-CPU in a syscall.
    fn blocked(tid: u32, syscalls: &SyscallTable) -> Activity {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut snapshot = Snapshot::new(syscalls);
            let existing = snapshot.thread(std::process::id(), tid).unwrap();
            if let Activity::Blocked { sys, .. } = existing.activity
                && sys.nr >= 0
            {
                return existing.activity;
            }
            assert!(Instant::now() < deadline, "thread {tid} never blocked");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The calling thread's kernel tid.
    fn gettid() -> u32 {
        // SAFETY: gettid has no preconditions.
        u32::try_from(unsafe { libc::gettid() }).unwrap()
    }

    #[test]
    fn a_thread_blocked_reading_a_socket_classifies_as_its_tcp_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(server).unwrap();
            tid_tx.send(gettid()).unwrap();
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).unwrap();
        });
        let (mut accepted, _) = listener.accept().unwrap();
        let tid = tid_rx.recv().unwrap();
        let syscalls = SyscallTable::new();
        let activity = blocked(tid, &syscalls);
        accepted.write_all(b"x").unwrap();
        reader.join().unwrap();

        let Activity::Blocked {
            block_state,
            sys,
            detail,
        } = activity
        else {
            unreachable!()
        };
        assert_eq!(block_state, TASK_INTERRUPTIBLE);
        assert_eq!(sys.mode, S_IFSOCK);
        assert_eq!(detail.flags, SYSD_DESCRIBED);
        let class = Classifier::new(SyscallTable::new(), None, Box::new(ProcFd)).classify(
            std::process::id(),
            &sys,
            &detail,
            block_state,
        );
        assert_eq!(class.class, Class::Net);
        assert_eq!(class.subject.to_string(), server.to_string());
        assert_eq!(class.socket, Some(sys.ino));
    }

    #[test]
    fn a_thread_blocked_reading_a_pipe_classifies_as_ipc() {
        let mut fds = [0; 2];
        // SAFETY: pipe writes two descriptors into `fds`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let read_end = fds[0];
        let reader = std::thread::spawn(move || {
            tid_tx.send(gettid()).unwrap();
            let mut byte = 0_u8;
            // SAFETY: reading one byte into `byte` from our pipe.
            unsafe { libc::read(read_end, (&raw mut byte).cast(), 1) };
        });
        let tid = tid_rx.recv().unwrap();
        let syscalls = SyscallTable::new();
        let activity = blocked(tid, &syscalls);
        // SAFETY: writing one byte to our pipe, then closing both ends.
        unsafe {
            libc::write(fds[1], b"x".as_ptr().cast(), 1);
        }
        reader.join().unwrap();
        // SAFETY: closing our own descriptors.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let Activity::Blocked {
            block_state,
            sys,
            detail,
        } = activity
        else {
            unreachable!()
        };
        assert_eq!(sys.fd, read_end);
        let class = Classifier::new(SyscallTable::new(), None, Box::new(ProcFd)).classify(
            std::process::id(),
            &sys,
            &detail,
            block_state,
        );
        assert_eq!(class.class, Class::Ipc);
    }

    #[test]
    fn a_thread_blocked_reading_an_eventfd_is_described_as_an_anonymous_inode() {
        // SAFETY: eventfd has no preconditions.
        let efd = unsafe { libc::eventfd(0, 0) };
        assert!(efd >= 0);
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            tid_tx.send(gettid()).unwrap();
            let mut count = 0_u64;
            // SAFETY: reading the 8-byte counter of our eventfd into `count`.
            unsafe { libc::read(efd, (&raw mut count).cast(), 8) };
        });
        let tid = tid_rx.recv().unwrap();
        let syscalls = SyscallTable::new();
        let activity = blocked(tid, &syscalls);
        let one = 1_u64;
        // SAFETY: adding `one` to our eventfd's counter, then closing it.
        unsafe {
            libc::write(efd, (&raw const one).cast(), 8);
        }
        reader.join().unwrap();
        // SAFETY: closing our own descriptor.
        unsafe { libc::close(efd) };

        let Activity::Blocked {
            block_state,
            sys,
            detail,
        } = activity
        else {
            unreachable!()
        };
        assert_eq!(detail.magic, ANON_INODE_FS_MAGIC);
        assert_eq!(&detail.path[..10], b"[eventfd]\0");
        assert_eq!(detail.path_len, 10);
        // A file the classifier cannot look up: the name alone classifies it.
        let class = Classifier::new(SyscallTable::new(), None, Box::new(crate::testkit::NoFiles))
            .classify(std::process::id(), &sys, &detail, block_state);
        assert_eq!(class.class, Class::Ipc);
    }
}
