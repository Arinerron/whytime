//! `wt-dns udp|tcp|tcp-musl SERVER NAME PORT N` resolves NAME with one DNS query (type A) to
//! SERVER, then N times connects to the answer's address on PORT and reads until the peer
//! closes. `udp` sends the query from an unconnected socket (`sendto`/`recvfrom`, as musl
//! does); `tcp` connects to SERVER and reads the 2-byte length and the message separately (as
//! glibc does); `tcp-musl` does what musl's TCP fallback does (see [`musl_tcp`]).
//!
//! `wt-dns serve ADDR NAME=IPV4...` is the DNS server the e2e suite starts outside the traced
//! tree: on UDP and TCP ADDR it answers A queries for each NAME with its IPV4 (other names:
//! NXDOMAIN; other types: no answer). It prints `ready` once listening and exits when its
//! standard input closes. Port 53 needs `cap_net_bind_service`.

use std::collections::HashMap;
use std::io::{self, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};

/// Query type and class: A, IN.
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn main() {
    let usage = "wt-dns udp|tcp|tcp-musl SERVER NAME PORT N | wt-dns serve ADDR NAME=IPV4...";
    let mode: String = whytime_testbins::arg(1, usage);
    if mode == "serve" {
        let addr: SocketAddr = whytime_testbins::arg(2, usage);
        let names = std::env::args()
            .skip(3)
            .map(|entry| {
                let (name, ip) = entry.split_once('=').unwrap_or_else(|| panic!("{usage}"));
                let ip: Ipv4Addr = ip.parse().unwrap_or_else(|e| panic!("{entry}: {e}"));
                (name.to_ascii_lowercase(), ip)
            })
            .collect();
        serve(addr, names);
        return;
    }
    let server: SocketAddr = whytime_testbins::arg(2, usage);
    let name: String = whytime_testbins::arg(3, usage);
    let port: u16 = whytime_testbins::arg(4, usage);
    let rounds: u32 = whytime_testbins::arg(5, usage);
    let query = query(&name);
    let reply = match mode.as_str() {
        "udp" => {
            let socket = UdpSocket::bind("0.0.0.0:0").expect("bind");
            socket.send_to(&query, server).expect("sendto");
            let mut reply = vec![0; 512];
            let (len, _) = socket.recv_from(&mut reply).expect("recvfrom");
            reply.truncate(len);
            reply
        }
        "tcp" => {
            let mut stream = TcpStream::connect(server).expect("connect");
            let mut framed = u16::try_from(query.len()).expect("short").to_be_bytes().to_vec();
            framed.extend_from_slice(&query);
            stream.write_all(&framed).expect("write");
            let mut len = [0; 2];
            stream.read_exact(&mut len).expect("read length");
            let mut reply = vec![0; usize::from(u16::from_be_bytes(len))];
            stream.read_exact(&mut reply).expect("read message");
            reply
        }
        "tcp-musl" => musl_tcp(server, &query),
        _ => {
            eprintln!("usage: {usage}");
            std::process::exit(2);
        }
    };
    let ip = answer(&reply).unwrap_or_else(|| panic!("no A record for {name} in the reply"));
    let mut data = Vec::new();
    for _ in 0..rounds {
        let addr = SocketAddr::from((ip, port));
        let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
        data.clear();
        stream.read_to_end(&mut data).expect("read");
    }
}

/// musl's TCP fallback (`res_msend.c`, 1.2.4+): a non-blocking socket with
/// `TCP_FASTOPEN_CONNECT`; the length and the query sent by one `sendmsg(MSG_FASTOPEN)` naming
/// the server, which connects (`EINPROGRESS` without a Fast Open cookie), the rest sent once
/// writable; the reply received by `recvmsg` into two buffers, the 2-byte length and the
/// message, each call continuing where the last one stopped.
fn musl_tcp(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(v4) = server else {
        panic!("tcp-musl needs an IPv4 server");
    };
    let addr = libc::sockaddr_in {
        sin_family: libc::sa_family_t::try_from(libc::AF_INET).expect("small"),
        sin_port: v4.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*v4.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let addr_len = libc::socklen_t::try_from(size_of_val(&addr)).expect("small");
    let flags = libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    // SAFETY: socket has no memory arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, flags, 0) };
    assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
    let mut length = u16::try_from(query.len()).expect("short").to_be_bytes();
    let one: libc::c_int = 1;
    let one_len = libc::socklen_t::try_from(size_of_val(&one)).expect("small");
    // SAFETY: setsockopt reads `one_len` bytes of `one`.
    let fastopen = unsafe {
        libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT, (&raw const one).cast(), one_len)
    } == 0;
    let mut query_buf = query.to_vec();
    let request = [(length.as_mut_ptr(), 2), (query_buf.as_mut_ptr(), query.len())];
    let mut sent = 0;
    let started = fastopen && {
        let r = msg(fd, &request, 0, Some((&addr, addr_len)), libc::MSG_FASTOPEN, false);
        sent = usize::try_from(r).unwrap_or(0);
        r >= 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS)
    };
    if !started {
        // SAFETY: connect reads `addr_len` bytes of `addr`.
        let r = unsafe { libc::connect(fd, (&raw const addr).cast(), addr_len) };
        let err = io::Error::last_os_error();
        assert!(r == 0 || err.raw_os_error() == Some(libc::EINPROGRESS), "connect: {err}");
    }
    while sent < 2 + query.len() {
        wait_for(fd, libc::POLLOUT);
        let r = msg(fd, &request, sent, None, 0, false);
        sent += usize::try_from(r).unwrap_or_else(|_| panic!("sendmsg: {}", io::Error::last_os_error()));
    }
    let mut alen = [0_u8; 2];
    let mut reply = vec![0_u8; 4096];
    let mut got = 0;
    loop {
        wait_for(fd, libc::POLLIN);
        let buffers = [(alen.as_mut_ptr(), 2), (reply.as_mut_ptr(), reply.len())];
        let r = msg(fd, &buffers, got, None, 0, true);
        assert!(r > 0, "recvmsg: {r}: {}", io::Error::last_os_error());
        got += usize::try_from(r).expect("positive");
        let want = 2 + usize::from(u16::from_be_bytes(alen));
        if got >= 2 && got >= want.min(2 + reply.len()) {
            break;
        }
    }
    // SAFETY: `fd` is ours.
    unsafe { libc::close(fd) };
    reply.truncate(usize::from(u16::from_be_bytes(alen)));
    reply
}

/// `sendmsg` (or with `recv`, `recvmsg`) on `fd` over `buffers` past their first `skip` bytes
/// (musl's `step_mh`), to `to` if given, with `flags` and `MSG_NOSIGNAL`.
fn msg(
    fd: libc::c_int,
    buffers: &[(*mut u8, usize)],
    skip: usize,
    to: Option<(&libc::sockaddr_in, libc::socklen_t)>,
    flags: libc::c_int,
    recv: bool,
) -> isize {
    let mut skip = skip;
    let mut iov = Vec::new();
    for &(base, len) in buffers {
        if skip >= len {
            skip -= len;
            continue;
        }
        iov.push(libc::iovec {
            iov_base: base.wrapping_add(skip).cast(),
            iov_len: len - skip,
        });
        skip = 0;
    }
    // SAFETY: an all-zero msghdr is an empty message.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_iov = iov.as_mut_ptr();
    mh.msg_iovlen = iov.len().try_into().expect("two buffers");
    if let Some((addr, len)) = to {
        mh.msg_name = std::ptr::from_ref(addr).cast_mut().cast();
        mh.msg_namelen = len;
    }
    // SAFETY: the iovecs point into live buffers of the given lengths; the name, if any, is
    // a sockaddr_in of `msg_namelen` bytes.
    unsafe {
        if recv {
            libc::recvmsg(fd, &raw mut mh, flags)
        } else {
            libc::sendmsg(fd, &raw const mh, flags | libc::MSG_NOSIGNAL)
        }
    }
}

/// Waits until `fd` has `events`.
fn wait_for(fd: libc::c_int, events: libc::c_short) {
    let mut pfd = libc::pollfd { fd, events, revents: 0 };
    // SAFETY: poll reads and writes one pollfd.
    let r = unsafe { libc::poll(&raw mut pfd, 1, 5000) };
    assert!(r == 1, "poll: {r}: {}", io::Error::last_os_error());
}

/// A recursive query for `name`, type A.
fn query(name: &str) -> Vec<u8> {
    let id = u16::try_from(std::process::id() & 0xffff).expect("masked");
    let mut msg = id.to_be_bytes().to_vec();
    msg.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        msg.push(u8::try_from(label.len()).expect("short label"));
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&TYPE_A.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg
}

/// The first A record of a reply to [`query`] (whose answers name the question by pointer,
/// as [`respond`] writes them).
fn answer(reply: &[u8]) -> Option<Ipv4Addr> {
    let answers = u16::from_be_bytes([*reply.get(6)?, *reply.get(7)?]);
    let mut at = 12;
    while *reply.get(at)? != 0 {
        at += 1 + usize::from(reply[at]);
    }
    at += 5;
    for _ in 0..answers {
        // A compression pointer (2 bytes), then type, class, TTL, length.
        let rtype = u16::from_be_bytes([*reply.get(at + 2)?, *reply.get(at + 3)?]);
        let len = usize::from(u16::from_be_bytes([*reply.get(at + 10)?, *reply.get(at + 11)?]));
        let data = reply.get(at + 12..at + 12 + len)?;
        if rtype == TYPE_A && len == 4 {
            return Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        at += 12 + len;
    }
    None
}

/// Serves `names` on UDP and TCP `addr` until standard input closes.
fn serve(addr: SocketAddr, names: HashMap<String, Ipv4Addr>) {
    let udp = UdpSocket::bind(addr).unwrap_or_else(|e| panic!("bind udp {addr}: {e}"));
    let tcp = TcpListener::bind(addr).unwrap_or_else(|e| panic!("bind tcp {addr}: {e}"));
    let names = std::sync::Arc::new(names);
    let udp_names = std::sync::Arc::clone(&names);
    std::thread::spawn(move || {
        let mut buf = [0; 512];
        while let Ok((len, peer)) = udp.recv_from(&mut buf) {
            if let Some(reply) = respond(&buf[..len], &udp_names) {
                let _ = udp.send_to(&reply, peer);
            }
        }
    });
    std::thread::spawn(move || {
        for mut stream in tcp.incoming().flatten() {
            let mut len = [0; 2];
            if stream.read_exact(&mut len).is_err() {
                continue;
            }
            let mut msg = vec![0; usize::from(u16::from_be_bytes(len))];
            if stream.read_exact(&mut msg).is_err() {
                continue;
            }
            if let Some(reply) = respond(&msg, &names) {
                let mut framed = u16::try_from(reply.len()).expect("short").to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                let _ = stream.write_all(&framed);
            }
        }
    });
    println!("ready");
    io::stdout().flush().expect("stdout");
    // Until the suite closes the pipe (or exits).
    let _ = io::copy(&mut io::stdin(), &mut io::sink());
}

/// The reply to `query`, or `None` for anything but a single-question query.
fn respond(query: &[u8], names: &HashMap<String, Ipv4Addr>) -> Option<Vec<u8>> {
    if query.len() < 12 || query[2] & 0x80 != 0 || query[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    while *query.get(at)? != 0 {
        let len = usize::from(query[at]);
        labels.push(String::from_utf8_lossy(query.get(at + 1..at + 1 + len)?).to_ascii_lowercase());
        at += 1 + len;
    }
    let question = query.get(12..at + 5)?;
    let qtype = u16::from_be_bytes([query[at + 1], query[at + 2]]);
    let ip = names.get(&labels.join("."));
    let mut reply = query[..2].to_vec();
    // Response, recursion desired and available; NXDOMAIN for unknown names.
    reply.extend_from_slice(&[0x81, if ip.is_some() { 0x80 } else { 0x83 }, 0, 1]);
    let answer = ip.filter(|_| qtype == TYPE_A);
    reply.extend_from_slice(&[0, u8::from(answer.is_some()), 0, 0, 0, 0]);
    reply.extend_from_slice(question);
    if let Some(ip) = answer {
        reply.extend_from_slice(&[0xc0, 12]);
        reply.extend_from_slice(&TYPE_A.to_be_bytes());
        reply.extend_from_slice(&CLASS_IN.to_be_bytes());
        reply.extend_from_slice(&60_u32.to_be_bytes());
        reply.extend_from_slice(&4_u16.to_be_bytes());
        reply.extend_from_slice(&ip.octets());
    }
    Some(reply)
}
