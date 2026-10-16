//! `wt-dns udp|tcp SERVER NAME PORT N` resolves NAME with one DNS query (type A) to SERVER,
//! then N times connects to the answer's address on PORT and reads until the peer closes.
//! `udp` sends the query from an unconnected socket (`sendto`/`recvfrom`, as musl does);
//! `tcp` connects to SERVER and reads the 2-byte length and the message separately (as glibc
//! does).
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
    let usage = "wt-dns udp|tcp SERVER NAME PORT N | wt-dns serve ADDR NAME=IPV4...";
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
