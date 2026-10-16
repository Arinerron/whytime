//! `wt-tcp ADDR N`: N times, connects to ADDR and reads until the server closes.

use std::io::Read as _;
use std::net::{SocketAddr, TcpStream};

fn main() {
    let usage = "wt-tcp ADDR N";
    let addr: SocketAddr = whytime_testbins::arg(1, usage);
    let rounds: u32 = whytime_testbins::arg(2, usage);
    let mut reply = Vec::new();
    for _ in 0..rounds {
        let mut stream = TcpStream::connect(addr).unwrap_or_else(|e| panic!("connect {addr}: {e}"));
        reply.clear();
        stream.read_to_end(&mut reply).expect("read");
    }
}
