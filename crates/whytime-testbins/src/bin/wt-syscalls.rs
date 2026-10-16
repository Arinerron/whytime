//! `wt-syscalls N`: N one-byte reads of `/dev/zero`, a syscall-bound workload for measuring
//! whytime's per-syscall overhead.

use std::io::Read as _;

fn main() {
    let rounds: u64 = whytime_testbins::arg(1, "wt-syscalls N");
    let mut zero = std::fs::File::open("/dev/zero").expect("open /dev/zero");
    let mut byte = [0_u8; 1];
    for _ in 0..rounds {
        zero.read_exact(&mut byte).expect("read /dev/zero");
    }
}
