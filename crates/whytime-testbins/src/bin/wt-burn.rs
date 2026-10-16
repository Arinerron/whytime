//! `wt-burn MS`: spins on the CPU for MS milliseconds without making syscalls (the clock is
//! read through the vDSO).

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let ms = whytime_testbins::arg(1, "wt-burn MS");
    let until = Instant::now() + whytime_testbins::millis(ms);
    let mut x = 0_u64;
    while Instant::now() < until {
        for i in 0..10_000 {
            x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
        }
    }
    black_box(x);
}
