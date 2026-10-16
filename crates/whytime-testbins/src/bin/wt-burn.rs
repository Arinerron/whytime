//! `wt-burn MS [EVERY_MS]`: spins on the CPU for MS milliseconds without making syscalls (the
//! clock is read through the vDSO). With EVERY_MS, it naps 1 ms after every EVERY_MS of
//! spinning, so its time is cut into many scheduling stretches.

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let usage = "wt-burn MS [EVERY_MS]";
    let ms = whytime_testbins::arg(1, usage);
    let every = std::env::args()
        .nth(2)
        .map(|_| whytime_testbins::millis(whytime_testbins::arg(2, usage)));
    let until = Instant::now() + whytime_testbins::millis(ms);
    let mut nap_at = every.map(|every| Instant::now() + every);
    let mut x = 0_u64;
    loop {
        let now = Instant::now();
        if now >= until {
            break;
        }
        if let (Some(at), Some(every)) = (nap_at, every)
            && now >= at
        {
            std::thread::sleep(whytime_testbins::millis(1));
            nap_at = Some(Instant::now() + every);
        }
        for i in 0..10_000 {
            x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
        }
    }
    black_box(x);
}
