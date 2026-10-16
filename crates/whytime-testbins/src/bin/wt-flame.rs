//! `wt-flame BURN_MS SLEEP_MS`: spins on the CPU in `burn_cpu_here` for BURN_MS, then sleeps
//! in `sleep_here` (nanosleep) for SLEEP_MS: functions the flamegraph checks look for. xtask
//! builds the testbins with frame pointers and symbols, so user stacks unwind through them.

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let usage = "wt-flame BURN_MS SLEEP_MS";
    let burn = whytime_testbins::arg(1, usage);
    let sleep = whytime_testbins::arg(2, usage);
    burn_cpu_here(burn);
    sleep_here(sleep);
    // Not a tail call: main's frame stays under both.
    black_box(());
}

/// Spins for `ms` milliseconds; the clock is read (through the vDSO) once per ~million
/// iterations, so samples land in this function.
#[inline(never)]
fn burn_cpu_here(ms: u64) {
    let until = Instant::now() + whytime_testbins::millis(ms);
    let mut x = 0_u64;
    while Instant::now() < until {
        for i in 0..1_000_000 {
            x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
        }
    }
    black_box(x);
}

/// Sleeps `ms` milliseconds. With frame pointers, a stack shows the callers of the innermost
/// function that has one: [`nanosleep`] keeps this frame visible under a libc without them.
#[inline(never)]
fn sleep_here(ms: u64) {
    nanosleep(ms);
    // Not a tail call, which would drop this frame.
    black_box(());
}

/// `std::thread::sleep` (nanosleep), in a frame of its own.
#[inline(never)]
fn nanosleep(ms: u64) {
    std::thread::sleep(whytime_testbins::millis(ms));
    black_box(());
}
