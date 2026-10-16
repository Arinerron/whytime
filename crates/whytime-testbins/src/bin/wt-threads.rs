//! `wt-threads N MS [WAIT_MS]`: N threads spin on the CPU until MS milliseconds after start,
//! without making syscalls. The main thread joins them (futex waits that the exiting threads
//! end), or with WAIT_MS first waits for them on a condition variable in timed waits of
//! WAIT_MS that mostly time out, the way xz and CPython's GIL wait.

use std::hint::black_box;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

fn main() {
    let usage = "wt-threads N MS [WAIT_MS]";
    let n: usize = whytime_testbins::arg(1, usage);
    let ms = whytime_testbins::arg(2, usage);
    let wait = std::env::args()
        .nth(3)
        .map(|_| whytime_testbins::millis(whytime_testbins::arg(3, usage)));
    let until = Instant::now() + whytime_testbins::millis(ms);
    let done = Arc::new((Mutex::new(0_usize), Condvar::new()));
    let threads: Vec<_> = (0..n)
        .map(|_| {
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                spin(until);
                let (count, finished) = &*done;
                *count.lock().expect("lock") += 1;
                finished.notify_one();
            })
        })
        .collect();
    if let Some(wait) = wait {
        let (count, finished) = &*done;
        let mut count = count.lock().expect("lock");
        while *count < n {
            count = finished.wait_timeout(count, wait).expect("wait").0;
        }
    }
    for thread in threads {
        thread.join().expect("join");
    }
}

/// Spins until `until` (the clock is read through the vDSO).
fn spin(until: Instant) {
    let mut x = 0_u64;
    while Instant::now() < until {
        for i in 0..10_000 {
            x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
        }
    }
    black_box(x);
}
