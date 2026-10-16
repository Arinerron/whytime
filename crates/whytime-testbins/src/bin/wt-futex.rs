//! `wt-futex MS`: a second thread takes a mutex and holds it for MS milliseconds; the main
//! thread blocks on the same mutex (a futex wait) until it is released.

use std::sync::{Arc, Barrier, Mutex};

fn main() {
    let ms = whytime_testbins::arg(1, "wt-futex MS");
    let lock = Arc::new(Mutex::new(0_u32));
    let held = Arc::new(Barrier::new(2));
    let holder = {
        let lock = Arc::clone(&lock);
        let held = Arc::clone(&held);
        std::thread::spawn(move || {
            let mut guard = lock.lock().expect("lock");
            held.wait();
            std::thread::sleep(whytime_testbins::millis(ms));
            *guard += 1;
        })
    };
    held.wait();
    *lock.lock().expect("lock") += 1;
    holder.join().expect("join");
}
