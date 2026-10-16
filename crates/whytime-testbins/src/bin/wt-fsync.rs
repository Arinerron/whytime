//! `wt-fsync DIR N`: N rounds of (write 4 KiB, fdatasync) to a fresh file in DIR, which is
//! removed afterwards. DIR must be on a real filesystem (not tmpfs) for fdatasync to wait.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::PathBuf;

fn main() {
    let usage = "wt-fsync DIR N";
    let dir: PathBuf = whytime_testbins::arg(1, usage);
    let rounds: u32 = whytime_testbins::arg(2, usage);
    let path = dir.join(format!("wt-fsync.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    let block = [0x5a_u8; 4096];
    for _ in 0..rounds {
        file.write_all(&block).expect("write");
        file.sync_data().expect("fdatasync");
    }
    drop(file);
    std::fs::remove_file(&path).expect("remove");
}
