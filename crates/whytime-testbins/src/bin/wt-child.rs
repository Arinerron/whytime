//! `wt-child MS`: runs `wt-burn MS` (from the same directory) and waits for it.

fn main() {
    let ms: u64 = whytime_testbins::arg(1, "wt-child MS");
    let exe = std::env::current_exe().expect("current_exe");
    let burn = exe.with_file_name("wt-burn");
    let status = std::process::Command::new(&burn)
        .arg(ms.to_string())
        .status()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", burn.display()));
    assert!(status.success(), "wt-burn failed: {status}");
}
