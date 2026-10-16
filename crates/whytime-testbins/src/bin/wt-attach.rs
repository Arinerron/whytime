//! `wt-attach SLEEP_MS BURN_MS`: sleeps SLEEP_MS, then runs `wt-burn BURN_MS` (from the same
//! directory) and waits for it: a parent that starts a child after whytime attached to it.

fn main() {
    let usage = "wt-attach SLEEP_MS BURN_MS";
    let sleep = whytime_testbins::arg(1, usage);
    let burn: u64 = whytime_testbins::arg(2, usage);
    std::thread::sleep(whytime_testbins::millis(sleep));
    let exe = std::env::current_exe().expect("current_exe");
    let burner = exe.with_file_name("wt-burn");
    let status = std::process::Command::new(&burner)
        .arg(burn.to_string())
        .status()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", burner.display()));
    assert!(status.success(), "wt-burn failed: {status}");
}
