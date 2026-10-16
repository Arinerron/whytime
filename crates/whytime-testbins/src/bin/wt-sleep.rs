//! `wt-sleep MS`: one timer sleep (`clock_nanosleep`).

fn main() {
    let ms = whytime_testbins::arg(1, "wt-sleep MS");
    std::thread::sleep(whytime_testbins::millis(ms));
}
