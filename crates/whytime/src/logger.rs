//! A minimal stderr logger; `WHYTIME_LOG=error|warn|info|debug|trace` (default `warn`).
//!
//! Every stderr write of whytime goes through [`stderr!`], which ignores write errors:
//! `eprintln!` panics on them, and a closed stderr (`whytime -- make 2>&1 | head`, EPIPE)
//! must neither abort whytime nor change its exit code.

use log::{Level, LevelFilter, Log, Metadata, Record};

/// `eprintln!` that ignores write errors (EPIPE from a closed pipe, ...).
macro_rules! stderr {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}
pub(crate) use stderr;

struct Stderr;

impl Log for Stderr {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            let level = match record.level() {
                Level::Error => "error",
                Level::Warn => "warning",
                Level::Info => "info",
                Level::Debug => "debug",
                Level::Trace => "trace",
            };
            stderr!("whytime: {level}: {}", record.args());
        }
    }

    fn flush(&self) {}
}

/// Installs the logger with the level from `WHYTIME_LOG`.
pub fn init() {
    let level = std::env::var("WHYTIME_LOG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(LevelFilter::Warn);
    if log::set_logger(&Stderr).is_ok() {
        log::set_max_level(level);
    }
}
