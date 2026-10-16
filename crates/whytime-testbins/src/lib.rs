//! Small workloads with known wall-time profiles, one binary each, for whytime's end-to-end
//! suite (`cargo xtask test-e2e`). They print nothing on success, so whytime's report is the
//! only thing on stderr.

use std::time::Duration;

/// The `index`-th command-line argument parsed as `T`; exits with usage on failure.
pub fn arg<T: std::str::FromStr>(index: usize, usage: &str) -> T {
    std::env::args()
        .nth(index)
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| {
            eprintln!("usage: {usage}");
            std::process::exit(2)
        })
}

/// Milliseconds as a `Duration`.
pub fn millis(ms: u64) -> Duration {
    Duration::from_millis(ms)
}
