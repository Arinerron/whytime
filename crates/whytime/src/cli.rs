//! Command-line interface.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

/// Explain where a command's wall-clock time went.
///
/// Runs COMMAND, traces it and every process it starts with eBPF, and prints to stderr where
/// its wall time went: on-CPU, waiting on children, sleeping, fsync, network peers, locks.
/// COMMAND's own output passes through, and whytime exits with COMMAND's exit code. With
/// `-p PID`, observes a running process and its descendants instead.
#[derive(Debug, Parser)]
#[command(
    name = "whytime",
    version,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    after_help = "Exit status: COMMAND's; 125 if whytime could not start tracing; \
                  126/127 if COMMAND is not executable / not found. With -p: 0 after the \
                  report, 1 if PID cannot be attached to, 125 if tracing could not start."
)]
pub struct Cli {
    #[command(subcommand)]
    pub sub: Option<Sub>,

    #[command(flatten)]
    pub run: RunArgs,
}

/// Wrap and attach mode.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// How to print the report, and what else to write.
    #[command(flatten)]
    pub output: OutputArgs,

    /// Stop observing after D (e.g. 500ms, 30s, 2m) and report; COMMAND (or PID) keeps
    /// running, and whytime still exits with COMMAND's code.
    #[arg(long, value_name = "D", value_parser = parse_duration)]
    pub duration: Option<Duration>,

    /// Also write a trace file to FILE, from which `whytime report FILE` prints the same
    /// report offline.
    #[arg(long, value_name = "FILE")]
    pub record: Option<PathBuf>,
    /// Attach to the running process PID and its descendants instead of running COMMAND;
    /// report when it exits, --duration elapses or on Ctrl-C (never signals PID).
    #[arg(
        short = 'p',
        long = "pid",
        value_name = "PID",
        conflicts_with = "command",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub pid: Option<u32>,

    /// The command to run, and its arguments.
    #[arg(
        value_name = "COMMAND",
        required_unless_present = "pid",
        trailing_var_arg = true
    )]
    pub command: Vec<OsString>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Sub {
    /// Check whether whytime can run on this system and print exact fixes.
    Doctor {
        /// Print the report as JSON (schema bpfdoctor/1).
        #[arg(long)]
        json: bool,
    },
    /// Print the report of a trace file written by `--record`, exactly as it was recorded.
    /// Needs no privileges. Exit status 0, or 2 if FILE cannot be replayed.
    Report {
        /// The trace file.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// How to print the report, and what else to write.
        #[command(flatten)]
        output: OutputArgs,
    },
    /// Print a shell completion script to stdout.
    Completions {
        /// The shell to generate for.
        shell: Shell,
    },
}

/// Report options shared by wrap mode, attach mode and `report` (replay).
#[derive(Clone, Debug, Default, Args)]
pub struct OutputArgs {
    /// Print the report as JSON (schema whytime.report/1).
    #[arg(long)]
    pub json: bool,

    /// Also write the window as a Chrome Trace Event JSON file to FILE (open it in
    /// ui.perfetto.dev or chrome://tracing): every traced thread's on-CPU, runqueue and
    /// blocked stretches, and the critical path.
    #[arg(long, value_name = "FILE")]
    pub perfetto: Option<PathBuf>,

    /// Write a wall-clock flamegraph of the critical path to FILE (SVG): its width is the
    /// window, each stack a report line, process and call stack. Samples stacks while
    /// tracing; `report` draws one only from a trace recorded with it (or --folded).
    #[arg(long, value_name = "FILE")]
    pub flamegraph: Option<PathBuf>,

    /// Write the flamegraph's stacks to FILE in folded format (`frame;frame;... count`,
    /// counts in microseconds), for inferno, flamegraph.pl or speedscope.
    #[arg(long, value_name = "FILE")]
    pub folded: Option<PathBuf>,

    /// Add a timeline to the report: the window in equal slices, each with its largest
    /// lines.
    #[arg(long)]
    pub timeline: bool,
}

impl OutputArgs {
    /// Whether stacks are needed (`--flamegraph` or `--folded`).
    pub fn stacks(&self) -> bool {
        self.flamegraph.is_some() || self.folded.is_some()
    }
}

/// Parses `500ms`, `30s`, `1.5s`, `2m`, `1h`; a bare number is seconds.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let split = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let value: f64 = number
        .parse()
        .map_err(|_| format!("invalid duration {text:?}: expected e.g. 500ms, 30s, 2m"))?;
    let scale = match unit {
        "ms" => 1e-3,
        "" | "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        _ => return Err(format!("invalid duration unit {unit:?}: use ms, s, m or h")),
    };
    Duration::try_from_secs_f64(value * scale)
        .ok()
        .filter(|d| !d.is_zero())
        .ok_or_else(|| format!("invalid duration {text:?}: must be positive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_with_units_and_reject_zero_or_junk() {
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("2m"), Ok(Duration::from_secs(120)));
        assert_eq!(parse_duration("3"), Ok(Duration::from_secs(3)));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("s").is_err());
    }

    #[test]
    fn command_words_after_the_command_belong_to_it() {
        let cli = Cli::try_parse_from(["whytime", "--json", "ls", "--json", "-l"]).unwrap();
        assert!(cli.sub.is_none());
        assert!(cli.run.output.json);
        assert_eq!(cli.run.command, ["ls", "--json", "-l"]);

        let cli = Cli::try_parse_from(["whytime", "--", "doctor"]).unwrap();
        assert!(cli.sub.is_none());
        assert_eq!(cli.run.command, ["doctor"]);

        let cli = Cli::try_parse_from(["whytime", "doctor", "--json"]).unwrap();
        assert!(matches!(cli.sub, Some(Sub::Doctor { json: true })));

        let cli = Cli::try_parse_from(["whytime", "completions", "zsh"]).unwrap();
        assert!(matches!(cli.sub, Some(Sub::Completions { shell: Shell::Zsh })));
        assert!(Cli::try_parse_from(["whytime", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn misspelled_options_are_errors_and_dash_commands_need_the_separator() {
        for argv in [
            &["whytime", "--duraton", "5", "--", "true"][..],
            &["whytime", "--recrod", "t.wt", "ls"],
            &["whytime", "-weird", "a"],
        ] {
            let err = Cli::try_parse_from(argv).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument, "{argv:?}");
        }
        let cli = Cli::try_parse_from(["whytime", "--", "-weird", "a"]).unwrap();
        assert_eq!(cli.run.command, ["-weird", "a"]);
    }

    #[test]
    fn record_is_a_run_option_and_report_a_subcommand() {
        let cli =
            Cli::try_parse_from(["whytime", "--record", "t.wt", "--", "report", "x"]).unwrap();
        assert!(cli.sub.is_none());
        assert_eq!(cli.run.record, Some(PathBuf::from("t.wt")));
        assert_eq!(cli.run.command, ["report", "x"]);

        let cli = Cli::try_parse_from(["whytime", "report", "t.wt", "--json"]).unwrap();
        assert!(matches!(
            cli.sub,
            Some(Sub::Report { ref file, ref output }) if file.as_os_str() == "t.wt" && output.json
        ));
    }

    #[test]
    fn report_options_parse_alike_in_every_mode_and_never_after_the_command() {
        let extras = ["--perfetto", "t.json", "--timeline"];
        let check = |output: &OutputArgs| {
            assert_eq!(output.perfetto, Some(PathBuf::from("t.json")));
            assert!(output.timeline);
        };
        let wrap = Cli::try_parse_from(["whytime"].into_iter().chain(extras).chain(["ls"]));
        check(&wrap.unwrap().run.output);
        let attach = Cli::try_parse_from(["whytime", "-p", "42"].into_iter().chain(extras));
        check(&attach.unwrap().run.output);
        let replay = Cli::try_parse_from(["whytime", "report", "t.wt"].into_iter().chain(extras));
        let Some(Sub::Report { output, .. }) = replay.unwrap().sub else {
            panic!("not the report subcommand");
        };
        check(&output);

        let cli = Cli::try_parse_from(["whytime", "ls", "--timeline"]).unwrap();
        assert!(!cli.run.output.timeline);
        assert_eq!(cli.run.command, ["ls", "--timeline"]);
    }

    #[test]
    fn pid_replaces_the_command_and_excludes_it() {
        let cli = Cli::try_parse_from(["whytime", "-p", "42", "--json"]).unwrap();
        assert_eq!(cli.run.pid, Some(42));
        assert!(cli.run.output.json);
        assert!(cli.run.command.is_empty());
        let cli = Cli::try_parse_from(["whytime", "-p", "42", "--record", "t.wt"]).unwrap();
        assert_eq!(cli.run.record, Some(PathBuf::from("t.wt")));
        assert!(Cli::try_parse_from(["whytime", "--pid", "42", "--", "ls"]).is_err());
        assert!(Cli::try_parse_from(["whytime", "-p", "0"]).is_err());
        assert!(Cli::try_parse_from(["whytime", "--json"]).is_err());
    }
}
