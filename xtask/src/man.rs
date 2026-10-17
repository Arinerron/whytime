//! `cargo xtask man [DIR]`: the man pages, `whytime.1` and one `whytime-SUB.1` per
//! subcommand.
//!
//! Each page is a hand-written roff template (`xtask/man/*.1.in`) in which a line
//! `.\" @SECTION` stands for a whole section, heading included, that clap_mangen renders from
//! the binary's own clap definition (`crates/whytime/src/cli.rs`, compiled into xtask), so
//! the option lists cannot drift from the code:
//!
//! - `@OPTIONS`: every option and positional argument with its help text (required on
//!   every page);
//! - `@COMMANDS`: the subcommands with their one-line summaries;
//! - `@SYNOPSIS`: clap_mangen's usage line, used where it is accurate (it leaves out option
//!   values, so pages with valued options write their synopsis by hand).
//!
//! The title line carries the workspace version and the date of the newest released
//! `## [X.Y.Z] - YYYY-MM-DD` entry of CHANGELOG.md, compiled in, so the output is the same
//! bytes on every run and machine (also in the Nix build, which runs the xtask binary after
//! the build). The templates' own `.\"` comments are left out, and every page turns off
//! hyphenation ([`NO_HYPHENATION`]).

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};
use clap::CommandFactory as _;
use clap_mangen::Man;

use crate::cli;

/// Each page: the subcommand it documents (`None`: the top-level command) and its template.
const PAGES: [(Option<&str>, &str); 4] = [
    (None, include_str!("../man/whytime.1.in")),
    (Some("report"), include_str!("../man/whytime-report.1.in")),
    (Some("doctor"), include_str!("../man/whytime-doctor.1.in")),
    (Some("completions"), include_str!("../man/whytime-completions.1.in")),
];
/// Release history; its newest released entry dates the pages.
const CHANGELOG: &str = include_str!("../../CHANGELOG.md");
/// What the `roff` crate writes before every rendered fragment (defines `\*(Aq`); the
/// fragments are spliced into one page, which starts with it once.
const ROFF_PREAMBLE: &str = ".ie \\n(.g .ds Aq \\(aq\n.el .ds Aq '\n";
/// Starts a roff comment line: the templates' own notes, left out of the pages.
const COMMENT: &str = ".\\\"";
/// Marks a template line that a generated section replaces.
const MARKER: &str = ".\\\" @";
/// The pages are full of identifiers (`kernel.perf_event_paranoid`, `CAP_SYS_PTRACE`,
/// `whytime`) that must not be broken at a hyphen. groff's man macros reset the hyphenation
/// mode at every paragraph from the `HY` register, which a page may set after `.TH`;
/// mandoc does not hyphenate.
const NO_HYPHENATION: &str = ".nr HY 0\n";
/// Longest text line written for the generated sections, where spaces allow.
const MAX_LINE: usize = 80;

/// Writes the pages to `dir` (default `$CARGO_TARGET_DIR/man`, else `target/man`).
pub fn man(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = match dir {
        Some(dir) => dir,
        None => std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(
                || Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"),
                PathBuf::from,
            )
            .join("man"),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    for (name, text) in pages()? {
        let path = dir.join(name);
        std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    }
    println!("{}", dir.display());
    Ok(())
}

/// Every page: file name and contents.
fn pages() -> anyhow::Result<Vec<(String, String)>> {
    let date = release_date(CHANGELOG)?;
    let source = format!("whytime {}", env!("CARGO_PKG_VERSION"));
    let mut root = cli::Cli::command()
        .disable_help_subcommand(true)
        .subcommand_help_heading("COMMANDS");
    root.build();
    // A subcommand without a page would ship undocumented.
    for sub in root.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        ensure!(
            PAGES.iter().any(|(name, _)| *name == Some(sub.get_name())),
            "the `{}` subcommand has no man page template in xtask/man",
            sub.get_name()
        );
    }
    PAGES
        .iter()
        .map(|&(sub, template)| {
            let cmd = match sub {
                None => root.clone(),
                Some(sub) => root
                    .find_subcommand(sub)
                    .with_context(|| format!("no `{sub}` subcommand in cli.rs"))?
                    .clone(),
            };
            let man = Man::new(cmd)
                .date(date)
                .source(&source)
                .manual("User Commands");
            let name = man.get_filename();
            let man = man.title(name.trim_end_matches(".1").to_uppercase());
            let text =
                page(&name, &man, template).with_context(|| format!("rendering {name}"))?;
            Ok((name, text))
        })
        .collect()
}

/// `template` (of page `name`) with the title line in front, its markers replaced and its
/// own comments left out.
fn page(name: &str, man: &Man, template: &str) -> anyhow::Result<String> {
    let mut out = format!(
        ".\\\" Generated by cargo xtask man from xtask/man/{name}.in and\n\
         .\\\" crates/whytime/src/cli.rs; edit those, not this file.\n{ROFF_PREAMBLE}"
    );
    out += &generated(|w| man.render_title(w))?;
    out += NO_HYPHENATION;
    let mut options = false;
    for line in template.lines() {
        let Some(marker) = line.strip_prefix(MARKER) else {
            if !line.starts_with(COMMENT) {
                out += line;
                out.push('\n');
            }
            continue;
        };
        out += &match marker {
            "SYNOPSIS" => generated(|w| man.render_synopsis_section(w))?,
            "OPTIONS" => {
                options = true;
                generated(|w| man.render_options_section(w))?
            }
            "COMMANDS" => generated(|w| man.render_subcommands_section(w))?,
            _ => bail!("unknown marker `{line}`"),
        };
    }
    ensure!(options, "the template has no `{MARKER}OPTIONS` line");
    Ok(out)
}

/// A clap_mangen section as roff lines to splice into a page, in the templates' style:
/// without the preamble; the help texts' `code` spans in bold; a blank line (vertical space
/// in roff) as `.sp`, without the `.br`s around it, which it implies; text lines wrapped at
/// [`MAX_LINE`] bytes, without trailing spaces.
fn generated(
    render: impl FnOnce(&mut dyn std::io::Write) -> std::io::Result<()>,
) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    render(&mut bytes)?;
    let text = String::from_utf8(bytes).context("clap_mangen wrote non-UTF-8")?;
    let body = text
        .strip_prefix(ROFF_PREAMBLE)
        .context("clap_mangen's output does not start with the roff preamble")?;
    let mut lines: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = if line.is_empty() { ".sp".to_owned() } else { bold_code(line)? };
        match (line.as_str(), lines.last().map(String::as_str)) {
            (".br", Some(".br" | ".sp")) => continue,
            (".sp", Some(".br")) => {
                lines.pop();
            }
            _ => {}
        }
        lines.push(line);
    }
    let mut out = String::new();
    for line in &lines {
        if line.starts_with(['.', '\'']) {
            out += line;
            out.push('\n');
        } else {
            wrap(line, &mut out);
        }
    }
    Ok(out)
}

/// `line` with its `code` spans (the help texts' Markdown) in bold.
fn bold_code(line: &str) -> anyhow::Result<String> {
    let spans: Vec<&str> = line.split('`').collect();
    ensure!(spans.len() % 2 == 1, "unbalanced ` in help text: {line}");
    let mut out = String::new();
    for (i, span) in spans.iter().enumerate() {
        if i % 2 == 1 {
            out += "\\fB";
            out += span;
            out += "\\fR";
        } else {
            out += span;
        }
    }
    Ok(out)
}

/// Appends roff text line `line` to `out` as lines of at most [`MAX_LINE`] bytes where
/// spaces allow.
fn wrap(line: &str, out: &mut String) {
    let mut current = String::new();
    for word in line.split(' ') {
        if !current.is_empty() && current.len() + 1 + word.len() > MAX_LINE {
            // roff takes a line ending in a period for the end of a sentence and widens the
            // space after it; `\&` keeps the original single space.
            let end = current.trim_end_matches([')', ']', '"', '\'', '*']);
            if end.ends_with(['.', '?', '!']) {
                current += "\\&";
            }
            push_text(&current, out);
            current.clear();
        } else if !current.is_empty() {
            current.push(' ');
        }
        current += word;
    }
    push_text(&current, out);
}

/// Appends one text line, without trailing spaces and with `\&` before a leading `.` or `'`
/// (a control line otherwise).
fn push_text(line: &str, out: &mut String) {
    if line.starts_with(['.', '\'']) {
        *out += "\\&";
    }
    *out += line.trim_end_matches(' ');
    out.push('\n');
}

/// The date of the newest released version in `changelog` (its first `## [X.Y.Z] -
/// YYYY-MM-DD` heading; `## [Unreleased]` has no date).
fn release_date(changelog: &str) -> anyhow::Result<&str> {
    changelog
        .lines()
        .find_map(|line| {
            let (version, date) = line.strip_prefix("## [")?.split_once("] - ")?;
            let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            let parts: Vec<&str> = version.split('.').collect();
            let dated = date.len() == 10
                && date.bytes().enumerate().all(|(i, b)| {
                    if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() }
                });
            (parts.len() == 3 && parts.iter().all(|part| numeric(part)) && dated).then_some(date)
        })
        .context("CHANGELOG.md has no released `## [X.Y.Z] - YYYY-MM-DD` entry")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_date_skips_unreleased_and_malformed_headings() {
        let changelog = "# Changelog\n\n## [Unreleased]\n\n- x\n\n## [1.2] - 2026-01-01\n\
                         ## [0.2.0] - 2026-1-02\n## [0.1.1] - 2026-10-16\n## [0.1.0] - 2026-10-01\n";
        assert_eq!(release_date(changelog).unwrap(), "2026-10-16");
        assert!(release_date("## [Unreleased]\n").is_err());
    }

    #[test]
    fn every_page_has_the_standard_sections_once() {
        let pages = pages().unwrap();
        let names: Vec<&str> = pages.iter().map(|(name, _)| name.as_str()).collect();
        // Packaging installs DIR/*.1 by these names.
        assert_eq!(
            names,
            ["whytime.1", "whytime-report.1", "whytime-doctor.1", "whytime-completions.1"]
        );
        for (name, text) in &pages {
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.iter().filter(|l| l.starts_with(".TH ")).count(), 1, "{name}");
            for section in [
                "NAME",
                "SYNOPSIS",
                "DESCRIPTION",
                "OPTIONS",
                "EXIT STATUS",
                "EXAMPLES",
                "SEE ALSO",
            ] {
                let heading = format!(".SH {section}");
                let count = lines.iter().filter(|l| **l == heading).count();
                assert_eq!(count, 1, "{name}: {heading}");
            }
            assert!(!text.contains('`'), "{name} has a Markdown code span");
        }
    }
}
