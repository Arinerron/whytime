//! `whytime doctor` and the start-up diagnostics: the shared bpfdoctor checks plus whytime's
//! own probes (`probe.sched`, `probe.syscalls`, `probe.dns`, `probe.readiness`,
//! `probe.faults`), which load and attach the real programs.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use bpfdoctor::{
    Cap, Check, Diagnostic, Doctor, Env, Fix, RealEnv, Report, Status, Tool, errno_name,
};

use crate::sys::SyscallTable;
use crate::tracer::{self, DNS, FAULTS, READINESS, SCHED, SYSCALLS, Tracer};

/// whytime as bpfdoctor sees it.
pub fn tool() -> Tool {
    Tool {
        name: "whytime",
        exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe")),
        required_caps: &[Cap::Bpf, Cap::Perfmon],
        optional_caps: &[(
            Cap::SysPtrace,
            "file paths of descendants that run as another user (setuid programs)",
        )],
        // sched_switch passes prev_state since 5.18.
        min_kernel: (5, 18),
        // 4 MiB ring buffer, 32768 task states (304 B), 16384 tracked pids, programs.
        memlock_bytes: 24 << 20,
    }
}

/// The full doctor: shared checks, then whytime's probes.
pub fn full() -> Doctor {
    let mut doctor = Doctor::with_shared();
    let probe = Arc::new(Probe::default());
    doctor.add(Box::new(SchedCheck(Arc::clone(&probe))));
    for index in 0..OPTIONAL.len() {
        doctor.add(Box::new(OptionalCheck {
            probe: Arc::clone(&probe),
            index,
        }));
    }
    doctor
}

/// `whytime doctor`: exit code 0 when whytime can run, 3 when it cannot.
pub fn run(json: bool) -> io::Result<i32> {
    let report = full().run(&RealEnv, &tool());
    let mut out = io::stdout().lock();
    if json {
        report.render_json(&mut out)?;
    } else {
        report.render_human(&mut out, color(libc::STDOUT_FILENO))?;
    }
    out.flush()?;
    Ok(if report.has_fail() { 3 } else { 0 })
}

/// Renders a start-up diagnosis to stderr.
pub fn print(report: &Report) {
    let mut err = io::stderr().lock();
    // Diagnostics are best effort: a closed stderr must not mask the original failure.
    let _ = report.render_human(&mut err, color(libc::STDERR_FILENO));
}

fn color(fd: libc::c_int) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    std::env::var_os("NO_COLOR").is_none() && unsafe { libc::isatty(fd) } == 1
}

/// Outcome of loading the real object once, shared by every probe check.
#[derive(Default)]
struct Probe {
    outcome: OnceLock<Outcome>,
}

struct Outcome {
    sched: Result<String, anyhow::Error>,
    /// The optional program sets, in [`OPTIONAL`] order; `None` when the scheduler probe
    /// failed and nothing else was tried.
    optional: Option<[Result<String, anyhow::Error>; 4]>,
}

impl Probe {
    fn get(&self) -> &Outcome {
        self.outcome
            .get_or_init(|| match Tracer::load(&SyscallTable::new()) {
                Ok(loaded) => {
                    let sizes = loaded.tracer.program_sizes();
                    let attached = |what: &str, set: &[(&str, &str)]| {
                        let insns: u32 = sizes
                            .iter()
                            .filter(|(name, _)| set.iter().any(|(prog, _)| prog == name))
                            .map(|(_, n)| n)
                            .sum();
                        format!("{what} loaded and attached ({insns} verified insns)")
                    };
                    let sched = attached(&format!("{} tp_btf programs", SCHED.len()), &SCHED);
                    let optional = [
                        loaded
                            .syscalls
                            .map(|()| attached("tp_btf/sys_enter and sys_exit", &SYSCALLS)),
                        loaded
                            .dns
                            .map(|()| attached("tp_btf/sys_exit with resolver capture", &[DNS])),
                        loaded.readiness.map(|()| {
                            attached("fentry/pollwake and ep_poll_callback", &READINESS)
                        }),
                        loaded
                            .faults
                            .map(|()| attached("fentry and fexit/handle_mm_fault", &FAULTS)),
                    ];
                    Outcome {
                        sched: Ok(sched),
                        optional: Some(optional),
                    }
                }
                Err(err) => Outcome {
                    sched: Err(err),
                    optional: None,
                },
            })
    }
}

/// `error: EPERM (Operation not permitted)`, naming the errno when there is one.
pub fn describe(err: &anyhow::Error) -> String {
    let what = err.to_string();
    match tracer::errno(err) {
        Some(errno) => format!(
            "{what}: {} ({})",
            errno_name(errno).unwrap_or("errno"),
            io::Error::from_raw_os_error(errno)
        ),
        None => format!("{what}: {err:#}"),
    }
}

/// Fixes for a failed load or attach, by errno.
fn fixes(err: &anyhow::Error, tool: &Tool) -> Vec<Fix> {
    match tracer::errno(err) {
        Some(libc::EPERM | libc::EACCES) => vec![
            Fix::new(
                tool.setcap_command(&[], &tool.exe),
                "one-time; re-run after every reinstall",
            ),
            Fix::new(format!("sudo {}", tool.exe.display()), "run with root"),
        ],
        Some(libc::ENOENT | libc::EINVAL | libc::E2BIG | libc::EOPNOTSUPP) => vec![Fix::new(
            "upgrade to Linux >= 5.18 built with CONFIG_DEBUG_INFO_BTF=y",
            "BTF tracepoints and sched_switch's prev_state argument",
        )],
        _ => vec![debug_fix(tool)],
    }
}

/// Fixes for a failed fentry/fexit set on `functions`.
fn fentry_fixes(err: &anyhow::Error, tool: &Tool, functions: &str) -> Vec<Fix> {
    match tracer::errno(err) {
        Some(libc::EPERM | libc::EACCES) => fixes(err, tool),
        _ => vec![
            Fix::new(
                "Linux with BPF trampolines (x86-64 >= 5.5, arm64 >= 6.0) and \
                 CONFIG_DEBUG_INFO_BTF=y",
                format!("fentry/fexit on {functions}, which must be in the kernel's BTF"),
            ),
            debug_fix(tool),
        ],
    }
}

fn debug_fix(tool: &Tool) -> Fix {
    Fix::new(
        format!("WHYTIME_LOG=debug {} doctor", tool.exe.display()),
        "prints the verifier log",
    )
}

struct SchedCheck(Arc<Probe>);

impl Check for SchedCheck {
    fn id(&self) -> &'static str {
        "probe.sched"
    }

    fn run(&self, _env: &dyn Env, tool: &Tool) -> Diagnostic {
        const TITLE: &str = "Scheduler tracepoints";
        match &self.0.get().sched {
            Ok(observed) => {
                Diagnostic::new(self.id(), TITLE, true, Status::Pass, observed.as_str())
            }
            Err(err) => {
                let mut diag = Diagnostic::new(self.id(), TITLE, true, Status::Fail, describe(err))
                    .with_impact("whytime cannot observe scheduling and will not run")
                    .with_explain(
                        "the timeline is built from tp_btf/sched_switch (with prev_state, \
                         5.18+), sched_waking and sched_process_fork/exec/exit",
                    );
                for fix in fixes(err, tool) {
                    diag = diag.with_fix(fix);
                }
                diag
            }
        }
    }
}

/// An optional program set: whytime runs without it, with less detail.
struct OptionalSpec {
    id: &'static str,
    title: &'static str,
    impact: &'static str,
    explain: &'static str,
    /// Kernel functions an fentry/fexit set hooks; `None` for tracepoints.
    functions: Option<&'static str>,
}

/// Optional program sets, in the order of [`Outcome::optional`].
static OPTIONAL: [OptionalSpec; 4] = [
    OptionalSpec {
        id: "probe.syscalls",
        title: "Syscall tracepoints",
        impact: "blocked time is reported as \"other\" instead of by resource (fsync, network \
                 peer, futex, ...)",
        explain: "the syscall in flight when a thread blocks says what it waited for; \
                  tp_btf/sys_enter and sys_exit record it",
        functions: None,
    },
    OptionalSpec {
        id: "probe.dns",
        title: "Resolver capture",
        impact: "network peers are reported as ip:port instead of the hostname the program \
                 resolved",
        explain: "a tp_btf/sys_exit variant copies what traced threads receive from DNS servers \
                  (port 53) and systemd-resolved's varlink socket, so peers can be named; \
                  without it the plain sys_exit program is attached",
        functions: None,
    },
    OptionalSpec {
        id: "probe.readiness",
        title: "Poll/epoll readiness probes",
        impact: "poll/select/epoll waits are reported as \"poll\" instead of the descriptor \
                 that became ready (network peer, pipe, terminal)",
        explain: "fentry on pollwake and ep_poll_callback records which file woke a thread \
                  blocked in poll, select or epoll_wait",
        functions: Some("pollwake and ep_poll_callback"),
    },
    OptionalSpec {
        id: "probe.faults",
        title: "Page-fault probes",
        impact: "time blocked in page faults (mapped-file reads, swap-in) is reported as \
                 \"other\" or as the syscall it interrupted instead of \"fault\"",
        explain: "fentry/fexit on handle_mm_fault mark threads inside a page fault, so a block \
                  there is attributed to the mapped file",
        functions: Some("handle_mm_fault"),
    },
];

struct OptionalCheck {
    probe: Arc<Probe>,
    /// Index into [`OPTIONAL`] and [`Outcome::optional`].
    index: usize,
}

impl Check for OptionalCheck {
    fn id(&self) -> &'static str {
        OPTIONAL[self.index].id
    }

    fn run(&self, _env: &dyn Env, tool: &Tool) -> Diagnostic {
        let spec = &OPTIONAL[self.index];
        match self.probe.get().optional.as_ref().map(|sets| &sets[self.index]) {
            None => Diagnostic::new(
                spec.id,
                spec.title,
                false,
                Status::Skip,
                "not probed: the scheduler probe failed",
            ),
            Some(Ok(observed)) => {
                Diagnostic::new(spec.id, spec.title, false, Status::Pass, observed.as_str())
            }
            Some(Err(err)) => {
                let mut diag =
                    Diagnostic::new(spec.id, spec.title, false, Status::Warn, describe(err))
                        .with_impact(spec.impact)
                        .with_explain(spec.explain);
                let fixes = match spec.functions {
                    Some(functions) => fentry_fixes(err, tool, functions),
                    None => fixes(err, tool),
                };
                for fix in fixes {
                    diag = diag.with_fix(fix);
                }
                diag
            }
        }
    }
}
