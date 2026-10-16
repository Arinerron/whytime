//! `whytime doctor` and the start-up diagnostics: the shared bpfdoctor checks plus whytime's
//! own `probe.sched` and `probe.syscalls`, which load and attach the real programs.

use std::cell::OnceCell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;

use bpfdoctor::{
    Cap, Check, Diagnostic, Doctor, Env, Fix, RealEnv, Report, Status, Tool, errno_name,
};

use crate::sys::SyscallTable;
use crate::tracer::{self, SCHED, SYSCALLS, Tracer};

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
        // 4 MiB ring buffer, 32768 task states, 16384 tracked pids, programs.
        memlock_bytes: 16 << 20,
    }
}

/// The full doctor: shared checks, then whytime's probes.
pub fn full() -> Doctor {
    let mut doctor = Doctor::with_shared();
    let probe = Rc::new(Probe::default());
    doctor.add(Box::new(SchedCheck(Rc::clone(&probe))));
    doctor.add(Box::new(SyscallsCheck(probe)));
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

/// Outcome of loading the real object once, shared by both probe checks.
#[derive(Default)]
struct Probe {
    outcome: OnceCell<Outcome>,
}

struct Outcome {
    sched: Result<String, anyhow::Error>,
    syscalls: Option<Result<String, anyhow::Error>>,
}

impl Probe {
    fn get(&self) -> &Outcome {
        self.outcome
            .get_or_init(|| match Tracer::load(&SyscallTable::new()) {
                Ok(loaded) => {
                    let sizes = loaded.tracer.program_sizes();
                    let insns = |names: &[(&str, &str)]| -> u32 {
                        sizes
                            .iter()
                            .filter(|(name, _)| names.iter().any(|(prog, _)| prog == name))
                            .map(|(_, n)| n)
                            .sum()
                    };
                    let sched = format!(
                        "{} tp_btf programs loaded and attached ({} verified insns)",
                        SCHED.len(),
                        insns(&SCHED)
                    );
                    let syscalls = loaded.syscalls.map(|()| {
                        format!(
                            "tp_btf/sys_enter and sys_exit loaded and attached ({} verified insns)",
                            insns(&SYSCALLS)
                        )
                    });
                    Outcome {
                        sched: Ok(sched),
                        syscalls: Some(syscalls),
                    }
                }
                Err(err) => Outcome {
                    sched: Err(err),
                    syscalls: None,
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
        _ => vec![Fix::new(
            format!("WHYTIME_LOG=debug {} doctor", tool.exe.display()),
            "prints the verifier log",
        )],
    }
}

struct SchedCheck(Rc<Probe>);

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

struct SyscallsCheck(Rc<Probe>);

impl Check for SyscallsCheck {
    fn id(&self) -> &'static str {
        "probe.syscalls"
    }

    fn run(&self, _env: &dyn Env, tool: &Tool) -> Diagnostic {
        const TITLE: &str = "Syscall tracepoints";
        match &self.0.get().syscalls {
            None => Diagnostic::new(
                self.id(),
                TITLE,
                false,
                Status::Skip,
                "not probed: the scheduler probe failed",
            ),
            Some(Ok(observed)) => {
                Diagnostic::new(self.id(), TITLE, false, Status::Pass, observed.as_str())
            }
            Some(Err(err)) => {
                let mut diag =
                    Diagnostic::new(self.id(), TITLE, false, Status::Warn, describe(err))
                        .with_impact(
                            "blocked time is reported as \"other\" instead of by resource \
                         (fsync, network peer, futex, ...)",
                        )
                        .with_explain(
                            "the syscall in flight when a thread blocks says what it waited for; \
                         tp_btf/sys_enter and sys_exit record it",
                        );
                for fix in fixes(err, tool) {
                    diag = diag.with_fix(fix);
                }
                diag
            }
        }
    }
}
