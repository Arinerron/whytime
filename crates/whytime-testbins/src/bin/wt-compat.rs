//! `wt-compat MS`: blocks MS milliseconds in a 32-bit (compat) syscall, `poll(NULL, 0, MS)`
//! by its i386 number (168, `swapoff` in the x86-64 table) through `int 0x80`, which x86-64
//! kernels with IA-32 emulation run as a compat syscall even from 64-bit code. Exits 77
//! where that is unavailable: other architectures, or a kernel without IA-32 emulation
//! (`-ENOSYS`; with emulation disabled at boot, `int 0x80` faults instead).

#[cfg(target_arch = "x86_64")]
fn main() {
    /// `__NR_poll` in the i386 table.
    const POLL_I386: u32 = 168;
    let ms: u32 = whytime_testbins::arg(1, "wt-compat MS");
    let mut ret = POLL_I386;
    // SAFETY: i386 poll with no descriptors reads no memory; ebx (the NULL array) is swapped
    // in and out by hand, as LLVM reserves rbx; int 0x80 may clobber r8-r11 on old kernels.
    unsafe {
        std::arch::asm!(
            "xchg {fds:r}, rbx",
            "int 0x80",
            "xchg {fds:r}, rbx",
            fds = inout(reg) 0_u64 => _,
            inout("eax") ret,
            in("ecx") 0,
            in("edx") ms,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }
    if ret.cast_signed() == -libc::ENOSYS {
        eprintln!("int 0x80: no IA-32 emulation");
        std::process::exit(77);
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {
    eprintln!("wt-compat: x86-64 only");
    std::process::exit(77);
}
