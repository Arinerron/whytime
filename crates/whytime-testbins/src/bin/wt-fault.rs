//! `wt-fault write FILE MB` creates FILE with MB MiB of data, syncs it to disk and drops its
//! pages from the page cache.
//! `wt-fault touch FILE` drops FILE's pages (again), maps it, checks with `mincore` that none
//! is cached, reads one byte every [`STRIDE`] pages, last first, and removes FILE. Every read
//! is a major fault that reads just its own page, synchronously. FILE must be on a real
//! filesystem (not tmpfs).

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;

/// Pages from one touched page to the next: 2048 faults (~0.2 s on an NVMe SSD) on the
/// suite's 128 MiB file.
const STRIDE: usize = 16;

fn main() {
    let usage = "wt-fault write FILE MB | wt-fault touch FILE";
    let mode: String = whytime_testbins::arg(1, usage);
    let path: PathBuf = whytime_testbins::arg(2, usage);
    match mode.as_str() {
        "write" => {
            let mib: usize = whytime_testbins::arg(3, usage);
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
            let chunk = vec![0x5a_u8; 1 << 20];
            for _ in 0..mib {
                file.write_all(&chunk).expect("write");
            }
            file.sync_all().expect("fsync");
            // Clean after the sync, so the drop evicts every page: `touch` starts cold
            // without spending its own time on the eviction.
            drop_cache(&file);
        }
        "touch" => {
            let file = File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
            drop_cache(&file);
            let sum = touch(&file);
            std::fs::remove_file(&path).expect("remove");
            // Keep the reads observable.
            assert!(sum > 0, "the file was empty");
        }
        _ => {
            eprintln!("usage: {usage}");
            std::process::exit(2);
        }
    }
}

/// Evicts `file`'s clean pages from the page cache.
fn drop_cache(file: &File) {
    // SAFETY: plain syscall on an open descriptor.
    let dropped = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    assert_eq!(dropped, 0, "posix_fadvise: {}", io::Error::from_raw_os_error(dropped));
}

/// Maps `file` and reads one byte every [`STRIDE`] pages, last page first. `MADV_RANDOM`
/// turns off the fault read-around: each read is a major fault that waits for its own page
/// only (a read-around fault allocates and maps up to 32 pages for one wait, on-CPU work that
/// rivals the wait). The reverse order keeps readahead from running ahead of the reads
/// should the advice be ignored. Panics if a page was still cached.
fn touch(file: &File) -> u64 {
    let len = usize::try_from(file.metadata().expect("stat").len()).expect("file size");
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is open for the whole function; the mapping is `len` bytes, read only
    // within bounds, and unmapped before returning; `resident` has a byte per page.
    unsafe {
        let page = usize::try_from(libc::sysconf(libc::_SC_PAGESIZE)).expect("page size");
        let map = libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, fd, 0);
        assert!(map != libc::MAP_FAILED, "mmap: {}", io::Error::last_os_error());
        let advised = libc::madvise(map, len, libc::MADV_RANDOM);
        assert_eq!(advised, 0, "madvise: {}", io::Error::last_os_error());
        let mut resident = vec![0_u8; len.div_ceil(page)];
        let probed = libc::mincore(map, len, resident.as_mut_ptr());
        assert_eq!(probed, 0, "mincore: {}", io::Error::last_os_error());
        let cached = resident.iter().filter(|&&page| page & 1 != 0).count();
        assert_eq!(
            cached,
            0,
            "{cached} of {} pages still cached after POSIX_FADV_DONTNEED",
            resident.len()
        );
        let bytes = map.cast::<u8>();
        let sum = (0..len)
            .step_by(page * STRIDE)
            .rev()
            .map(|offset| u64::from(bytes.add(offset).read_volatile()))
            .sum();
        libc::munmap(map, len);
        sum
    }
}
