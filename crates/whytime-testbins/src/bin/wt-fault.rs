//! `wt-fault write FILE MB` creates FILE with MB MiB of data and syncs it to disk.
//! `wt-fault touch FILE` drops FILE's pages from the page cache, maps it, reads one byte per
//! page, last page first (so the pages fault in from disk, synchronously) and removes FILE.
//! FILE must be on a real filesystem (not tmpfs).

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;

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
        }
        "touch" => {
            let file = File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
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

/// Evicts `file` from the page cache, then reads one byte of every page through a mapping,
/// last page first: the fault read-around then reads each block synchronously (a forward
/// scan would trigger asynchronous readahead and hide most of the I/O behind on-CPU time).
fn touch(file: &File) -> u64 {
    let len = usize::try_from(file.metadata().expect("stat").len()).expect("file size");
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is open for the whole function; the mapping is `len` bytes, read only
    // within bounds, and unmapped before returning.
    unsafe {
        let page = usize::try_from(libc::sysconf(libc::_SC_PAGESIZE)).expect("page size");
        let dropped = libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
        assert_eq!(dropped, 0, "posix_fadvise: {}", io::Error::from_raw_os_error(dropped));
        let map = libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, fd, 0);
        assert!(map != libc::MAP_FAILED, "mmap: {}", io::Error::last_os_error());
        let bytes = map.cast::<u8>();
        let sum = (0..len)
            .step_by(page)
            .rev()
            .map(|offset| u64::from(bytes.add(offset).read_volatile()))
            .sum();
        libc::munmap(map, len);
        sum
    }
}
