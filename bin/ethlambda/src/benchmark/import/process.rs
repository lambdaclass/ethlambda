//! Process-level resource readings for the import replay: CPU time and memory.
//!
//! Wall time says how long an import took; it does not say whether the time
//! went to computation or to waiting, nor whether it ran on one core or
//! several. CPU seconds beside it does: an import whose CPU time is well above
//! its wall time was parallel (rayon in the merkle fold and the BLS batches),
//! and one whose CPU time is well below it spent the difference blocked.
//!
//! Everything here reads the whole process, not the importing thread. That is
//! deliberate: the work an import causes is not all on its own thread (the
//! state writer, the merkle fold's worker pool, RocksDB's background
//! compaction), and a per-thread reading would call a parallel import cheap.
//! The same property is the caveat: anything else the process does during the
//! import is in the number, which is why the replay runs nothing else.
//!
//! No dependency beyond `libc`, which the binary already carries for its file
//! descriptor limit. `getrusage` is the one portable process-wide CPU clock
//! the standard library does not wrap, so it is the one `unsafe` call here.

/// User plus system CPU seconds this process has used so far, across all of
/// its threads, or `None` if the kernel refuses the reading.
pub(crate) fn cpu_seconds() -> Option<f64> {
    let usage = rusage()?;
    Some(seconds(usage.ru_utime) + seconds(usage.ru_stime))
}

/// The process's peak resident set size so far, in bytes.
///
/// A high-water mark, so it never goes down: between two blocks it moves only
/// when a block set a new peak, and a replay's last value is the run's peak.
pub(crate) fn peak_rss_bytes() -> Option<u64> {
    let usage = rusage()?;
    let maxrss = u64::try_from(usage.ru_maxrss).ok()?;
    // `ru_maxrss` is bytes on macOS and kibibytes on Linux.
    if cfg!(target_os = "macos") {
        Some(maxrss)
    } else {
        maxrss.checked_mul(1024)
    }
}

/// The process's resident set size right now, in bytes.
///
/// Read from `/proc/self/status`, so Linux only: macOS has no equivalent that
/// needs no new dependency, and `None` there is honest where a stand-in would
/// not be. A replay on a Mac still reports [`peak_rss_bytes`].
pub(crate) fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_vm_rss(&status)
}

/// The `VmRSS` line of a `/proc/<pid>/status` file, which the kernel reports in
/// kibibytes.
fn parse_vm_rss(status: &str) -> Option<u64> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?;
    let kibibytes: u64 = line.trim().strip_suffix("kB")?.trim().parse().ok()?;
    kibibytes.checked_mul(1024)
}

fn seconds(time: libc::timeval) -> f64 {
    time.tv_sec as f64 + time.tv_usec as f64 / 1e6
}

fn rusage() -> Option<libc::rusage> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: `getrusage` writes a complete `rusage` through the pointer when
    // it returns 0 and does not read it, and the pointer is to a live local;
    // the value is only assumed initialized on that success path.
    unsafe {
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) != 0 {
            return None;
        }
        Some(usage.assume_init())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_advances_while_the_process_computes() {
        let before = cpu_seconds().expect("getrusage works on the host");
        // Enough work that the clock's resolution cannot hide it; `black_box`
        // keeps the loop from being folded away.
        let mut acc = 0u64;
        let started = std::time::Instant::now();
        while started.elapsed() < std::time::Duration::from_millis(30) {
            for i in 0..10_000u64 {
                acc = std::hint::black_box(acc.wrapping_add(i * i));
            }
        }
        let after = cpu_seconds().expect("getrusage works on the host");
        assert!(after > before, "{after} should exceed {before}");
    }

    #[test]
    fn a_process_has_a_nonzero_peak_resident_set() {
        assert!(peak_rss_bytes().expect("getrusage works on the host") > 0);
    }

    #[test]
    fn vm_rss_is_read_in_bytes_from_the_kibibyte_line() {
        let status = "Name:\tethlambda\nVmHWM:\t  999 kB\nVmRSS:\t  2048 kB\nThreads:\t4\n";
        assert_eq!(parse_vm_rss(status), Some(2048 * 1024));
    }

    #[test]
    fn a_status_file_without_vm_rss_gives_none() {
        // A kernel thread's status has no `VmRSS`, and a malformed line must
        // not become a number.
        assert_eq!(parse_vm_rss("Name:\tkthreadd\n"), None);
        assert_eq!(parse_vm_rss("VmRSS:\tlots\n"), None);
    }
}
