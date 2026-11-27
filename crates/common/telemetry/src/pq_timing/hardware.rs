//! What the run's timings were measured on, for `run.json`.
//!
//! Read from `/proc` and the cgroup v2 tree, so a container reports the CPU
//! and memory it was given and not only the host's. Off Linux every field but
//! the architecture, the operating system and the core count is null.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

pub(super) fn hardware() -> Value {
    let cpu_model =
        field("/proc/cpuinfo", "model name").or_else(|| field("/proc/cpuinfo", "Hardware"));
    let visible_memory_bytes = field("/proc/meminfo", "MemTotal")
        .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())
        .and_then(|kib| kib.checked_mul(1024));
    let (cpu_quota, memory_limit) = cgroup_limits(Path::new("/sys/fs/cgroup"), &own_cgroup());
    json!({
        "architecture": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "kernel": read_trimmed("/proc/sys/kernel/osrelease"),
        "cpu_model": cpu_model,
        "available_parallelism": std::thread::available_parallelism().ok().map(usize::from),
        "cpu_affinity": field("/proc/self/status", "Cpus_allowed_list"),
        "cgroup_cpu_equivalents": cpu_quota,
        "visible_memory_bytes": visible_memory_bytes,
        "cgroup_memory_bytes": memory_limit,
    })
}

fn read_trimmed(file: &str) -> Option<String> {
    Some(fs::read_to_string(file).ok()?.trim().to_string())
}

/// The value of the first `key: value` line of `file`.
fn field(file: &str, key: &str) -> Option<String> {
    let text = fs::read_to_string(file).ok()?;
    value_of(&text, key)
}

fn value_of(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_string())
    })
}

/// This process's cgroup, relative to the cgroup root: the `0::/...` line of
/// `/proc/self/cgroup`. Empty when there is none, which reads the root.
fn own_cgroup() -> String {
    fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("0::/").map(str::to_owned))
        })
        .unwrap_or_default()
}

/// The tightest CPU quota, in CPUs, and memory limit, in bytes, among
/// `group` and its ancestors under `root`. `None` where none sets one: an
/// unlimited `cpu.max` or `memory.max` reads `max`, which is not a number.
fn cgroup_limits(root: &Path, group: &str) -> (Option<f64>, Option<u64>) {
    let mut path = root.join(group);
    if !path.is_dir() {
        path = root.to_path_buf();
    }
    let cpu = |path: &Path| {
        let value = fs::read_to_string(path.join("cpu.max")).ok()?;
        let (quota, period) = value.trim().split_once(' ')?;
        let period = period.parse::<u64>().ok().filter(|&period| period > 0)?;
        Some(quota.parse::<u64>().ok()? as f64 / period as f64)
    };
    let memory = |path: &Path| {
        fs::read_to_string(path.join("memory.max"))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    };
    let levels = || {
        path.ancestors()
            .take_while(|ancestor| ancestor.starts_with(root))
    };
    (
        levels().filter_map(cpu).reduce(f64::min),
        levels().filter_map(memory).min(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proc_field_is_read_by_its_key() {
        let cpuinfo =
            "processor\t: 0\nmodel name\t: AMD EPYC 9454P 48-Core Processor\nflags\t: fpu";
        assert_eq!(
            value_of(cpuinfo, "model name").as_deref(),
            Some("AMD EPYC 9454P 48-Core Processor")
        );
        assert_eq!(value_of(cpuinfo, "model"), None);
    }

    /// A container's limits are the tightest of its own cgroup's and its
    /// ancestors': here the parent caps CPU at 4 and the leaf memory at 8 GiB.
    #[test]
    fn the_tightest_cgroup_limit_among_the_ancestors_wins() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("kubepods/pod1");
        fs::create_dir_all(&leaf).unwrap();
        fs::write(root.path().join("cpu.max"), "max 100000\n").unwrap();
        fs::write(root.path().join("kubepods/cpu.max"), "400000 100000\n").unwrap();
        fs::write(leaf.join("cpu.max"), "800000 100000\n").unwrap();
        fs::write(root.path().join("kubepods/memory.max"), "max\n").unwrap();
        fs::write(leaf.join("memory.max"), "8589934592\n").unwrap();

        let limits = cgroup_limits(root.path(), "kubepods/pod1");
        assert_eq!(limits, (Some(4.0), Some(8 << 30)));
        // No cgroup of its own, or one that is not there: the root's, which
        // sets none.
        assert_eq!(cgroup_limits(root.path(), ""), (None, None));
        assert_eq!(cgroup_limits(root.path(), "elsewhere"), (None, None));
    }

    #[test]
    fn the_report_names_the_architecture_everywhere() {
        let report = hardware();
        assert_eq!(report["architecture"], std::env::consts::ARCH);
        assert!(report["available_parallelism"].is_number());
    }
}
