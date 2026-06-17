use crate::utils::fs::path_string;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::{Path, PathBuf};

/// Root used for procfs reads. Tests can point this at a fixture tree.
#[derive(Debug, Clone)]
pub struct ProcfsRoot {
    root: PathBuf,
}

impl ProcfsRoot {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn default_linux() -> Self {
        Self {
            root: PathBuf::from("/proc"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }
}

/// Parse Linux procfs process entries into raw process facts.
pub fn collect_processes(root: &ProcfsRoot) -> SentinelResult<Vec<RawEvent>> {
    if !root.path().exists() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    let uptime_seconds = read_uptime_seconds(root.path().join("uptime"));
    let clock_ticks = clock_ticks_per_second();
    let entries = match fs::read_dir(root.path()) {
        Ok(entries) => entries,
        Err(err) => return Err(sentinel_core::SentinelError::io(root.path(), err)),
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let file_name = entry.file_name();
        let pid = match file_name.to_str().and_then(|text| text.parse::<u32>().ok()) {
            Some(pid) => pid,
            None => continue,
        };
        let process_dir = entry.path();
        let argv = read_argv(&process_dir);
        let cmdline = argv.join(" ");
        let argv_json = serde_json::to_string(&argv).unwrap_or_else(|_| "[]".to_string());
        let exe_path = fs::read_link(process_dir.join("exe"))
            .map(|path| path_string(&path))
            .unwrap_or_default();
        let cwd = fs::read_link(process_dir.join("cwd"))
            .map(|path| path_string(&path))
            .unwrap_or_default();
        let socket_fd_count = socket_fd_count(&process_dir);
        let status = fs::read_to_string(process_dir.join("status")).unwrap_or_default();
        let ppid = parse_status_value(&status, "PPid").unwrap_or_default();
        let name = parse_status_value(&status, "Name").unwrap_or_default();
        let uid = parse_status_first_value(&status, "Uid").unwrap_or_default();
        let euid = parse_status_indexed_value(&status, "Uid", 1).unwrap_or_default();
        let cpu = fs::read_to_string(process_dir.join("stat"))
            .ok()
            .and_then(|stat| parse_process_cpu(&stat, uptime_seconds, clock_ticks));

        let mut event = RawEvent::new("process", "process_snapshot")
            .with_field("pid", pid.to_string())
            .with_field("ppid", ppid)
            .with_field("name", name)
            .with_field("uid", uid)
            .with_field("euid", euid)
            .with_field("cmdline", cmdline)
            .with_field("argv_json", argv_json)
            .with_field("exe_path", exe_path)
            .with_field("cwd", cwd)
            .with_field("socket_fd_count", socket_fd_count.to_string());
        if let Some(cpu) = cpu {
            event = event
                .with_field("cpu_percent", format!("{:.1}", cpu.percent))
                .with_field("cpu_total_seconds", format!("{:.1}", cpu.total_seconds))
                .with_field("process_age_seconds", format!("{:.1}", cpu.age_seconds));
        }
        events.push(event);
    }
    Ok(events)
}

fn read_argv(process_dir: &Path) -> Vec<String> {
    fs::read(process_dir.join("cmdline"))
        .map(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .filter_map(|part| std::str::from_utf8(part).ok())
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status.lines().find_map(|line| {
        line.strip_prefix(&prefix)
            .map(|value| value.trim().to_string())
    })
}

fn parse_status_first_value(status: &str, key: &str) -> Option<String> {
    parse_status_indexed_value(status, key, 0)
}

fn parse_status_indexed_value(status: &str, key: &str, index: usize) -> Option<String> {
    parse_status_value(status, key)
        .and_then(|value| value.split_whitespace().nth(index).map(str::to_string))
}

#[derive(Debug, Clone, Copy)]
struct CpuUsage {
    percent: f64,
    total_seconds: f64,
    age_seconds: f64,
}

fn parse_process_cpu(
    stat: &str,
    uptime_seconds: Option<f64>,
    clock_ticks: f64,
) -> Option<CpuUsage> {
    let uptime_seconds = uptime_seconds?;
    if clock_ticks <= 0.0 {
        return None;
    }
    let after_comm = stat.rsplit_once(") ")?.1;
    let fields = after_comm.split_whitespace().collect::<Vec<_>>();
    let user_ticks = fields.get(11)?.parse::<f64>().ok()?;
    let system_ticks = fields.get(12)?.parse::<f64>().ok()?;
    let start_ticks = fields.get(19)?.parse::<f64>().ok()?;
    let total_seconds = (user_ticks + system_ticks) / clock_ticks;
    let start_seconds = start_ticks / clock_ticks;
    let age_seconds = (uptime_seconds - start_seconds).max(0.0);
    if age_seconds <= 0.0 {
        return None;
    }
    Some(CpuUsage {
        percent: (total_seconds / age_seconds) * 100.0,
        total_seconds,
        age_seconds,
    })
}

fn read_uptime_seconds(path: impl AsRef<Path>) -> Option<f64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse::<f64>().ok())
}

#[cfg(unix)]
fn clock_ticks_per_second() -> f64 {
    // SAFETY: sysconf is a thread-safe libc query and does not dereference pointers.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as f64
    } else {
        100.0
    }
}

#[cfg(not(unix))]
fn clock_ticks_per_second() -> f64 {
    100.0
}

fn socket_fd_count(process_dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(process_dir.join("fd")) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter(|target| {
            target
                .to_str()
                .is_some_and(|value| value.starts_with("socket:["))
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::{collect_processes, parse_process_cpu, ProcfsRoot};
    use std::fs;

    #[test]
    fn collect_processes_extracts_linux_status_and_argv_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let pid_dir = temp.path().join("1234");
        fs::create_dir_all(&pid_dir)?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tkworker\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
        )?;
        fs::write(
            pid_dir.join("cmdline"),
            b"/usr/local/bin/kworker\0--daemon\0",
        )?;
        fs::write(temp.path().join("uptime"), "1000.00 900.00\n")?;
        fs::write(
            pid_dir.join("stat"),
            "1234 (kworker) S 1 0 0 0 0 0 0 0 0 0 200 100 0 0 20 0 1 0 500 0",
        )?;

        let events = collect_processes(&ProcfsRoot::new(temp.path().to_path_buf()))?;

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.field("pid"), Some("1234"));
        assert_eq!(event.field("name"), Some("kworker"));
        assert_eq!(event.field("ppid"), Some("1"));
        assert_eq!(event.field("uid"), Some("0"));
        assert_eq!(event.field("euid"), Some("0"));
        assert_eq!(
            event.field("cmdline"),
            Some("/usr/local/bin/kworker --daemon")
        );
        assert_eq!(event.field("socket_fd_count"), Some("0"));
        assert!(event.field("cpu_percent").is_some());
        assert!(event.field("cpu_total_seconds").is_some());
        assert!(event.field("process_age_seconds").is_some());
        Ok(())
    }

    #[test]
    fn parses_process_cpu_from_proc_stat() {
        let stat = "1234 (miner worker) S 1 0 0 0 0 0 0 0 0 0 9000 1000 0 0 20 0 1 0 5000 0";
        let usage = parse_process_cpu(stat, Some(200.0), 100.0).expect("cpu usage");

        assert!((usage.total_seconds - 100.0).abs() < 0.01);
        assert!((usage.age_seconds - 150.0).abs() < 0.01);
        assert!((usage.percent - 66.7).abs() < 0.1);
    }
}
