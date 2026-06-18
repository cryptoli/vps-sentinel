use crate::utils::fs::{hash_file_limited, path_string, resolve_under_root};
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::{Path, PathBuf};

const EXE_HASH_LIMIT_BYTES: u64 = 25 * 1024 * 1024;

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
        let status = match fs::read_to_string(process_dir.join("status")) {
            Ok(status) if !status.trim().is_empty() => status,
            _ => continue,
        };
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
        let ppid = parse_status_value(&status, "PPid").unwrap_or_default();
        let name = parse_status_value(&status, "Name").unwrap_or_default();
        let uid = parse_status_first_value(&status, "Uid").unwrap_or_default();
        let euid = parse_status_indexed_value(&status, "Uid", 1).unwrap_or_default();
        let parent_name = read_trimmed(root.path().join(&ppid).join("comm"));
        let cgroup = fs::read_to_string(process_dir.join("cgroup")).unwrap_or_default();
        let container_context = container_metadata_from_cgroup(&cgroup);
        let systemd_unit = systemd_unit_from_cgroup(&cgroup).unwrap_or_default();
        let systemd_execstart = systemd_execstart_for_unit(root.path(), &systemd_unit)
            .unwrap_or_default()
            .join(" | ");
        let exe_metadata = executable_metadata(root.path(), &exe_path);
        let cpu = fs::read_to_string(process_dir.join("stat"))
            .ok()
            .and_then(|stat| parse_process_cpu(&stat, uptime_seconds, clock_ticks));

        let mut event = RawEvent::new("process", "process_snapshot")
            .with_field("pid", pid.to_string())
            .with_field("ppid", ppid)
            .with_field("name", name)
            .with_field("parent_name", parent_name)
            .with_field("uid", uid)
            .with_field("euid", euid)
            .with_field("cmdline", cmdline)
            .with_field("argv_json", argv_json)
            .with_field("exe_path", exe_path)
            .with_field("cwd", cwd)
            .with_field("socket_fd_count", socket_fd_count.to_string());
        if let Some(container) = container_context {
            event = event.with_field("container_context", container.runtime);
            if let Some(id) = container.id {
                event = event.with_field("container_id", id);
            }
            if let Some(scope) = container.scope {
                event = event.with_field("container_cgroup", scope);
            }
        }
        if !systemd_unit.is_empty() {
            event = event.with_field("systemd_unit", systemd_unit);
        }
        if !systemd_execstart.is_empty() {
            event = event.with_field("systemd_execstart", systemd_execstart);
        }
        if let Some(metadata) = exe_metadata {
            event = event
                .with_field("exe_uid", metadata.uid)
                .with_field("exe_gid", metadata.gid)
                .with_field("exe_size", metadata.size);
            if let Some(hash) = metadata.hash {
                event = event.with_field("exe_hash_blake3", hash);
            }
        }
        if let Some(cpu) = cpu {
            event = event
                .with_field("cpu_percent", format!("{:.1}", cpu.percent))
                .with_field("cpu_total_seconds", format!("{:.1}", cpu.total_seconds))
                .with_field("process_age_seconds", format!("{:.1}", cpu.age_seconds))
                .with_field("process_start_ticks", cpu.start_ticks.to_string());
        }
        events.push(event);
    }
    Ok(events)
}

fn read_trimmed(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
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

#[derive(Debug, Clone)]
struct ExeMetadata {
    uid: String,
    gid: String,
    size: String,
    hash: Option<String>,
}

fn executable_metadata(proc_root: &Path, exe_path: &str) -> Option<ExeMetadata> {
    let normalized = exe_path
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| exe_path.trim());
    if normalized.is_empty()
        || normalized.starts_with("memfd:")
        || normalized.starts_with("anon_inode:")
    {
        return None;
    }
    let scan_root = scan_root_for_proc_root(proc_root);
    let path = resolve_under_root(&scan_root, Path::new(normalized));
    let metadata = fs::metadata(&path).ok()?;
    Some(ExeMetadata {
        uid: metadata_uid(&metadata),
        gid: metadata_gid(&metadata),
        size: metadata.len().to_string(),
        hash: hash_file_limited(&path, EXE_HASH_LIMIT_BYTES)
            .ok()
            .flatten(),
    })
}

fn scan_root_for_proc_root(proc_root: &Path) -> PathBuf {
    if proc_root == Path::new("/proc") {
        return PathBuf::from("/");
    }
    if proc_root.file_name().and_then(|name| name.to_str()) == Some("proc") {
        return proc_root
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf();
    }
    PathBuf::from("/")
}

fn metadata_uid(metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.uid().to_string()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        String::new()
    }
}

fn metadata_gid(metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.gid().to_string()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        String::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerMetadata {
    runtime: String,
    id: Option<String>,
    scope: Option<String>,
}

fn container_metadata_from_cgroup(cgroup: &str) -> Option<ContainerMetadata> {
    let lowered = cgroup.to_ascii_lowercase();
    let runtime = if lowered.contains("kubepods") {
        "kubernetes"
    } else if lowered.contains("containerd") || lowered.contains("cri-containerd") {
        "containerd"
    } else if lowered.contains("docker") {
        "docker"
    } else if lowered.contains("lxc") {
        "lxc"
    } else {
        return None;
    };
    Some(ContainerMetadata {
        runtime: runtime.to_string(),
        id: extract_container_id(&lowered),
        scope: cgroup
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string()),
    })
}

fn extract_container_id(cgroup: &str) -> Option<String> {
    for token in cgroup.split(|ch: char| !ch.is_ascii_hexdigit()) {
        if token.len() >= 12 && token.len() <= 128 && token.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return Some(token.to_string());
        }
    }
    None
}

fn systemd_unit_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .flat_map(|line| line.split('/'))
        .find(|part| part.ends_with(".service") && !part.trim().is_empty())
        .map(str::to_string)
}

fn systemd_execstart_for_unit(proc_root: &Path, unit: &str) -> Option<Vec<String>> {
    if unit.trim().is_empty() {
        return None;
    }
    let scan_root = scan_root_for_proc_root(proc_root);
    for candidate in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ] {
        let path = resolve_under_root(&scan_root, Path::new(candidate)).join(unit);
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let execstart = text
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with('#') {
                    return None;
                }
                trimmed
                    .strip_prefix("ExecStart=")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        if !execstart.is_empty() {
            return Some(execstart);
        }
    }
    None
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
    start_ticks: u64,
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
    let start_ticks = fields.get(19)?.parse::<u64>().ok()?;
    let total_seconds = (user_ticks + system_ticks) / clock_ticks;
    let start_seconds = start_ticks as f64 / clock_ticks;
    let age_seconds = (uptime_seconds - start_seconds).max(0.0);
    if age_seconds <= 0.0 {
        return None;
    }
    Some(CpuUsage {
        percent: (total_seconds / age_seconds) * 100.0,
        total_seconds,
        age_seconds,
        start_ticks,
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
    use super::{collect_processes, container_metadata_from_cgroup, parse_process_cpu, ProcfsRoot};
    use std::fs;

    #[test]
    fn collect_processes_extracts_linux_status_and_argv_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let proc_dir = temp.path().join("proc");
        let pid_dir = proc_dir.join("1234");
        fs::create_dir_all(&pid_dir)?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tkworker\nPPid:\t1\nUid:\t0\t0\t0\t0\n",
        )?;
        let parent_dir = proc_dir.join("1");
        fs::create_dir_all(&parent_dir)?;
        fs::write(parent_dir.join("comm"), "systemd\n")?;
        fs::write(
            pid_dir.join("cmdline"),
            b"/usr/local/bin/kworker\0--daemon\0",
        )?;
        fs::write(pid_dir.join("cgroup"), "0::/system.slice/test.service\n")?;
        let unit_dir = temp.path().join("etc/systemd/system");
        fs::create_dir_all(&unit_dir)?;
        fs::write(
            unit_dir.join("test.service"),
            "[Service]\nExecStart=/usr/local/bin/kworker --daemon\n",
        )?;
        let exe_path = temp.path().join("usr/local/bin/kworker");
        fs::create_dir_all(exe_path.parent().unwrap())?;
        fs::write(&exe_path, "binary")?;
        fs::write(proc_dir.join("uptime"), "1000.00 900.00\n")?;
        fs::write(
            pid_dir.join("stat"),
            "1234 (kworker) S 1 0 0 0 0 0 0 0 0 0 200 100 0 0 20 0 1 0 500 0",
        )?;

        let events = collect_processes(&ProcfsRoot::new(proc_dir))?;

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.field("pid"), Some("1234"));
        assert_eq!(event.field("name"), Some("kworker"));
        assert_eq!(event.field("ppid"), Some("1"));
        assert_eq!(event.field("parent_name"), Some("systemd"));
        assert_eq!(event.field("uid"), Some("0"));
        assert_eq!(event.field("euid"), Some("0"));
        assert_eq!(
            event.field("cmdline"),
            Some("/usr/local/bin/kworker --daemon")
        );
        assert_eq!(event.field("socket_fd_count"), Some("0"));
        assert_eq!(event.field("systemd_unit"), Some("test.service"));
        assert_eq!(
            event.field("systemd_execstart"),
            Some("/usr/local/bin/kworker --daemon")
        );
        assert!(event.field("cpu_percent").is_some());
        assert!(event.field("cpu_total_seconds").is_some());
        assert!(event.field("process_age_seconds").is_some());
        assert_eq!(event.field("process_start_ticks"), Some("500"));
        Ok(())
    }

    #[test]
    fn parses_process_cpu_from_proc_stat() {
        let stat = "1234 (miner worker) S 1 0 0 0 0 0 0 0 0 0 9000 1000 0 0 20 0 1 0 5000 0";
        let usage = parse_process_cpu(stat, Some(200.0), 100.0).expect("cpu usage");

        assert!((usage.total_seconds - 100.0).abs() < 0.01);
        assert!((usage.age_seconds - 150.0).abs() < 0.01);
        assert!((usage.percent - 66.7).abs() < 0.1);
        assert_eq!(usage.start_ticks, 5000);
    }

    #[test]
    fn parses_container_runtime_and_id_from_cgroup() {
        let cgroup = "0::/system.slice/docker-0123456789abcdef0123456789abcdef.scope\n";
        let context = container_metadata_from_cgroup(cgroup).expect("container context");

        assert_eq!(context.runtime, "docker");
        assert_eq!(
            context.id.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(context
            .scope
            .as_deref()
            .is_some_and(|scope| scope.contains("docker-")));
    }
}
