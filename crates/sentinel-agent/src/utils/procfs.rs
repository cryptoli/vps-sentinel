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

        events.push(
            RawEvent::new("process", "process_snapshot")
                .with_field("pid", pid.to_string())
                .with_field("ppid", ppid)
                .with_field("name", name)
                .with_field("uid", uid)
                .with_field("euid", euid)
                .with_field("cmdline", cmdline)
                .with_field("argv_json", argv_json)
                .with_field("exe_path", exe_path)
                .with_field("cwd", cwd)
                .with_field("socket_fd_count", socket_fd_count.to_string()),
        );
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
