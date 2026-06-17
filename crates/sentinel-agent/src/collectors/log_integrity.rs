use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::path_string;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct LogIntegrityCollector;

#[async_trait]
impl Collector for LogIntegrityCollector {
    fn name(&self) -> &'static str {
        "log_integrity"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.log_integrity.enabled {
            return Ok(Vec::new());
        }

        let rotation_grace = Duration::from_secs(ctx.config.log_integrity.rotation_grace_seconds);
        let mut events = Vec::new();
        for configured in &ctx.config.log_integrity.paths {
            let path = ctx.resolve(configured);
            if let Some(event) = log_file_event(&path, rotation_grace) {
                events.push(event);
            }
        }
        Ok(events)
    }
}

fn log_file_event(path: &Path, rotation_grace: Duration) -> Option<RawEvent> {
    let symlink_metadata = fs::symlink_metadata(path).ok()?;
    let file_type = if symlink_metadata.file_type().is_symlink() {
        "symlink"
    } else if symlink_metadata.is_file() {
        "file"
    } else {
        "other"
    };

    let metadata = fs::metadata(path).unwrap_or_else(|_| symlink_metadata.clone());
    let mut event = RawEvent::new("log_integrity", "log_file_snapshot")
        .with_field("path", path_string(path))
        .with_field("file_type", file_type)
        .with_field("size", metadata.len().to_string());

    if let Ok(modified) = metadata.modified() {
        event = event.with_field("modified_unix", unix_seconds(modified).to_string());
    }

    if file_type == "symlink" {
        if let Ok(target) = fs::read_link(path) {
            event = event.with_field("symlink_target", path_string(&target));
        }
    }

    if let Some(sibling) = recent_rotated_sibling(path, rotation_grace) {
        event = event
            .with_field("recent_rotated_sibling", "true")
            .with_field("rotated_sibling", path_string(&sibling));
    }

    Some(event)
}

fn recent_rotated_sibling(path: &Path, grace: Duration) -> Option<PathBuf> {
    let parent = path.parent()?;
    let file_name = path.file_name()?.to_string_lossy();
    let dot_prefix = format!("{file_name}.");
    let dash_prefix = format!("{file_name}-");
    let now = SystemTime::now();
    fs::read_dir(parent)
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| {
            let entry_name = entry.file_name().to_string_lossy().to_string();
            if entry.path() == path
                || !(entry_name.starts_with(&dot_prefix) || entry_name.starts_with(&dash_prefix))
            {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            let age = now.duration_since(modified).ok()?;
            (age <= grace).then(|| entry.path())
        })
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{log_file_event, recent_rotated_sibling};
    use std::fs;
    use std::time::Duration;

    #[test]
    fn collects_log_file_snapshot() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("auth.log");
        fs::write(&path, "Accepted publickey\n")?;

        let event = log_file_event(&path, Duration::from_secs(900)).expect("log event");

        assert_eq!(event.kind, "log_file_snapshot");
        assert_eq!(event.field("file_type"), Some("file"));
        assert_eq!(event.field("size"), Some("19"));
        Ok(())
    }

    #[test]
    fn detects_recent_rotated_sibling() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("auth.log");
        let rotated = temp.path().join("auth.log.1");
        fs::write(&path, "")?;
        fs::write(&rotated, "old log\n")?;

        let sibling = recent_rotated_sibling(&path, Duration::from_secs(900));

        assert_eq!(sibling, Some(rotated));
        Ok(())
    }
}
