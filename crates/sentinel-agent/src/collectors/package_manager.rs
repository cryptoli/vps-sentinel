use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{path_string, read_tail};
use async_trait::async_trait;
use chrono::Utc;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::time::UNIX_EPOCH;

pub struct PackageManagerCollector;

#[async_trait]
impl Collector for PackageManagerCollector {
    fn name(&self) -> &'static str {
        "package_manager"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.package_manager.enabled {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        for configured_path in &ctx.config.package_manager.log_paths {
            let path = ctx.resolve(configured_path);
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            let Ok(modified_since_epoch) = modified.duration_since(UNIX_EPOCH) else {
                continue;
            };
            let age_seconds = Utc::now()
                .timestamp()
                .saturating_sub(modified_since_epoch.as_secs() as i64)
                .max(0) as u64;
            if age_seconds > ctx.config.package_manager.recent_activity_window_seconds {
                continue;
            }

            let tail = read_tail(&path, ctx.config.package_manager.max_log_tail_bytes)
                .map(|text| compact_log_tail(&text))
                .unwrap_or_default();
            let mut event = RawEvent::new("package_manager", "package_manager_activity")
                .with_field("path", path_string(&path))
                .with_field("modified_unix", modified_since_epoch.as_secs().to_string())
                .with_field("age_seconds", age_seconds.to_string());
            if !tail.is_empty() {
                event = event.with_field("recent_lines", tail);
            }
            events.push(event);
        }
        Ok(events)
    }
}

fn compact_log_tail(text: &str) -> String {
    text.lines()
        .rev()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::PackageManagerCollector;
    use crate::collectors::{CollectContext, Collector};
    use sentinel_core::SentinelConfig;
    use std::fs;
    use std::sync::Arc;

    #[tokio::test]
    async fn collects_recent_package_manager_activity() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let log = temp.path().join("dpkg.log");
        fs::write(&log, "install nginx\nconfigure nginx\n")?;

        let mut config = SentinelConfig::default();
        config.package_manager.log_paths = vec![log.clone()];
        config.package_manager.recent_activity_window_seconds = 3600;
        let ctx = CollectContext::new(Arc::new(config));

        let events = PackageManagerCollector.collect(&ctx).await?;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "package_manager_activity");
        assert!(events[0]
            .field("recent_lines")
            .is_some_and(|value| value.contains("configure nginx")));
        Ok(())
    }
}
