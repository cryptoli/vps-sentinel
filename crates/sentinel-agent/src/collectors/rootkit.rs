use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::path_string;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::Path;

pub struct RootkitSignalCollector;

#[async_trait]
impl Collector for RootkitSignalCollector {
    fn name(&self) -> &'static str {
        "rootkit_signal"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        let preload = ctx.resolve(Path::new("/etc/ld.so.preload"));
        if !preload.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&preload)
            .map_err(|err| sentinel_core::SentinelError::io(&preload, err))?;
        Ok(vec![RawEvent::new("rootkit", "ld_preload_present")
            .with_field("path", path_string(&preload))
            .with_field("entries", active_lines(&content).join(","))])
    }
}

fn active_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToString::to_string)
        .collect()
}
