use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::path_string;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct ConfigRiskCollector;

#[async_trait]
impl Collector for ConfigRiskCollector {
    fn name(&self) -> &'static str {
        "config_risk"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        let mut events = Vec::new();
        for path in ssh_config_paths(ctx) {
            if !path.exists() {
                continue;
            }
            if path.is_file() {
                collect_ssh_config_file(&path, &mut events)?;
            } else if path.is_dir() {
                for entry in WalkDir::new(&path)
                    .max_depth(1)
                    .into_iter()
                    .filter_map(Result::ok)
                {
                    if entry.file_type().is_file() {
                        collect_ssh_config_file(entry.path(), &mut events)?;
                    }
                }
            }
        }
        Ok(events)
    }
}

fn ssh_config_paths(ctx: &CollectContext) -> Vec<PathBuf> {
    vec![
        ctx.resolve(Path::new("/etc/ssh/sshd_config")),
        ctx.resolve(Path::new("/etc/ssh/sshd_config.d")),
    ]
}

fn collect_ssh_config_file(path: &Path, events: &mut Vec<RawEvent>) -> SentinelResult<()> {
    let content =
        fs::read_to_string(path).map_err(|err| sentinel_core::SentinelError::io(path, err))?;
    for (key, value) in parse_ssh_config(&content) {
        events.push(
            RawEvent::new("config_risk", "ssh_config_option")
                .with_field("path", path_string(path))
                .with_field("key", key)
                .with_field("value", value),
        );
    }
    Ok(())
}

/// Parse active sshd_config key-value directives.
pub fn parse_ssh_config(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let mut parts = trimmed.split_whitespace();
            let key = parts.next()?;
            let value = parts.collect::<Vec<_>>().join(" ");
            if value.is_empty() {
                None
            } else {
                Some((key.to_string(), value))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_ssh_config;

    #[test]
    fn ignores_commented_ssh_config_lines() {
        let parsed = parse_ssh_config("#PasswordAuthentication no\nPasswordAuthentication yes");
        assert_eq!(
            parsed,
            vec![("PasswordAuthentication".to_string(), "yes".to_string())]
        );
    }
}
