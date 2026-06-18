use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{hash_file_limited, is_executable, is_hidden, path_string, read_small_text};
use crate::utils::ssh_config::discover_authorized_key_patterns;
use async_trait::async_trait;
use glob::glob;
use sentinel_core::{RawEvent, SentinelResult};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const SKIPPED_DIRS: &[&str] = &["node_modules", "vendor", ".git", "cache", ".cache"];
const MAX_CONTENT_SCAN_BYTES: u64 = 256 * 1024;

pub struct FileIntegrityCollector;

#[async_trait]
impl Collector for FileIntegrityCollector {
    fn name(&self) -> &'static str {
        "file_integrity"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        let mut events = BTreeMap::new();
        if ctx.config.file_integrity.enabled {
            for configured_path in &ctx.config.file_integrity.paths {
                collect_configured_path(ctx, configured_path, &mut events);
            }
        }

        if ctx.config.ssh.enabled && ctx.config.ssh.monitor_authorized_keys {
            for configured_path in discover_authorized_key_patterns(&ctx.scan_root) {
                collect_configured_path(ctx, &configured_path, &mut events);
            }
        }

        Ok(events.into_values().collect())
    }
}

fn collect_configured_path(
    ctx: &CollectContext,
    configured_path: &Path,
    events: &mut BTreeMap<String, RawEvent>,
) {
    let resolved = ctx.resolve(configured_path);
    for path in expand_path(&resolved) {
        collect_path(ctx, &path, events);
    }
}

fn expand_path(path: &Path) -> Vec<PathBuf> {
    let pattern = path_string(path);
    if pattern.contains('*') {
        return glob(&pattern)
            .map(|paths| paths.filter_map(Result::ok).collect())
            .unwrap_or_default();
    }
    vec![path.to_path_buf()]
}

fn collect_path(ctx: &CollectContext, path: &Path, events: &mut BTreeMap<String, RawEvent>) {
    let Some(metadata) = fs::symlink_metadata(path).ok() else {
        return;
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        if let Some(event) = file_event(ctx, path) {
            insert_file_event(events, event);
        }
        return;
    }
    if !metadata.is_dir() {
        return;
    }

    let walker = WalkDir::new(path)
        .max_depth(ctx.config.file_integrity.max_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !should_skip_dir(entry));

    for entry_result in walker {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.file_type().is_file() {
            if let Some(event) = file_event(ctx, entry.path()) {
                insert_file_event(events, event);
            }
        }
    }
}

fn insert_file_event(events: &mut BTreeMap<String, RawEvent>, event: RawEvent) {
    let Some(path) = event.field("path") else {
        return;
    };
    events.entry(path.to_string()).or_insert(event);
}

fn should_skip_dir(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    entry
        .file_name()
        .to_str()
        .map(|name| SKIPPED_DIRS.iter().any(|skipped| skipped == &name))
        .unwrap_or(false)
}

fn file_event(ctx: &CollectContext, path: &Path) -> Option<RawEvent> {
    let symlink_metadata = fs::symlink_metadata(path).ok()?;
    let metadata = fs::metadata(path).unwrap_or_else(|_| symlink_metadata.clone());
    let max_hash_bytes = ctx.config.file_integrity.max_file_size_mb * 1024 * 1024;
    let hash = hash_file_limited(path, max_hash_bytes)
        .ok()
        .flatten()
        .unwrap_or_else(|| "too_large".to_string());
    let path_text = path_string(path);
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_web_path = is_under_any(path, &ctx.config.web.web_roots, ctx);
    let markers = if should_scan_content(&extension, is_web_path) {
        content_markers(path)
    } else {
        Vec::new()
    };

    let mut event = RawEvent::new("file_integrity", "file_snapshot")
        .with_field("path", path_text)
        .with_field("size", metadata.len().to_string())
        .with_field("hash", hash)
        .with_field("extension", extension)
        .with_field("executable", is_executable(&metadata).to_string())
        .with_field("hidden", is_hidden(path).to_string())
        .with_field("is_web_path", is_web_path.to_string())
        .with_field("file_type", file_type_label(&symlink_metadata, &metadata));

    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            event = event.with_field("modified_unix", duration.as_secs().to_string());
        }
    }
    if let Some(mode) = unix_mode_octal(&metadata) {
        event = event.with_field("mode_octal", mode);
    }
    if symlink_metadata.file_type().is_symlink() {
        if let Ok(target) = fs::read_link(path) {
            event = event.with_field("symlink_target", path_string(&target));
        }
    }
    if !markers.is_empty() {
        event = event.with_field("content_markers", markers.join(","));
    }
    Some(event)
}

fn file_type_label(symlink_metadata: &fs::Metadata, metadata: &fs::Metadata) -> &'static str {
    if symlink_metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.is_file() {
        "file"
    } else if metadata.is_dir() {
        "directory"
    } else {
        "other"
    }
}

#[cfg(unix)]
fn unix_mode_octal(metadata: &fs::Metadata) -> Option<String> {
    Some(format!("{:04o}", metadata.permissions().mode() & 0o7777))
}

#[cfg(not(unix))]
fn unix_mode_octal(_metadata: &fs::Metadata) -> Option<String> {
    None
}

fn is_under_any(path: &Path, roots: &[PathBuf], ctx: &CollectContext) -> bool {
    roots.iter().any(|root| {
        let resolved = ctx.resolve(root);
        path.starts_with(resolved)
    })
}

fn content_markers(path: &Path) -> Vec<&'static str> {
    let text = match read_small_text(path, MAX_CONTENT_SCAN_BYTES) {
        Ok(Some(text)) => text,
        Ok(None) | Err(_) => return Vec::new(),
    };
    let lowered = text.to_ascii_lowercase();
    let mut markers = Vec::new();
    for (name, marker) in marker_patterns() {
        if lowered.contains(&marker) {
            markers.push(name);
        }
    }
    if has_long_base64_like_token(&text) {
        markers.push("long_base64");
    }
    markers
}

fn should_scan_content(extension: &str, is_web_path: bool) -> bool {
    is_web_path
        || matches!(
            extension,
            "php" | "phtml" | "jsp" | "asp" | "aspx" | "cgi" | "pl" | "py" | "sh"
        )
}

fn marker_patterns() -> Vec<(&'static str, String)> {
    vec![
        ("eval_call", ["ev", "al("].concat()),
        ("system_call", ["sys", "tem("].concat()),
        ("shell_exec", ["shell", "_exec"].concat()),
        ("passthru", ["pass", "thru"].concat()),
        ("base64_decode", ["base64", "_decode"].concat()),
        ("assert_call", ["as", "sert("].concat()),
        ("dev_tcp", ["/dev", "/tcp/"].concat()),
        ("cmd_exe", ["cmd", ".exe"].concat()),
    ]
}

fn has_long_base64_like_token(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '+' && ch != '/' && ch != '=')
        .any(|token| token.len() >= 120)
}

#[cfg(test)]
mod tests {
    use super::{content_markers, should_scan_content, FileIntegrityCollector};
    use crate::collectors::{CollectContext, Collector};
    use sentinel_core::SentinelConfig;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn detects_webshell_content_markers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("shell.php");
        let payload = [
            "<?php ",
            &["ev", "al("].concat(),
            &["base64", "_decode("].concat(),
            "$_POST['x']));",
        ]
        .concat();
        fs::write(&path, payload)?;
        let markers = content_markers(&path);
        assert!(markers.contains(&"eval_call"));
        assert!(markers.contains(&"base64_decode"));
        Ok(())
    }

    #[test]
    fn skips_non_web_ssh_key_like_content() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("authorized_keys");
        fs::write(&path, format!("ssh-ed25519 {}", "A".repeat(140)))?;
        assert!(!should_scan_content("", false));
        assert!(content_markers(&path).contains(&"long_base64"));
        Ok(())
    }

    #[tokio::test]
    async fn collects_ssh_authorized_keys_when_file_integrity_is_disabled(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let key_path = temp.path().join("root/.ssh/authorized_keys");
        let parent = key_path
            .parent()
            .ok_or_else(|| std::io::Error::other("test key path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(&key_path, "ssh-ed25519 AAAATEST\n")?;

        let mut config = SentinelConfig::default();
        config.file_integrity.enabled = false;
        config.ssh.enabled = true;
        config.ssh.monitor_authorized_keys = true;
        let ctx = CollectContext::new(Arc::new(config)).with_scan_root(temp.path().to_path_buf());

        let events = FileIntegrityCollector.collect(&ctx).await?;

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "file_snapshot");
        assert!(events[0]
            .field("path")
            .is_some_and(|path| path.ends_with("/root/.ssh/authorized_keys")));
        Ok(())
    }

    #[tokio::test]
    async fn skips_ssh_authorized_keys_when_ssh_monitoring_is_disabled(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let key_path = temp.path().join("root/.ssh/authorized_keys");
        let parent = key_path
            .parent()
            .ok_or_else(|| std::io::Error::other("test key path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(&key_path, "ssh-ed25519 AAAATEST\n")?;

        let mut config = SentinelConfig::default();
        config.file_integrity.enabled = false;
        config.ssh.enabled = true;
        config.ssh.monitor_authorized_keys = false;
        let ctx = CollectContext::new(Arc::new(config)).with_scan_root(temp.path().to_path_buf());

        let events = FileIntegrityCollector.collect(&ctx).await?;

        assert!(events.is_empty());
        Ok(())
    }
}
