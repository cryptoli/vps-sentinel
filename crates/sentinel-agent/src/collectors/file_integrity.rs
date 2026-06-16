use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{hash_file_limited, is_executable, is_hidden, path_string, read_small_text};
use async_trait::async_trait;
use glob::glob;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const SKIPPED_DIRS: &[&str] = &["node_modules", "vendor", ".git", "cache", ".cache"];
const MAX_CONTENT_SCAN_BYTES: u64 = 256 * 1024;

pub struct FileIntegrityCollector;

#[async_trait]
impl Collector for FileIntegrityCollector {
    fn name(&self) -> &'static str {
        "file_integrity"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.file_integrity.enabled {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        for configured_path in &ctx.config.file_integrity.paths {
            let resolved = ctx.resolve(configured_path);
            for path in expand_path(&resolved) {
                collect_path(ctx, &path, &mut events);
            }
        }
        Ok(events)
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

fn collect_path(ctx: &CollectContext, path: &Path, events: &mut Vec<RawEvent>) {
    if !path.exists() {
        return;
    }
    if path.is_file() {
        if let Some(event) = file_event(ctx, path) {
            events.push(event);
        }
        return;
    }
    if !path.is_dir() {
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
                events.push(event);
            }
        }
    }
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
    let metadata = fs::metadata(path).ok()?;
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
    let markers = content_markers(path);
    let is_web_path = is_under_any(path, &ctx.config.web.web_roots, ctx);

    let mut event = RawEvent::new("file_integrity", "file_snapshot")
        .with_field("path", path_text)
        .with_field("size", metadata.len().to_string())
        .with_field("hash", hash)
        .with_field("extension", extension)
        .with_field("executable", is_executable(&metadata).to_string())
        .with_field("hidden", is_hidden(path).to_string())
        .with_field("is_web_path", is_web_path.to_string());

    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            event = event.with_field("modified_unix", duration.as_secs().to_string());
        }
    }
    if !markers.is_empty() {
        event = event.with_field("content_markers", markers.join(","));
    }
    Some(event)
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
    use super::content_markers;
    use std::fs;

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
}
