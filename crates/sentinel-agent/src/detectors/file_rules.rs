use crate::detectors::{evidence, path_is_allowlisted, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct FileDetector;

impl Detector for FileDetector {
    fn name(&self) -> &'static str {
        "file_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "SSH-005",
                "authorized_keys modified",
                Category::Ssh,
                Severity::High,
                "An SSH authorized_keys file changed relative to the baseline.",
            ),
            RuleMetadata::new(
                "FILE-001",
                "Critical file modified",
                Category::FileIntegrity,
                Severity::High,
                "A critical system file changed relative to the baseline.",
            ),
            RuleMetadata::new(
                "FILE-002",
                "WebShell-like file detected",
                Category::FileIntegrity,
                Severity::High,
                "A monitored file contains web shell style markers.",
            ),
            RuleMetadata::new(
                "FILE-003",
                "Executable file created in web directory",
                Category::FileIntegrity,
                Severity::Medium,
                "A file in a configured web root is executable or has a script extension.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events {
            let path = string_field(event, "path");
            if path.is_empty() || path_is_allowlisted(&path, &ctx.config.allowlist.file_paths) {
                continue;
            }
            match event.kind.as_str() {
                "file_created" | "file_modified" | "file_deleted" => {
                    if is_authorized_keys_path(&path) {
                        findings.push(authorized_keys_changed(event, ctx));
                    } else if is_critical_path(&path) {
                        findings.push(critical_file_changed(event, ctx));
                    } else if is_web_script_path(&path) && event.kind == "file_created" {
                        findings.push(webshell_path_created(event, ctx));
                    }
                }
                "file_snapshot" => {
                    if event.field("content_markers").is_some() {
                        findings.push(webshell_content(event, ctx));
                    } else if event.field("is_web_path") == Some("true")
                        && (event.field("executable") == Some("true") || is_web_script_path(&path))
                    {
                        findings.push(executable_web_file(event, ctx));
                    }
                }
                _ => {}
            }
        }
        findings
    }
}

fn authorized_keys_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "SSH authorized_keys changed",
        "An SSH authorized_keys file was created, modified, or deleted compared with the baseline.",
        Severity::High,
        Category::Ssh,
        "SSH-005",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_impact(vec![
        "Unexpected SSH keys can grant persistent remote access.".to_string(),
    ])
    .with_recommendations(vec![
        "Inspect the key owner and fingerprint before trusting the change.".to_string(),
        "Remove unknown keys and rotate credentials if unauthorized access is suspected."
            .to_string(),
    ])
}

fn critical_file_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Critical system file changed",
        "A monitored critical system file changed relative to the baseline.",
        Severity::High,
        Category::FileIntegrity,
        "FILE-001",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_impact(vec![
        "Changes to identity, sudo, SSH, cron, or systemd files may affect persistence or privilege.".to_string(),
    ])
    .with_recommendations(vec![
        "Review the file diff from a trusted shell session.".to_string(),
        "Correlate this change with package updates or administrative activity.".to_string(),
    ])
}

fn webshell_path_created(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Script-like file created in monitored path",
        "A newly observed file has an extension commonly used by web shells.",
        Severity::Medium,
        Category::FileIntegrity,
        "FILE-002",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_recommendations(vec![
        "Confirm the file was deployed intentionally.".to_string(),
        "Search web access logs for requests to this path.".to_string(),
    ])
}

fn webshell_content(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "WebShell-like file content detected",
        "A monitored file contains markers commonly seen in web shells.",
        Severity::High,
        Category::FileIntegrity,
        "FILE-002",
        &path,
    )
    .with_evidence(vec![
        evidence("path", path),
        evidence("content_markers", string_field(event, "content_markers")),
        evidence("size", string_field(event, "size")),
    ])
    .with_impact(vec![
        "The file may allow remote command execution if reachable by a web server.".to_string(),
    ])
    .with_recommendations(vec![
        "Quarantine only after confirming it is not legitimate application code.".to_string(),
        "Review web logs and deployment history for the file.".to_string(),
    ])
}

fn executable_web_file(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Executable file in web directory",
        "A monitored web path contains a file that is executable or script-like.",
        Severity::Medium,
        Category::FileIntegrity,
        "FILE-003",
        &path,
    )
    .with_evidence(vec![
        evidence("path", path),
        evidence("executable", string_field(event, "executable")),
        evidence("extension", string_field(event, "extension")),
    ])
    .with_recommendations(vec![
        "Check whether the web server can execute this file.".to_string(),
        "Move uploads outside executable paths where possible.".to_string(),
    ])
}

fn diff_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("change", &event.kind),
        evidence("path", string_field(event, "path")),
        evidence("previous_hash", string_field(event, "previous_hash")),
        evidence("current_hash", string_field(event, "current_hash")),
    ]
}

fn is_critical_path(path: &str) -> bool {
    [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d/",
        "/etc/ssh/",
        "/etc/systemd/system/",
        "/etc/crontab",
        "/etc/cron.d/",
        "/var/spool/cron/",
        "/etc/profile",
        "/etc/profile.d/",
        "/etc/bash.bashrc",
        "/etc/ld.so.preload",
    ]
    .iter()
    .any(|prefix| path == *prefix || path.starts_with(prefix))
}

fn is_authorized_keys_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.ends_with("/.ssh/authorized_keys") || normalized.ends_with("/.ssh/authorized_keys2")
}

fn is_web_script_path(path: &str) -> bool {
    [".php", ".phtml", ".jsp", ".asp", ".aspx"]
        .iter()
        .any(|extension| path.to_ascii_lowercase().ends_with(extension))
}

#[cfg(test)]
mod tests {
    use super::{is_authorized_keys_path, FileDetector};
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn recognizes_authorized_keys_and_legacy_authorized_keys2() {
        assert!(is_authorized_keys_path("/root/.ssh/authorized_keys"));
        assert!(is_authorized_keys_path("/home/app/.ssh/authorized_keys2"));
        assert!(!is_authorized_keys_path("/tmp/authorized_keys"));
    }

    #[test]
    fn detects_authorized_keys2_baseline_drift_as_ssh_finding() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("baseline", "file_modified")
            .with_field("path", "/home/app/.ssh/authorized_keys2")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new");

        let findings = FileDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SSH-005");
    }
}
