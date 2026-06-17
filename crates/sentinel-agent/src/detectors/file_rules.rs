use crate::detectors::risk::RiskAssessment;
use crate::detectors::{
    evidence, package_activity_context, path_is_allowlisted, string_field, DetectContext, Detector,
    PackageActivityContext,
};
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
                "SSH-006",
                "authorized_keys unsafe file state",
                Category::Ssh,
                Severity::High,
                "An SSH authorized_keys file has unsafe permissions or points to a risky target.",
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
        let package_context = package_activity_context(events);
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
                        findings.push(critical_file_changed(event, ctx, &package_context));
                    } else if is_web_script_path(&path) && event.kind == "file_created" {
                        findings.push(webshell_path_created(event, ctx));
                    }
                }
                "file_snapshot" => {
                    if is_authorized_keys_path(&path) {
                        if let Some(finding) = authorized_keys_unsafe_state(event, ctx) {
                            findings.push(finding);
                        }
                    } else if event.field("content_markers").is_some() {
                        let assessment = webshell_content_assessment(event);
                        if assessment.is_suspicious(ctx.config.file_integrity.webshell_min_score) {
                            findings.push(webshell_content(event, ctx, assessment));
                        }
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

fn authorized_keys_unsafe_state(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let mode = string_field(event, "mode_octal");
    let symlink_target = string_field(event, "symlink_target");
    let mut reasons = Vec::new();
    let mut features = Vec::new();

    if authorized_keys_mode_is_writable_by_group_or_other(&mode) {
        reasons.push("authorized_keys is writable by group or other users".to_string());
        features.push("unsafe_authorized_keys_permissions".to_string());
    }
    if authorized_keys_symlink_target_is_risky(&symlink_target) {
        reasons.push("authorized_keys symlink points to a risky target".to_string());
        features.push("risky_authorized_keys_symlink".to_string());
    }
    if reasons.is_empty() {
        return None;
    }

    let path = string_field(event, "path");
    Some(
        Finding::new(
            &ctx.host_id,
            "SSH authorized_keys unsafe file state",
            "An SSH authorized_keys file has unsafe permissions or points to a risky target.",
            Severity::High,
            Category::Ssh,
            "SSH-006",
            &path,
        )
        .with_evidence(vec![
            evidence("path", path),
            evidence("file_type", string_field(event, "file_type")),
            evidence("mode_octal", mode),
            evidence("symlink_target", symlink_target),
            evidence("risk_reasons", reasons.join("; ")),
            evidence("risk_features", features.join(", ")),
        ])
        .with_impact(vec![
            "Unsafe SSH key file state can let another local user plant or replace SSH keys."
                .to_string(),
        ])
        .with_recommendations(vec![
            "Set authorized_keys ownership and permissions back to a strict state such as 0600."
                .to_string(),
            "Avoid authorized_keys symlinks to temporary, world-writable, or null-device paths."
                .to_string(),
            "Audit recent SSH logins and remove unknown keys if the state was not intentional."
                .to_string(),
        ]),
    )
}

fn critical_file_changed(
    event: &RawEvent,
    ctx: &DetectContext,
    package_context: &PackageActivityContext,
) -> Finding {
    let path = string_field(event, "path");
    let mut finding = Finding::new(
        &ctx.host_id,
        "Critical system file changed",
        "A monitored critical system file changed relative to the baseline.",
        Severity::High,
        Category::FileIntegrity,
        "FILE-001",
        &path,
    )
    .with_evidence({
        let mut items = diff_evidence(event);
        items.extend(package_context.evidence());
        items
    })
    .with_impact(vec![
        "Changes to identity, sudo, SSH, cron, or systemd files may affect persistence or privilege.".to_string(),
    ])
    .with_recommendations(vec![
        "Review the file diff from a trusted shell session.".to_string(),
        "Correlate this change with package updates or administrative activity.".to_string(),
    ]);
    if let Some(recommendation) = package_context.recommendation() {
        finding.recommendations.push(recommendation);
    }
    finding
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

fn webshell_content(event: &RawEvent, ctx: &DetectContext, assessment: RiskAssessment) -> Finding {
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
        evidence("risk_score", assessment.score.to_string()),
        evidence("risk_reasons", assessment.reason_text()),
        evidence("risk_features", assessment.feature_names()),
    ])
    .with_impact(vec![
        "The file may allow remote command execution if reachable by a web server.".to_string(),
    ])
    .with_recommendations(vec![
        "Quarantine only after confirming it is not legitimate application code.".to_string(),
        "Review web logs and deployment history for the file.".to_string(),
    ])
}

fn webshell_content_assessment(event: &RawEvent) -> RiskAssessment {
    let markers = marker_set(event);
    let mut assessment = RiskAssessment::default();

    let web_script_context =
        event.field("is_web_path") == Some("true") && is_script_like_event(event);

    if has_command_execution_markers(&markers) {
        assessment.add_signal(
            55,
            "command_execution_marker",
            "file contains command-execution style markers",
        );
    }
    if has_dynamic_execution_markers(&markers) {
        assessment.add_signal(
            40,
            "dynamic_code_marker",
            "file contains dynamic code execution markers",
        );
    }
    if has_encoded_payload_markers(&markers) {
        assessment.add_signal(
            35,
            "encoded_payload_marker",
            "file contains encoded-payload markers",
        );
    }
    if web_script_context {
        assessment.add_signal(
            60,
            "web_script_context",
            "marker appears in a script-like file under a web path",
        );
    }
    if has_command_execution_markers(&markers) && web_script_context {
        assessment.add_signal(
            80,
            "web_command_execution",
            "command-execution marker appears in a script-like web file",
        );
    }
    if has_dynamic_and_encoded_markers(&markers) {
        assessment.add_signal(
            85,
            "encoded_dynamic_execution",
            "dynamic execution marker is combined with encoded payload markers",
        );
    }
    if has_command_and_encoded_markers(&markers) {
        assessment.add_signal(
            90,
            "encoded_command_execution",
            "command-execution marker is combined with encoded payload markers",
        );
    }
    if markers.contains("long_base64") && web_script_context {
        assessment.add_signal(
            75,
            "large_encoded_web_script",
            "large encoded token appears in a script-like web file",
        );
    }
    if event.field("hidden") == Some("true") && assessment.score >= 55 {
        assessment.add_signal(
            75,
            "hidden_suspicious_script",
            "suspicious markers appear in a hidden file",
        );
    }
    assessment
}

fn marker_set(event: &RawEvent) -> std::collections::BTreeSet<String> {
    string_field(event, "content_markers")
        .split(',')
        .map(str::trim)
        .filter(|marker| !marker.is_empty())
        .map(str::to_string)
        .collect()
}

fn has_dynamic_and_encoded_markers(markers: &std::collections::BTreeSet<String>) -> bool {
    has_dynamic_execution_markers(markers) && has_encoded_payload_markers(markers)
}

fn has_command_and_encoded_markers(markers: &std::collections::BTreeSet<String>) -> bool {
    has_command_execution_markers(markers) && has_encoded_payload_markers(markers)
}

fn has_command_execution_markers(markers: &std::collections::BTreeSet<String>) -> bool {
    markers.contains("system_call")
        || markers.contains("shell_exec")
        || markers.contains("passthru")
        || markers.contains("dev_tcp")
        || markers.contains("cmd_exe")
}

fn has_dynamic_execution_markers(markers: &std::collections::BTreeSet<String>) -> bool {
    markers.contains("eval_call") || markers.contains("assert_call")
}

fn has_encoded_payload_markers(markers: &std::collections::BTreeSet<String>) -> bool {
    markers.contains("base64_decode") || markers.contains("long_base64")
}

fn is_script_like_event(event: &RawEvent) -> bool {
    let extension = string_field(event, "extension");
    matches!(
        extension.as_str(),
        "php" | "phtml" | "jsp" | "asp" | "aspx" | "cgi" | "pl" | "py" | "sh"
    ) || is_web_script_path(&string_field(event, "path"))
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

fn authorized_keys_mode_is_writable_by_group_or_other(mode: &str) -> bool {
    let Some(mode) = parse_octal_mode(mode) else {
        return false;
    };
    mode & 0o022 != 0
}

fn parse_octal_mode(mode: &str) -> Option<u32> {
    let normalized = mode.trim().trim_start_matches("0o");
    u32::from_str_radix(normalized, 8).ok()
}

fn authorized_keys_symlink_target_is_risky(target: &str) -> bool {
    let normalized = target.trim().replace('\\', "/");
    if normalized.is_empty() {
        return false;
    }
    normalized == "/dev/null"
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/var/tmp/")
        || normalized.starts_with("/dev/shm/")
        || normalized.starts_with("/run/")
}

fn is_web_script_path(path: &str) -> bool {
    [".php", ".phtml", ".jsp", ".asp", ".aspx"]
        .iter()
        .any(|extension| path.to_ascii_lowercase().ends_with(extension))
}

#[cfg(test)]
mod tests {
    use super::{
        authorized_keys_unsafe_state, is_authorized_keys_path, webshell_content_assessment,
        FileDetector,
    };
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

    #[test]
    fn detects_unsafe_authorized_keys_permissions() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/root/.ssh/authorized_keys")
            .with_field("file_type", "file")
            .with_field("mode_octal", "0666");

        let finding = authorized_keys_unsafe_state(&event, &ctx).expect("unsafe key finding");

        assert_eq!(finding.rule_id, "SSH-006");
        assert!(finding.evidence.iter().any(|item| {
            item.key == "risk_features" && item.value.contains("unsafe_authorized_keys_permissions")
        }));
    }

    #[test]
    fn ignores_strict_authorized_keys_permissions() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/root/.ssh/authorized_keys")
            .with_field("file_type", "file")
            .with_field("mode_octal", "0600");

        assert!(authorized_keys_unsafe_state(&event, &ctx).is_none());
    }

    #[test]
    fn detects_authorized_keys_symlink_to_temp_target() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/home/app/.ssh/authorized_keys")
            .with_field("file_type", "symlink")
            .with_field("mode_octal", "0600")
            .with_field("symlink_target", "/dev/shm/.keys");

        let finding = authorized_keys_unsafe_state(&event, &ctx).expect("unsafe key finding");

        assert!(finding.evidence.iter().any(|item| {
            item.key == "risk_features" && item.value.contains("risky_authorized_keys_symlink")
        }));
    }

    #[test]
    fn webshell_content_requires_combined_risk_markers() {
        let benign_admin_script = RawEvent::new("file", "file_snapshot")
            .with_field("path", "/var/www/html/admin.php")
            .with_field("extension", "php")
            .with_field("is_web_path", "true")
            .with_field("content_markers", "eval_call");
        assert!(!webshell_content_assessment(&benign_admin_script).is_suspicious(70));

        let encoded_shell = RawEvent::new("file", "file_snapshot")
            .with_field("path", "/var/www/html/shell.php")
            .with_field("extension", "php")
            .with_field("is_web_path", "true")
            .with_field("content_markers", "eval_call,base64_decode");
        assert!(webshell_content_assessment(&encoded_shell).is_suspicious(70));

        let classic_webshell = RawEvent::new("file", "file_snapshot")
            .with_field("path", "/var/www/html/cmd.php")
            .with_field("extension", "php")
            .with_field("is_web_path", "true")
            .with_field("content_markers", "system_call");
        assert!(webshell_content_assessment(&classic_webshell).is_suspicious(70));

        let non_web_helper = RawEvent::new("file", "file_snapshot")
            .with_field("path", "/opt/admin/task.php")
            .with_field("extension", "php")
            .with_field("is_web_path", "false")
            .with_field("content_markers", "system_call");
        assert!(!webshell_content_assessment(&non_web_helper).is_suspicious(70));
    }

    #[test]
    fn critical_file_drift_includes_package_activity_context() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let events = vec![
            RawEvent::new("package_manager", "package_manager_activity")
                .with_field("path", "/var/log/dpkg.log"),
            RawEvent::new("baseline", "file_modified")
                .with_field("path", "/etc/systemd/system/app.service")
                .with_field("previous_hash", "old")
                .with_field("current_hash", "new"),
        ];

        let findings = FileDetector.detect(&events, &ctx);

        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "package_activity_recent" && item.value == "true"));
    }
}
