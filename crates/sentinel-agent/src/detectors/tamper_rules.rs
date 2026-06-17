use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use chrono::{DateTime, Utc};
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct TamperDetector;

impl Detector for TamperDetector {
    fn name(&self) -> &'static str {
        "tamper_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "TAMPER-001",
                "Sensitive log redirected to risky target",
                Category::System,
                Severity::Critical,
                "A sensitive log file is a symlink to a null device or temporary path.",
            ),
            RuleMetadata::new(
                "TAMPER-002",
                "Sensitive log was abruptly truncated",
                Category::System,
                Severity::High,
                "A sensitive log file shrank sharply compared with the previous scan.",
            ),
            RuleMetadata::new(
                "TAMPER-003",
                "Sensitive log disappeared",
                Category::System,
                Severity::High,
                "A sensitive log file that existed in previous scans is now missing.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.kind == "log_file_snapshot")
        {
            if log_symlink_target_is_risky(event) {
                findings.push(log_redirected(event, ctx));
            }
            if event.field("log_size_drop") == Some("true")
                && event.field("recent_rotated_sibling") != Some("true")
            {
                findings.push(log_truncated(event, ctx));
            }
            if event.field("log_file_missing") == Some("true") {
                findings.push(log_missing(event, ctx));
            }
        }
        findings
    }
}

fn log_redirected(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Sensitive log redirected to risky target",
        "A sensitive log file is a symlink to a null device or temporary path.",
        Severity::Critical,
        Category::System,
        "TAMPER-001",
        &path,
    )
    .with_evidence(common_log_evidence(event))
    .with_impact(vec![
        "Authentication or login evidence may be hidden from normal log review.".to_string(),
    ])
    .with_recommendations(vec![
        "Restore the log path to a regular file owned by the expected system account.".to_string(),
        "Review recent SSH logins, sudo activity, and persistence locations from a trusted session."
            .to_string(),
    ])
}

fn log_truncated(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Sensitive log was abruptly truncated",
        "A sensitive log file shrank sharply compared with the previous scan without recent rotation context.",
        Severity::High,
        Category::System,
        "TAMPER-002",
        &path,
    )
    .with_evidence(common_log_evidence(event))
    .with_impact(vec![
        "Abrupt log truncation can indicate post-intrusion cleanup or anti-forensics.".to_string(),
    ])
    .with_recommendations(vec![
        "Check rotated logs, journal entries, shell history, and remote login records for the same time window."
            .to_string(),
        "Preserve the disk image or log directory before further cleanup if compromise is suspected."
            .to_string(),
    ])
}

fn log_missing(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Sensitive log disappeared",
        "A sensitive log file that existed in previous scans is now missing.",
        Severity::High,
        Category::System,
        "TAMPER-003",
        &path,
    )
    .with_evidence(common_log_evidence(event))
    .with_impact(vec![
        "A missing authentication log can hide login, brute-force, or privilege-escalation evidence."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Confirm whether logrotate or logging configuration intentionally moved this file."
            .to_string(),
        "If no maintenance explains it, inspect journal logs, rotated files, SSH sessions, and persistence locations."
            .to_string(),
    ])
}

fn common_log_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    let mut items = vec![
        evidence("path", string_field(event, "path")),
        evidence("file_type", string_field(event, "file_type")),
        evidence("size", string_field(event, "size")),
    ];
    push_if_present(&mut items, event, "symlink_target");
    push_if_present(&mut items, event, "previous_size");
    push_if_present(&mut items, event, "current_size");
    push_if_present(&mut items, event, "dropped_bytes");
    push_if_present(&mut items, event, "drop_percent");
    push_if_present(&mut items, event, "rotated_sibling");
    push_if_present(&mut items, event, "log_file_missing");
    push_if_present(&mut items, event, "previous_file_type");
    push_if_present(&mut items, event, "previous_symlink_target");
    push_unix_time_evidence(&mut items, event, "modified_unix", "modified_time_utc");
    push_unix_time_evidence(
        &mut items,
        event,
        "previous_modified_unix",
        "previous_modified_time_utc",
    );
    items
}

fn push_if_present(items: &mut Vec<sentinel_core::Evidence>, event: &RawEvent, key: &str) {
    let value = string_field(event, key);
    if !value.trim().is_empty() {
        items.push(evidence(key, value));
    }
}

fn push_unix_time_evidence(
    items: &mut Vec<sentinel_core::Evidence>,
    event: &RawEvent,
    source_key: &str,
    evidence_key: &str,
) {
    let Some(seconds) = event
        .field(source_key)
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return;
    };
    let Some(timestamp) = DateTime::<Utc>::from_timestamp(seconds, 0) else {
        return;
    };
    items.push(evidence(
        evidence_key,
        timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    ));
}

fn log_symlink_target_is_risky(event: &RawEvent) -> bool {
    if event.field("file_type") != Some("symlink") {
        return false;
    }
    let target = string_field(event, "symlink_target").replace('\\', "/");
    target == "/dev/null"
        || target.starts_with("/tmp/")
        || target.starts_with("/var/tmp/")
        || target.starts_with("/dev/shm/")
        || target.starts_with("/run/")
}

#[cfg(test)]
mod tests {
    use super::{log_symlink_target_is_risky, TamperDetector};
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn detects_sensitive_log_redirected_to_null() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("log_integrity", "log_file_snapshot")
            .with_field("path", "/var/log/auth.log")
            .with_field("file_type", "symlink")
            .with_field("symlink_target", "/dev/null")
            .with_field("size", "0");

        let findings = TamperDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TAMPER-001");
    }

    #[test]
    fn detects_sensitive_log_truncation_without_rotation_context() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("log_integrity", "log_file_snapshot")
            .with_field("path", "/var/log/secure")
            .with_field("file_type", "file")
            .with_field("size", "128")
            .with_field("log_size_drop", "true")
            .with_field("previous_size", "524288")
            .with_field("current_size", "128")
            .with_field("dropped_bytes", "524160")
            .with_field("drop_percent", "99");

        let findings = TamperDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TAMPER-002");
    }

    #[test]
    fn ignores_log_truncation_with_recent_rotation_context() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("log_integrity", "log_file_snapshot")
            .with_field("path", "/var/log/auth.log")
            .with_field("file_type", "file")
            .with_field("size", "0")
            .with_field("log_size_drop", "true")
            .with_field("recent_rotated_sibling", "true")
            .with_field("rotated_sibling", "/var/log/auth.log.1");

        let findings = TamperDetector.detect(&[event], &ctx);

        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_ordinary_log_file() {
        let event = RawEvent::new("log_integrity", "log_file_snapshot")
            .with_field("path", "/var/log/auth.log")
            .with_field("file_type", "file")
            .with_field("size", "4096");

        assert!(!log_symlink_target_is_risky(&event));
    }

    #[test]
    fn detects_sensitive_log_disappeared_from_previous_state() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("log_integrity", "log_file_snapshot")
            .with_field("path", "/var/log/auth.log")
            .with_field("file_type", "missing")
            .with_field("size", "0")
            .with_field("log_file_missing", "true")
            .with_field("previous_file_type", "file")
            .with_field("previous_size", "4096");

        let findings = TamperDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "TAMPER-003");
    }
}
