use crate::risk_score::unified_score;
use sentinel_core::{evidence_value, Category, Evidence, Finding, SentinelConfig, Severity};
use std::collections::{BTreeMap, BTreeSet};

pub const TIMELINE_RULE_ID: &str = "TIMELINE-001";

#[derive(Debug, Clone)]
struct TimelineGroup<'a> {
    key: String,
    subject: String,
    findings: Vec<&'a Finding>,
    phases: BTreeSet<&'static str>,
    rules: BTreeSet<String>,
    score: u16,
}

pub fn correlate_timelines(findings: &[Finding], config: &SentinelConfig) -> Vec<Finding> {
    if findings.len() < 2 || !config.incidents.enabled {
        return Vec::new();
    }
    let mut groups = BTreeMap::<String, TimelineGroup<'_>>::new();
    for finding in findings {
        for key in correlation_keys(finding) {
            let group = groups.entry(key.clone()).or_insert_with(|| TimelineGroup {
                key: key.clone(),
                subject: timeline_subject(&key),
                findings: Vec::new(),
                phases: BTreeSet::new(),
                rules: BTreeSet::new(),
                score: 0,
            });
            group.score = group.score.saturating_add(unified_score(finding)).min(300);
            group.rules.insert(finding.rule_id.clone());
            if let Some(phase) = phase_name(finding) {
                group.phases.insert(phase);
            }
            if group.findings.len() < config.incidents.max_findings_per_incident {
                group.findings.push(finding);
            }
        }
    }
    groups
        .into_values()
        .filter(qualified_group)
        .map(timeline_finding)
        .collect()
}

fn correlation_keys(finding: &Finding) -> Vec<String> {
    if !is_timeline_candidate(finding) {
        return Vec::new();
    }
    let mut keys = Vec::new();
    if let Some(ip) = evidence_value(&finding.evidence, "source_ip") {
        keys.push(format!("source_ip:{ip}"));
    }
    if let Some(path) = evidence_value(&finding.evidence, "exe_path")
        .or_else(|| evidence_value(&finding.evidence, "path"))
    {
        keys.push(format!("path:{}", normalize_path(path)));
    }
    if let Some(process_name) = evidence_value(&finding.evidence, "process_name")
        .or_else(|| evidence_value(&finding.evidence, "name"))
    {
        keys.push(format!("process:{process_name}"));
    }
    keys.sort();
    keys.dedup();
    keys
}

fn is_timeline_candidate(finding: &Finding) -> bool {
    if finding.rule_id == TIMELINE_RULE_ID {
        return false;
    }
    matches!(
        finding.category,
        Category::Web
            | Category::Ssh
            | Category::Process
            | Category::Persistence
            | Category::FileIntegrity
            | Category::Network
            | Category::Rootkit
            | Category::System
    ) && (finding.severity.meets(Severity::Medium)
        || high_value_rule(&finding.rule_id)
        || evidence_value(&finding.evidence, "active_response_status").is_some())
}

fn high_value_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "WEB-001"
            | "WEB-002"
            | "SSH-003"
            | "SSH-007"
            | "PROC-001"
            | "PROC-002"
            | "PROC-003"
            | "PROC-004"
            | "PROC-005"
            | "PROC-006"
            | "PERSIST-002"
            | "TAMPER-001"
            | "TAMPER-002"
            | "TAMPER-003"
            | "ROOTKIT-001"
    )
}

fn phase_name(finding: &Finding) -> Option<&'static str> {
    match finding.category {
        Category::Web => Some("web_probe"),
        Category::Ssh => Some("ssh_access"),
        Category::Process => Some("process_execution"),
        Category::Persistence => Some("persistence"),
        Category::FileIntegrity => Some("file_change"),
        Category::Network => Some("network_exposure"),
        Category::Rootkit => Some("rootkit_signal"),
        Category::System if finding.rule_id.starts_with("TAMPER-") => Some("anti_forensics"),
        _ => None,
    }
}

fn qualified_group(group: &TimelineGroup<'_>) -> bool {
    if group.findings.len() < 2 || group.phases.len() < 2 {
        return false;
    }
    let has_execution = group.phases.contains("process_execution")
        || group.phases.contains("persistence")
        || group.phases.contains("anti_forensics")
        || group.phases.contains("rootkit_signal");
    let has_external = group.phases.contains("web_probe") || group.phases.contains("ssh_access");
    let has_high_rule = group
        .findings
        .iter()
        .any(|finding| finding.severity.meets(Severity::High) || high_value_rule(&finding.rule_id));
    (has_execution && has_high_rule) || (has_external && group.phases.len() >= 3)
}

fn timeline_finding(group: TimelineGroup<'_>) -> Finding {
    let severity = if group.score >= 180 {
        Severity::High
    } else {
        Severity::Medium
    };
    let phases = group.phases.into_iter().collect::<Vec<_>>().join(", ");
    let rules = group.rules.into_iter().collect::<Vec<_>>().join(", ");
    Finding::new(
        &group.findings[0].host_id,
        "Correlated intrusion timeline detected",
        "Multiple related signals form an intrusion-style timeline in the same scan window.",
        severity,
        Category::System,
        TIMELINE_RULE_ID,
        &group.subject,
    )
    .with_evidence_deduped_by(
        vec![
            Evidence::new("timeline_subject", group.subject),
            Evidence::new("timeline_key", group.key),
            Evidence::new("timeline_phases", phases),
            Evidence::new("timeline_rules", rules),
            Evidence::new("timeline_score", group.score.to_string()),
            Evidence::new("related_finding_count", group.findings.len().to_string()),
        ],
        &["timeline_key", "timeline_phases"],
    )
    .with_impact(vec![
        "A chain of related signals is more suspicious than each signal in isolation.".to_string(),
    ])
    .with_recommendations(vec![
        "Review the related source, process, file, and persistence evidence before approving baseline changes.".to_string(),
        "Preserve logs and process metadata if the chain includes execution, persistence, or anti-forensics.".to_string(),
    ])
}

fn timeline_subject(key: &str) -> String {
    key.split_once(':')
        .map(|(_, value)| value.to_string())
        .unwrap_or_else(|| key.to_string())
}

fn normalize_path(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::correlate_timelines;
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

    #[test]
    fn correlates_process_and_persistence_on_same_path() {
        let config = SentinelConfig::default();
        let findings = vec![
            Finding::new(
                "host",
                "process",
                "process",
                Severity::High,
                Category::Process,
                "PROC-005",
                "pid",
            )
            .with_evidence(vec![
                Evidence::new("exe_path", "/tmp/.x"),
                Evidence::new("unified_risk_score", "82"),
            ]),
            Finding::new(
                "host",
                "persistence",
                "persistence",
                Severity::Medium,
                Category::Persistence,
                "PERSIST-002",
                "/tmp/.x",
            )
            .with_evidence(vec![
                Evidence::new("path", "/tmp/.x"),
                Evidence::new("unified_risk_score", "76"),
            ]),
        ];

        let timelines = correlate_timelines(&findings, &config);

        assert_eq!(timelines.len(), 1);
        assert_eq!(timelines[0].rule_id, "TIMELINE-001");
    }

    #[test]
    fn ignores_single_phase_baseline_noise() {
        let config = SentinelConfig::default();
        let findings = vec![
            Finding::new(
                "host",
                "file",
                "file",
                Severity::Medium,
                Category::FileIntegrity,
                "FILE-001",
                "/etc/passwd",
            )
            .with_evidence(vec![Evidence::new("path", "/etc/passwd")]),
            Finding::new(
                "host",
                "file2",
                "file2",
                Severity::Medium,
                Category::FileIntegrity,
                "FILE-001",
                "/etc/shadow",
            )
            .with_evidence(vec![Evidence::new("path", "/etc/shadow")]),
        ];

        assert!(correlate_timelines(&findings, &config).is_empty());
    }
}
