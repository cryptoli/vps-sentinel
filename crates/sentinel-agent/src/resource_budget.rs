use crate::risk_score::{confidence_percent, unified_score};
use crate::utils::text::truncate_utf8;
use sentinel_core::{evidence_schema::keys, Finding, SentinelConfig, Severity};
use std::cmp::Reverse;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceBudgetReport {
    pub dropped_findings: usize,
    pub truncated_evidence_items: usize,
    pub truncated_evidence_values: usize,
}

pub fn apply_resource_budget(
    findings: &mut Vec<Finding>,
    config: &SentinelConfig,
) -> ResourceBudgetReport {
    if !config.resource_budget.enabled {
        return ResourceBudgetReport::default();
    }
    let mut report = ResourceBudgetReport::default();
    for finding in findings.iter_mut() {
        report.truncated_evidence_values +=
            limit_evidence_values(finding, config.resource_budget.max_evidence_value_bytes);
        report.truncated_evidence_items += limit_evidence_items(
            finding,
            config.resource_budget.max_evidence_items_per_finding,
        );
    }
    if findings.len() > config.resource_budget.max_findings_per_scan {
        findings.sort_by_key(|finding| Reverse(finding_rank(finding)));
        report.dropped_findings = findings.len() - config.resource_budget.max_findings_per_scan;
        findings.truncate(config.resource_budget.max_findings_per_scan);
    }
    report
}

fn limit_evidence_values(finding: &mut Finding, max_bytes: usize) -> usize {
    let mut truncated = 0usize;
    for item in &mut finding.evidence {
        if item.value.len() > max_bytes {
            item.value = truncate_utf8(&item.value, max_bytes);
            truncated += 1;
        }
    }
    truncated
}

fn limit_evidence_items(finding: &mut Finding, limit: usize) -> usize {
    if finding.evidence.len() <= limit {
        return 0;
    }
    finding.evidence.sort_by(|left, right| {
        evidence_priority(&right.key)
            .cmp(&evidence_priority(&left.key))
            .then_with(|| left.key.cmp(&right.key))
    });
    let dropped = finding.evidence.len() - limit;
    finding.evidence.truncate(limit);
    dropped
}

fn finding_rank(finding: &Finding) -> (u16, u16, u16, i64, String) {
    (
        severity_rank(finding.severity),
        unified_score(finding),
        confidence_percent(finding),
        finding.timestamp.timestamp_millis(),
        finding.dedup_key.clone(),
    )
}

fn severity_rank(severity: Severity) -> u16 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}

fn evidence_priority(key: &str) -> u8 {
    if key.starts_with("active_response_") {
        return 100;
    }
    if key.starts_with("attack_fingerprint_") {
        return 95;
    }
    if key.starts_with("baseline_") {
        return 75;
    }
    match key {
        keys::SOURCE_IP | keys::ACTIVE_RESPONSE_IP => 90,
        keys::PATH | keys::EXE_PATH | keys::CMDLINE | keys::PROCESS_NAME => 80,
        keys::PROBE_FAMILY
        | keys::PROBE_FAMILIES
        | keys::RESPONSE_PROFILE
        | keys::FAILURE_COUNT
        | keys::USERS
        | keys::SAMPLE_PATHS => 70,
        keys::RISK_SCORE | keys::UNIFIED_RISK_SCORE => 60,
        _ => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::apply_resource_budget;
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

    #[test]
    fn budget_keeps_high_priority_evidence() {
        let mut config = SentinelConfig::default();
        config.resource_budget.max_evidence_items_per_finding = 2;
        let mut findings = vec![Finding::new(
            "host",
            "test",
            "test",
            Severity::High,
            Category::Web,
            "WEB-001",
            "x",
        )
        .with_evidence(vec![
            Evidence::new("low", "x"),
            Evidence::new("source_ip", "8.8.8.8"),
            Evidence::new("attack_fingerprint_id", "WEB-FP-test"),
        ])];

        let report = apply_resource_budget(&mut findings, &config);

        assert_eq!(report.truncated_evidence_items, 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "source_ip"));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "attack_fingerprint_id"));
    }

    #[test]
    fn budget_keeps_highest_risk_findings() {
        let mut config = SentinelConfig::default();
        config.resource_budget.max_findings_per_scan = 1;
        let low = Finding::new(
            "host",
            "low",
            "low",
            Severity::Low,
            Category::System,
            "REPORT-001",
            "low",
        );
        let high = Finding::new(
            "host",
            "high",
            "high",
            Severity::Critical,
            Category::Process,
            "PROC-001",
            "high",
        );
        let mut findings = vec![low, high];

        let report = apply_resource_budget(&mut findings, &config);

        assert_eq!(report.dropped_findings, 1);
        assert_eq!(findings[0].rule_id, "PROC-001");
    }
}
