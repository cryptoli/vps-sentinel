use crate::evidence_score;
use sentinel_core::{Category, Confidence, Evidence, Finding, RiskScoringConfig, Severity};
use std::collections::BTreeSet;

const SCORE_KEY: &str = "unified_risk_score";
const LEVEL_KEY: &str = "unified_risk_level";
const FEATURES_KEY: &str = "unified_risk_features";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedRisk {
    pub score: u16,
    pub level: &'static str,
    pub features: Vec<String>,
}

pub fn enrich_findings(findings: &mut [Finding]) {
    enrich_findings_with_scoring(findings, &RiskScoringConfig::default());
}

pub fn enrich_findings_with_scoring(findings: &mut [Finding], scoring: &RiskScoringConfig) {
    for finding in findings {
        let risk = score_finding_with_scoring(finding, scoring);
        upsert_evidence(
            &mut finding.evidence,
            SCORE_KEY,
            risk.score.min(100).to_string(),
        );
        upsert_evidence(&mut finding.evidence, LEVEL_KEY, risk.level);
        upsert_evidence(
            &mut finding.evidence,
            FEATURES_KEY,
            risk.features.join(", "),
        );
    }
}

pub fn score_finding(finding: &Finding) -> UnifiedRisk {
    score_finding_with_scoring(finding, &RiskScoringConfig::default())
}

pub fn score_finding_with_scoring(finding: &Finding, scoring: &RiskScoringConfig) -> UnifiedRisk {
    let mut score = severity_score(finding.severity);
    let mut features = BTreeSet::new();
    features.insert(format!("severity:{}", severity_feature(finding.severity)));

    let confidence_score = confidence_score(finding.confidence);
    score = score.max(confidence_score);
    features.insert(format!(
        "confidence:{}",
        confidence_feature(finding.confidence)
    ));

    if let Some(detector_score) = evidence_score(finding, "risk_score") {
        score = score.max(detector_score);
        features.insert("detector_score".to_string());
    }
    if let Some(detector_score) = evidence_score(finding, "behavior_score") {
        score = score.max(detector_score);
        features.insert("behavior_score".to_string());
    }
    if let Some(drift_score) = evidence_score(finding, "baseline_drift_score") {
        score = score.max(drift_score);
        features.insert("baseline_drift_score".to_string());
    }
    if let Some(assessment_score) = evidence_score::evidence_score(finding) {
        score = score.max(assessment_score);
        features.insert("evidence_score".to_string());
    }
    if evidence_value(finding, "threat_intel_match").as_deref() == Some("true") {
        score = score.saturating_add(scoring.threat_intel_bonus).min(100);
        features.insert("threat_intel_match".to_string());
    }
    if evidence_value(finding, "active_response_status").is_some() {
        score = score.saturating_add(scoring.active_response_bonus).min(100);
        features.insert("active_response".to_string());
    }
    if evidence_score(finding, "attack_chain_stage_count").is_some_and(|value| value >= 3) {
        score = score
            .saturating_add(scoring.high_stage_count_bonus)
            .min(100);
        features.insert("attack_chain_stage_count".to_string());
    }
    if is_state_drift(finding) {
        score = score.saturating_sub(scoring.state_drift_deduction);
        features.insert("state_drift".to_string());
    }
    if finding.category == Category::Rootkit {
        score = score.saturating_add(scoring.rootkit_context_bonus).min(100);
        features.insert("rootkit_context".to_string());
    }

    let level = risk_level(score);
    UnifiedRisk {
        score,
        level,
        features: features.into_iter().collect(),
    }
}

pub fn unified_score(finding: &Finding) -> u16 {
    evidence_score(finding, SCORE_KEY).unwrap_or_else(|| score_finding(finding).score)
}

pub fn confidence_percent(finding: &Finding) -> u16 {
    match finding.confidence {
        Confidence::Low => 40,
        Confidence::Medium => 65,
        Confidence::High => 85,
    }
}

fn severity_score(severity: Severity) -> u16 {
    match severity {
        Severity::Info => 10,
        Severity::Low => 30,
        Severity::Medium => 55,
        Severity::High => 75,
        Severity::Critical => 90,
    }
}

fn confidence_score(confidence: Confidence) -> u16 {
    match confidence {
        Confidence::Low => 35,
        Confidence::Medium => 60,
        Confidence::High => 80,
    }
}

fn severity_feature(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_feature(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

fn risk_level(score: u16) -> &'static str {
    match score {
        0..=29 => "info",
        30..=54 => "low",
        55..=74 => "medium",
        75..=89 => "high",
        _ => "critical",
    }
}

fn evidence_score(finding: &Finding, key: &str) -> Option<u16> {
    evidence_value(finding, key)?
        .parse::<u16>()
        .ok()
        .map(|value| value.min(100))
}

fn evidence_value(finding: &Finding, key: &str) -> Option<String> {
    finding
        .evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.clone())
}

fn is_state_drift(finding: &Finding) -> bool {
    finding
        .evidence
        .iter()
        .any(|item| item.key.ends_with("_changed") || item.key.ends_with("_drift"))
}

fn upsert_evidence(evidence: &mut Vec<Evidence>, key: &str, value: impl Into<String>) {
    let value = value.into();
    if let Some(existing) = evidence.iter_mut().find(|item| item.key == key) {
        existing.value = value;
        return;
    }
    evidence.push(Evidence::new(key, value));
}

#[cfg(test)]
mod tests {
    use super::{score_finding, unified_score};
    use sentinel_core::{Category, Confidence, Evidence, Finding, Severity};

    #[test]
    fn uses_detector_score_when_it_is_stronger_than_severity() {
        let finding = Finding::new(
            "host",
            "test",
            "test",
            Severity::Low,
            Category::Process,
            "P",
            "p",
        )
        .with_evidence(vec![Evidence::new("risk_score", "86")])
        .with_confidence(Confidence::Medium);

        let risk = score_finding(&finding);

        assert_eq!(risk.score, 86);
        assert!(risk.features.contains(&"detector_score".to_string()));
    }

    #[test]
    fn unified_score_reads_enriched_value() {
        let finding = Finding::new(
            "host",
            "test",
            "test",
            Severity::Low,
            Category::Process,
            "P",
            "p",
        )
        .with_evidence(vec![Evidence::new("unified_risk_score", "91")]);

        assert_eq!(unified_score(&finding), 91);
    }

    #[test]
    fn uses_evidence_score_when_it_is_stronger_than_severity() {
        let finding = Finding::new(
            "host",
            "test",
            "test",
            Severity::Low,
            Category::Process,
            "P",
            "p",
        )
        .with_evidence(vec![Evidence::new("evidence_score", "88")]);

        let risk = score_finding(&finding);

        assert_eq!(risk.score, 88);
        assert!(risk.features.contains(&"evidence_score".to_string()));
    }

    #[test]
    fn uses_baseline_drift_score_when_it_is_stronger_than_severity() {
        let finding = Finding::new(
            "host",
            "test",
            "test",
            Severity::Medium,
            Category::Network,
            "NET-002",
            "tcp:0.0.0.0:443",
        )
        .with_evidence(vec![Evidence::new("baseline_drift_score", "82")])
        .with_confidence(Confidence::Medium);

        let risk = score_finding(&finding);

        assert_eq!(risk.score, 82);
        assert!(risk.features.contains(&"baseline_drift_score".to_string()));
    }
}
