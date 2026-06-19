use crate::evidence_schema::{canonical_key, normalize_evidence_items};
use crate::severity::Severity;
use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use uuid::Uuid;

/// Detector confidence after evidence correlation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl Display for Confidence {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        };
        f.write_str(text)
    }
}

/// High-level security area for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Category {
    Ssh,
    User,
    Privilege,
    Persistence,
    Process,
    Network,
    FileIntegrity,
    Web,
    Docker,
    Rootkit,
    ConfigRisk,
    System,
}

impl Display for Category {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Ssh => "ssh",
            Self::User => "user",
            Self::Privilege => "privilege",
            Self::Persistence => "persistence",
            Self::Process => "process",
            Self::Network => "network",
            Self::FileIntegrity => "file_integrity",
            Self::Web => "web",
            Self::Docker => "docker",
            Self::Rootkit => "rootkit",
            Self::ConfigRisk => "config_risk",
            Self::System => "system",
        };
        f.write_str(text)
    }
}

/// Key-value evidence attached to a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub key: String,
    pub value: String,
}

impl Evidence {
    /// Create one evidence entry.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Unified detector output consumed by storage and notifier implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub host_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    pub category: Category,
    pub rule_id: String,
    pub timestamp: DateTime<Utc>,
    pub subject: String,
    pub evidence: Vec<Evidence>,
    pub impact: Vec<String>,
    pub recommendations: Vec<String>,
    pub dedup_key: String,
}

impl Finding {
    /// Build a complete finding and derive a stable deduplication key.
    pub fn new(
        host_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: Category,
        rule_id: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        let host_id = host_id.into();
        let rule_id = rule_id.into();
        let subject = subject.into();
        let dedup_key = stable_dedup_key(&host_id, &rule_id, &subject, &[]);
        Self {
            id: Uuid::new_v4().to_string(),
            host_id,
            title: title.into(),
            description: description.into(),
            severity,
            confidence: confidence_for_severity(&severity),
            category,
            rule_id,
            timestamp: Utc::now(),
            subject,
            evidence: Vec::new(),
            impact: Vec::new(),
            recommendations: Vec::new(),
            dedup_key,
        }
    }

    /// Attach evidence and refresh the deduplication key.
    pub fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        let evidence = normalize_evidence_items(evidence);
        self.dedup_key = stable_dedup_key(&self.host_id, &self.rule_id, &self.subject, &evidence);
        self.evidence = evidence;
        self
    }

    /// Attach full evidence while deriving the deduplication key from stable evidence fields only.
    pub fn with_evidence_deduped_by(
        mut self,
        evidence: Vec<Evidence>,
        dedup_evidence_keys: &[&str],
    ) -> Self {
        let evidence = normalize_evidence_items(evidence);
        let dedup_keys = dedup_evidence_keys
            .iter()
            .map(|key| canonical_key(key).into_owned())
            .collect::<Vec<_>>();
        let dedup_evidence = evidence
            .iter()
            .filter(|item| dedup_keys.iter().any(|key| key == &item.key))
            .cloned()
            .collect::<Vec<_>>();
        self.dedup_key =
            stable_dedup_key(&self.host_id, &self.rule_id, &self.subject, &dedup_evidence);
        self.evidence = evidence;
        self
    }

    /// Normalize evidence already attached through direct mutation.
    ///
    /// Deduplication identity is chosen by the detector when the finding is
    /// created. Later pipeline stages append display-only evidence such as risk
    /// scores, fingerprint context, active-response status, or volatile ports,
    /// so normalization must not widen the deduplication key implicitly.
    pub fn normalize_evidence(&mut self) {
        self.evidence = normalize_evidence_items(std::mem::take(&mut self.evidence));
    }

    /// Attach likely impact statements.
    pub fn with_impact(mut self, impact: Vec<String>) -> Self {
        self.impact = impact;
        self
    }

    /// Attach actionable recommendations.
    pub fn with_recommendations(mut self, recommendations: Vec<String>) -> Self {
        self.recommendations = recommendations;
        self
    }

    /// Override the detector confidence when evidence strength is known.
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }
}

fn confidence_for_severity(severity: &Severity) -> Confidence {
    match severity {
        Severity::Critical | Severity::High => Confidence::High,
        Severity::Medium => Confidence::Medium,
        Severity::Low | Severity::Info => Confidence::Low,
    }
}

/// Derive a deterministic deduplication key from rule, subject, and evidence.
pub fn stable_dedup_key(
    host_id: &str,
    rule_id: &str,
    subject: &str,
    evidence: &[Evidence],
) -> String {
    let mut ordered = BTreeMap::new();
    for item in evidence {
        let key = canonical_key(&item.key).into_owned();
        ordered.insert(key, item.value.as_str());
    }

    let mut hasher = Hasher::new();
    hasher.update(host_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(subject.as_bytes());
    hasher.update(b"\n");
    for (key, value) in ordered {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::{stable_dedup_key, Category, Evidence, Finding};
    use crate::Severity;

    #[test]
    fn dedup_key_is_stable_when_evidence_order_changes() {
        let left = stable_dedup_key(
            "host",
            "SSH-001",
            "root@1.2.3.4",
            &[
                Evidence::new("ip", "1.2.3.4"),
                Evidence::new("user", "root"),
            ],
        );
        let right = stable_dedup_key(
            "host",
            "SSH-001",
            "root@1.2.3.4",
            &[
                Evidence::new("user", "root"),
                Evidence::new("ip", "1.2.3.4"),
            ],
        );
        assert_eq!(left, right);
    }

    #[test]
    fn finding_contains_required_fields() {
        let finding = Finding::new(
            "host",
            "Root SSH login detected",
            "Root logged in through SSH.",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root@1.2.3.4",
        )
        .with_evidence(vec![Evidence::new("user", "root")])
        .with_recommendations(vec!["Review the login source.".to_string()]);

        assert_eq!(finding.rule_id, "SSH-001");
        assert_eq!(finding.severity, Severity::High);
        assert!(!finding.id.is_empty());
        assert!(!finding.dedup_key.is_empty());
        assert_eq!(finding.evidence.len(), 1);
    }

    #[test]
    fn finding_can_dedup_by_stable_evidence_subset() {
        let left = Finding::new(
            "host",
            "SSH brute force pattern detected",
            "A source generated many failures.",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            "203.0.113.10",
        )
        .with_evidence_deduped_by(
            vec![
                Evidence::new("source_ip", "203.0.113.10"),
                Evidence::new("failure_count", "10"),
            ],
            &["source_ip"],
        );
        let right = Finding::new(
            "host",
            "SSH brute force pattern detected",
            "A source generated many failures.",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            "203.0.113.10",
        )
        .with_evidence_deduped_by(
            vec![
                Evidence::new("source_ip", "203.0.113.10"),
                Evidence::new("failure_count", "65"),
            ],
            &["source_ip"],
        );

        assert_eq!(left.dedup_key, right.dedup_key);
        assert_ne!(left.evidence, right.evidence);
    }

    #[test]
    fn normalize_evidence_preserves_detector_dedup_identity() {
        let mut finding = Finding::new(
            "host",
            "Root SSH login detected",
            "Root logged in through SSH.",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root@203.0.113.10",
        )
        .with_evidence_deduped_by(
            vec![
                Evidence::new("user", "root"),
                Evidence::new("source_ip", "203.0.113.10"),
                Evidence::new("method", "publickey"),
                Evidence::new("port", "42100"),
            ],
            &["user", "source_ip", "method"],
        );
        let before = finding.dedup_key.clone();

        finding.evidence.push(Evidence::new("port", "58812"));
        finding
            .evidence
            .push(Evidence::new("unified_risk_score", "80"));
        finding.normalize_evidence();

        assert_eq!(finding.dedup_key, before);
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "unified_risk_score"));
    }
}
