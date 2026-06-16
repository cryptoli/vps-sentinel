use crate::severity::Severity;
use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use uuid::Uuid;

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
        let dedup_evidence = evidence
            .iter()
            .filter(|item| dedup_evidence_keys.contains(&item.key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        self.dedup_key =
            stable_dedup_key(&self.host_id, &self.rule_id, &self.subject, &dedup_evidence);
        self.evidence = evidence;
        self
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
        ordered.insert(item.key.as_str(), item.value.as_str());
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
}
