use crate::path_match::PathMatcher;
use chrono::{DateTime, Utc};
use sentinel_core::{evidence_value, Finding, SentinelConfig, SuppressRuleEntryConfig};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressRulesReport {
    pub suppressed_count: usize,
}

pub fn apply_suppress_rules(
    findings: Vec<Finding>,
    config: &SentinelConfig,
) -> (Vec<Finding>, SuppressRulesReport) {
    apply_suppress_rules_at(findings, config, Utc::now())
}

fn apply_suppress_rules_at(
    findings: Vec<Finding>,
    config: &SentinelConfig,
    now: DateTime<Utc>,
) -> (Vec<Finding>, SuppressRulesReport) {
    if !config.suppress_rules.enabled {
        return (
            findings,
            SuppressRulesReport {
                suppressed_count: 0,
            },
        );
    }
    let policy = SuppressRulesPolicy::from_config(config, now);
    if policy.is_empty() {
        return (
            findings,
            SuppressRulesReport {
                suppressed_count: 0,
            },
        );
    }
    let before = findings.len();
    let retained = findings
        .into_iter()
        .filter(|finding| !policy.matches(finding))
        .collect::<Vec<_>>();
    let suppressed_count = before.saturating_sub(retained.len());
    (retained, SuppressRulesReport { suppressed_count })
}

struct SuppressRulesPolicy {
    rule_ids: BTreeSet<String>,
    entries: Vec<CompiledSuppressRuleEntry>,
}

impl SuppressRulesPolicy {
    fn from_config(config: &SentinelConfig, now: DateTime<Utc>) -> Self {
        let rule_ids = config
            .suppress_rules
            .rule_ids
            .iter()
            .map(|rule| rule.trim())
            .filter(|rule| !rule.is_empty())
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let entries = config
            .suppress_rules
            .entries
            .iter()
            .filter(|entry| !entry_expired(entry, now))
            .map(CompiledSuppressRuleEntry::from_config)
            .collect::<Vec<_>>();
        Self { rule_ids, entries }
    }

    fn is_empty(&self) -> bool {
        self.rule_ids.is_empty() && self.entries.is_empty()
    }

    fn matches(&self, finding: &Finding) -> bool {
        self.rule_ids.contains(finding.rule_id.as_str())
            || self.entries.iter().any(|entry| entry.matches(finding))
    }
}

struct CompiledSuppressRuleEntry {
    rule_ids: BTreeSet<String>,
    subjects: BTreeSet<String>,
    path_unrestricted: bool,
    path_patterns: PathMatcher,
}

impl CompiledSuppressRuleEntry {
    fn from_config(entry: &SuppressRuleEntryConfig) -> Self {
        Self {
            rule_ids: entry
                .rule_ids
                .iter()
                .map(|rule| rule.trim())
                .filter(|rule| !rule.is_empty())
                .map(str::to_string)
                .collect(),
            subjects: entry
                .subjects
                .iter()
                .map(|subject| subject.trim())
                .filter(|subject| !subject.is_empty())
                .map(str::to_string)
                .collect(),
            path_unrestricted: entry.path_patterns.is_empty(),
            path_patterns: PathMatcher::from_strings(&entry.path_patterns),
        }
    }

    fn matches(&self, finding: &Finding) -> bool {
        self.rule_ids.contains(finding.rule_id.as_str())
            && self.subject_matches(finding)
            && self.path_matches(finding)
    }

    fn subject_matches(&self, finding: &Finding) -> bool {
        self.subjects.is_empty() || self.subjects.contains(finding.subject.as_str())
    }

    fn path_matches(&self, finding: &Finding) -> bool {
        if self.path_unrestricted {
            return true;
        }
        if self.path_patterns.matches(&finding.subject) {
            return true;
        }
        if self
            .path_patterns
            .matches(evidence_value(&finding.evidence, "path").unwrap_or(""))
        {
            return true;
        }
        self.path_patterns
            .matches(evidence_value(&finding.evidence, "file_path").unwrap_or(""))
    }
}

fn entry_expired(entry: &SuppressRuleEntryConfig, now: DateTime<Utc>) -> bool {
    let value = entry.expires_at.trim();
    if value.is_empty() {
        return false;
    }
    DateTime::parse_from_rfc3339(value)
        .map(|expires_at| expires_at.with_timezone(&Utc) <= now)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::apply_suppress_rules_at;
    use chrono::{TimeZone, Utc};
    use sentinel_core::{
        Category, Evidence, Finding, SentinelConfig, Severity, SuppressRuleEntryConfig,
    };

    #[test]
    fn top_level_rule_ids_suppress_matching_findings() {
        let mut config = SentinelConfig::default();
        config
            .suppress_rules
            .rule_ids
            .push("CONFIG-004".to_string());
        let finding = finding("CONFIG-004", "/etc/ssh/sshd_config");

        let (retained, report) = apply_suppress_rules_at(vec![finding], &config, Utc::now());

        assert!(retained.is_empty());
        assert_eq!(report.suppressed_count, 1);
    }

    #[test]
    fn scoped_entries_match_rule_subject_and_path_pattern() {
        let mut config = SentinelConfig::default();
        config.suppress_rules.entries.push(SuppressRuleEntryConfig {
            id: "accepted-root-login".to_string(),
            rule_ids: vec!["CONFIG-004".to_string()],
            subjects: vec!["/etc/ssh/sshd_config".to_string()],
            path_patterns: vec!["/etc/ssh/*".to_string()],
            reason: "documented exception".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        });

        let (retained, report) = apply_suppress_rules_at(
            vec![
                finding("CONFIG-004", "/etc/ssh/sshd_config"),
                finding("CONFIG-004", "/tmp/sshd_config"),
            ],
            &config,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        );

        assert_eq!(retained.len(), 1);
        assert_eq!(report.suppressed_count, 1);
    }

    #[test]
    fn expired_entries_do_not_suppress_findings() {
        let mut config = SentinelConfig::default();
        config.suppress_rules.entries.push(SuppressRuleEntryConfig {
            id: "expired".to_string(),
            rule_ids: vec!["CONFIG-004".to_string()],
            reason: "old exception".to_string(),
            expires_at: "2025-01-01T00:00:00Z".to_string(),
            ..SuppressRuleEntryConfig::default()
        });

        let (retained, report) = apply_suppress_rules_at(
            vec![finding("CONFIG-004", "/etc/ssh/sshd_config")],
            &config,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        );

        assert_eq!(retained.len(), 1);
        assert_eq!(report.suppressed_count, 0);
    }

    fn finding(rule_id: &str, subject: &str) -> Finding {
        Finding::new(
            "host",
            "finding",
            "description",
            Severity::Medium,
            Category::ConfigRisk,
            rule_id,
            subject,
        )
        .with_evidence(vec![Evidence::new("path", subject)])
    }
}
