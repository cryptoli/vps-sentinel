use crate::rules::model::RuleAttackStage;
use crate::storage::SqliteStore;
use chrono::{DateTime, Duration, Utc};
use sentinel_core::{Category, Evidence, Finding, SentinelConfig, SentinelResult, Severity};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

const STATE_RULE_ID: &str = "incident_index";
const MAX_STORED_INCIDENTS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub host_id: String,
    pub title: String,
    pub severity: Severity,
    pub score: u16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub correlation_key: String,
    pub subjects: Vec<String>,
    pub categories: Vec<String>,
    pub rules: Vec<String>,
    pub finding_ids: Vec<String>,
    pub summary: String,
    pub timeline: Vec<IncidentTimelineItem>,
    #[serde(default)]
    pub attack_chain: Vec<IncidentAttackStage>,
    #[serde(default)]
    pub correlation: IncidentCorrelation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineItem {
    pub timestamp: DateTime<Utc>,
    pub finding_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentAttackStage {
    pub stage: String,
    pub label: String,
    pub severity: Severity,
    pub finding_count: usize,
    pub rule_ids: Vec<String>,
    pub subjects: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentCorrelation {
    pub key: String,
    pub method: String,
    pub window_seconds: u64,
    pub finding_count: usize,
    pub subject_count: usize,
    pub category_count: usize,
    pub rule_count: usize,
    pub stage_count: usize,
}

impl Default for IncidentCorrelation {
    fn default() -> Self {
        Self {
            key: String::new(),
            method: "unknown".to_string(),
            window_seconds: 0,
            finding_count: 0,
            subject_count: 0,
            category_count: 0,
            rule_count: 0,
            stage_count: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IncidentIndex {
    incidents: Vec<Incident>,
}

pub fn correlate_findings(findings: &[Finding], config: &SentinelConfig) -> Vec<Incident> {
    if !config.incidents.enabled || findings.is_empty() {
        return Vec::new();
    }
    let mut groups = BTreeMap::<String, Vec<&Finding>>::new();
    let window = config.incidents.correlation_window_seconds.max(1);
    for finding in findings {
        let bucket = finding.timestamp.timestamp().max(0) as u64 / window;
        let key = correlation_key(finding);
        groups
            .entry(format!("{bucket}:{key}"))
            .or_default()
            .push(finding);
    }

    groups
        .into_values()
        .filter(|items| !items.is_empty())
        .map(|mut items| {
            items.sort_by_key(|finding| finding.timestamp);
            build_incident(&items, config)
        })
        .collect()
}

pub fn save_incidents(store: &SqliteStore, incidents: &[Incident]) -> SentinelResult<()> {
    if incidents.is_empty() {
        return Ok(());
    }
    let mut index = store
        .load_rule_state::<IncidentIndex>(STATE_RULE_ID)?
        .unwrap_or_default();
    let mut by_id = index
        .incidents
        .into_iter()
        .map(|incident| (incident.id.clone(), incident))
        .collect::<BTreeMap<_, _>>();
    for incident in incidents {
        by_id.insert(incident.id.clone(), incident.clone());
    }
    let mut incidents = by_id.into_values().collect::<Vec<_>>();
    incidents.sort_by_key(|incident| Reverse(incident.last_seen));
    incidents.truncate(MAX_STORED_INCIDENTS);
    index = IncidentIndex { incidents };
    store.save_rule_state(STATE_RULE_ID, &index)
}

pub fn list_incidents(store: &SqliteStore, limit: usize) -> SentinelResult<Vec<Incident>> {
    let mut incidents = store
        .load_rule_state::<IncidentIndex>(STATE_RULE_ID)?
        .unwrap_or_default()
        .incidents;
    incidents.sort_by_key(|incident| Reverse(incident.last_seen));
    incidents.truncate(limit);
    Ok(incidents)
}

pub fn get_incident(store: &SqliteStore, id: &str) -> SentinelResult<Option<Incident>> {
    Ok(store
        .load_rule_state::<IncidentIndex>(STATE_RULE_ID)?
        .unwrap_or_default()
        .incidents
        .into_iter()
        .find(|incident| incident.id == id))
}

pub fn prune_incidents(store: &SqliteStore, retention_days: u32) -> SentinelResult<usize> {
    let Some(mut index) = store.load_rule_state::<IncidentIndex>(STATE_RULE_ID)? else {
        return Ok(0);
    };
    let before = index.incidents.len();
    let cutoff = Utc::now() - Duration::days(retention_days.max(1) as i64);
    index
        .incidents
        .retain(|incident| incident.last_seen >= cutoff);
    let deleted = before.saturating_sub(index.incidents.len());
    if deleted > 0 {
        store.save_rule_state(STATE_RULE_ID, &index)?;
    }
    Ok(deleted)
}

fn build_incident(findings: &[&Finding], config: &SentinelConfig) -> Incident {
    let first = findings.first().expect("incident group is non-empty");
    let last = findings.last().expect("incident group is non-empty");
    let mut subjects = BTreeSet::new();
    let mut categories = BTreeSet::new();
    let mut rules = BTreeSet::new();
    let mut finding_ids = Vec::new();
    let mut timeline = Vec::new();
    let mut severity = Severity::Info;
    let mut score = 0u16;

    for finding in findings
        .iter()
        .take(config.incidents.max_findings_per_incident)
    {
        subjects.insert(finding.subject.clone());
        categories.insert(finding.category.to_string());
        rules.insert(finding.rule_id.clone());
        finding_ids.push(finding.id.clone());
        severity = severity.max(finding.severity);
        score = score.max(unified_score_from_evidence(finding));
        timeline.push(IncidentTimelineItem {
            timestamp: finding.timestamp,
            finding_id: finding.id.clone(),
            rule_id: finding.rule_id.clone(),
            severity: finding.severity,
            title: finding.title.clone(),
            subject: finding.subject.clone(),
        });
    }

    let correlation_key = correlation_key(first);
    let id = incident_id(&first.host_id, &correlation_key, first.timestamp);
    let categories = categories.into_iter().collect::<Vec<_>>();
    let subjects = subjects.into_iter().collect::<Vec<_>>();
    let rules = rules.into_iter().collect::<Vec<_>>();
    let title = incident_title(severity, &categories, &subjects);
    let attack_chain = build_attack_chain(&timeline);
    let correlation = IncidentCorrelation {
        key: correlation_key.clone(),
        method: correlation_method(&correlation_key),
        window_seconds: config.incidents.correlation_window_seconds,
        finding_count: finding_ids.len(),
        subject_count: subjects.len(),
        category_count: categories.len(),
        rule_count: rules.len(),
        stage_count: attack_chain.len(),
    };
    Incident {
        id,
        host_id: first.host_id.clone(),
        title,
        severity,
        score,
        first_seen: first.timestamp,
        last_seen: last.timestamp,
        correlation_key,
        subjects,
        categories,
        rules,
        finding_ids,
        summary: format!(
            "{} related finding(s) correlated across {} stage(s) within {} seconds on {}.",
            findings.len(),
            attack_chain.len().max(1),
            config.incidents.correlation_window_seconds,
            config.display_name()
        ),
        timeline,
        attack_chain,
        correlation,
    }
}

fn correlation_key(finding: &Finding) -> String {
    for key in ["source_ip", "ip", "remote_addr"] {
        if let Some(value) =
            evidence_value(&finding.evidence, key).filter(|value| !value.is_empty())
        {
            return format!("ip:{value}");
        }
    }
    for key in ["path", "file_path", "exe_path", "process_name"] {
        if let Some(value) =
            evidence_value(&finding.evidence, key).filter(|value| !value.is_empty())
        {
            return format!("{key}:{value}");
        }
    }
    match finding.category {
        Category::Ssh | Category::Web | Category::Network => {
            format!("{}:{}", finding.category, finding.subject)
        }
        _ => format!("{}:{}", finding.rule_id, finding.subject),
    }
}

fn evidence_value(evidence: &[Evidence], key: &str) -> Option<String> {
    evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.trim().to_string())
}

fn unified_score_from_evidence(finding: &Finding) -> u16 {
    evidence_value(&finding.evidence, "unified_risk_score")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(match finding.severity {
            Severity::Info => 10,
            Severity::Low => 30,
            Severity::Medium => 55,
            Severity::High => 75,
            Severity::Critical => 90,
        })
}

fn incident_title(severity: Severity, categories: &[String], subjects: &[String]) -> String {
    let category = categories
        .first()
        .cloned()
        .unwrap_or_else(|| "system".to_string());
    let subject = subjects
        .first()
        .cloned()
        .unwrap_or_else(|| "host".to_string());
    format!("{severity} correlated {category} activity on {subject}")
}

fn build_attack_chain(timeline: &[IncidentTimelineItem]) -> Vec<IncidentAttackStage> {
    let mut stages = BTreeMap::<String, Vec<&IncidentTimelineItem>>::new();
    for item in timeline {
        let stage = RuleAttackStage::from_signal(
            &item.rule_id,
            &format!("{} {}", item.subject, item.title),
        );
        stages
            .entry(stage.key().to_string())
            .or_default()
            .push(item);
    }
    let mut result = Vec::new();
    for (stage, mut items) in stages {
        items.sort_by_key(|item| item.timestamp);
        let first = items.first().expect("stage group is non-empty");
        let last = items.last().expect("stage group is non-empty");
        let severity = items
            .iter()
            .map(|item| item.severity)
            .max()
            .unwrap_or(Severity::Info);
        let rule_ids = items
            .iter()
            .map(|item| item.rule_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let subjects = items
            .iter()
            .map(|item| item.subject.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        result.push(IncidentAttackStage {
            label: RuleAttackStage::from_key(&stage).label().to_string(),
            stage,
            severity,
            finding_count: items.len(),
            rule_ids,
            subjects,
            first_seen: first.timestamp,
            last_seen: last.timestamp,
        });
    }
    result.sort_by_key(|stage| RuleAttackStage::from_key(&stage.stage).rank());
    result
}

fn correlation_method(key: &str) -> String {
    key.split_once(':')
        .map(|(method, _)| method.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn incident_id(host_id: &str, correlation_key: &str, timestamp: DateTime<Utc>) -> String {
    let bucket = timestamp.timestamp().div_euclid(900);
    let hash = blake3::hash(format!("{host_id}\n{correlation_key}\n{bucket}").as_bytes());
    hash.to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::correlate_findings;
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

    #[test]
    fn correlates_findings_by_source_ip() {
        let config = SentinelConfig::default();
        let findings = vec![
            Finding::new(
                "host",
                "ssh",
                "ssh",
                Severity::High,
                Category::Ssh,
                "SSH-003",
                "1.1.1.1",
            )
            .with_evidence(vec![Evidence::new("source_ip", "1.1.1.1")]),
            Finding::new(
                "host",
                "web",
                "web",
                Severity::Low,
                Category::Web,
                "WEB-001",
                "1.1.1.1",
            )
            .with_evidence(vec![Evidence::new("ip", "1.1.1.1")]),
        ];

        let incidents = correlate_findings(&findings, &config);

        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].finding_ids.len(), 2);
        assert_eq!(incidents[0].severity, Severity::High);
    }
}
