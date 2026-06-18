use crate::rules::system::DAILY_REPORT_RULE_ID;
use crate::storage::{ScanRunSummary, SqliteStore, StorageStats};
use chrono::{DateTime, Local, TimeZone, Utc};
use sentinel_core::{Category, Evidence, Finding, SentinelConfig, SentinelResult, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const TOP_RULE_LIMIT: usize = 5;
const IMPORTANT_EVENT_LIMIT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportPeriod {
    Today,
    Last24h,
}

impl ReportPeriod {
    pub fn window(self, now: DateTime<Utc>) -> ReportWindow {
        match self {
            Self::Today => ReportWindow {
                label: "today".to_string(),
                since: local_day_start(now),
                until: now,
            },
            Self::Last24h => ReportWindow {
                label: "last24h".to_string(),
                since: now - chrono::Duration::hours(24),
                until: now,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportWindow {
    pub label: String,
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReport {
    pub window: ReportWindow,
    pub finding_count: usize,
    pub severity_counts: BTreeMap<String, usize>,
    pub category_counts: BTreeMap<String, usize>,
    pub top_rules: Vec<ReportCount>,
    pub important_events: Vec<ReportEvent>,
    pub active_response: ActiveResponseReportSummary,
    pub scan_runs: ScanRunSummaryView,
    pub notification_attempts: usize,
    pub storage: ReportStorageSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportCount {
    pub key: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEvent {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub rule_id: String,
    pub title: String,
    pub subject: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveResponseReportSummary {
    pub temporary_blocks: usize,
    pub permanent_blocks: usize,
    pub failed_blocks: usize,
    pub source_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRunSummaryView {
    pub total: usize,
    pub failed: usize,
    pub last_finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportStorageSummary {
    pub database_bytes: u64,
    pub findings: usize,
    pub notification_logs: usize,
    pub scan_runs: usize,
}

pub fn build_security_report(
    config: &SentinelConfig,
    store: &SqliteStore,
    period: ReportPeriod,
) -> SentinelResult<SecurityReport> {
    let window = period.window(Utc::now());
    let findings = store.list_findings_between(window.since, window.until)?;
    let scan_runs = store.scan_run_summary_between(window.since, window.until)?;
    let notification_attempts = store.notification_attempt_count_since(window.since)?;
    let storage = store.stats()?;
    Ok(build_security_report_from_parts(
        config,
        window,
        findings,
        scan_runs,
        notification_attempts,
        storage,
    ))
}

pub fn build_report_finding(
    config: &SentinelConfig,
    store: &SqliteStore,
    period: ReportPeriod,
) -> SentinelResult<Finding> {
    let report = build_security_report(config, store, period)?;
    Ok(report_to_finding(config, &report))
}

fn build_security_report_from_parts(
    _config: &SentinelConfig,
    window: ReportWindow,
    findings: Vec<Finding>,
    scan_runs: ScanRunSummary,
    notification_attempts: usize,
    storage: StorageStats,
) -> SecurityReport {
    let severity_counts = count_by(&findings, |finding| finding.severity.to_string());
    let category_counts = count_by(&findings, |finding| finding.category.to_string());
    let top_rules = top_counts(count_by(&findings, |finding| finding.rule_id.clone()));
    let active_response = active_response_summary(&findings);
    let important_events = important_events(&findings);
    SecurityReport {
        window,
        finding_count: findings.len(),
        severity_counts,
        category_counts,
        top_rules,
        important_events,
        active_response,
        scan_runs: ScanRunSummaryView {
            total: scan_runs.total,
            failed: scan_runs.failed,
            last_finished_at: scan_runs.last_finished_at,
        },
        notification_attempts,
        storage: ReportStorageSummary {
            database_bytes: storage.database_bytes,
            findings: storage.findings,
            notification_logs: storage.notification_logs,
            scan_runs: storage.scan_runs,
        },
    }
}

fn report_to_finding(config: &SentinelConfig, report: &SecurityReport) -> Finding {
    let high_or_critical =
        severity_count(report, Severity::High) + severity_count(report, Severity::Critical);
    let severity = if high_or_critical > 0 {
        Severity::High
    } else {
        Severity::Info
    };
    Finding::new(
        config.host_id(),
        "VPS Sentinel daily report",
        "Daily security summary generated from local scan history, findings, active-response results, and storage counters.",
        severity,
        Category::System,
        DAILY_REPORT_RULE_ID,
        report.window.label.clone(),
    )
    .with_evidence(report_evidence(report))
    .with_impact(report_impact(report))
    .with_recommendations(report_recommendations(report))
}

fn report_evidence(report: &SecurityReport) -> Vec<Evidence> {
    let mut evidence = vec![
        Evidence::new("report_period", &report.window.label),
        Evidence::new("report_start", report.window.since.to_rfc3339()),
        Evidence::new("report_end", report.window.until.to_rfc3339()),
        Evidence::new("report_scan_runs", report.scan_runs.total.to_string()),
        Evidence::new(
            "report_failed_scan_runs",
            report.scan_runs.failed.to_string(),
        ),
        Evidence::new("report_findings_total", report.finding_count.to_string()),
        Evidence::new(
            "report_severity_summary",
            format_counts(&report.severity_counts),
        ),
        Evidence::new(
            "report_category_summary",
            format_counts(&report.category_counts),
        ),
        Evidence::new("report_top_rules", format_report_counts(&report.top_rules)),
        Evidence::new(
            "report_active_response",
            format_active_response_summary(&report.active_response),
        ),
        Evidence::new(
            "report_notification_attempts",
            report.notification_attempts.to_string(),
        ),
        Evidence::new(
            "report_database_size",
            format_bytes(report.storage.database_bytes),
        ),
    ];
    if let Some(last_finished_at) = report.scan_runs.last_finished_at {
        evidence.push(Evidence::new(
            "report_last_scan_at",
            last_finished_at.to_rfc3339(),
        ));
    }
    if !report.important_events.is_empty() {
        evidence.push(Evidence::new(
            "report_important_events",
            format_important_events(&report.important_events),
        ));
    }
    evidence
}

fn report_impact(report: &SecurityReport) -> Vec<String> {
    let high_or_critical =
        severity_count(report, Severity::High) + severity_count(report, Severity::Critical);
    if high_or_critical == 0 {
        return vec![
            "No High or Critical findings were recorded in this report window.".to_string(),
        ];
    }
    vec![format!(
        "{high_or_critical} High/Critical finding(s) were recorded in this report window."
    )]
}

fn report_recommendations(report: &SecurityReport) -> Vec<String> {
    let mut recommendations = vec![
        "Review High and Critical events first with `vs findings list --limit 20`.".to_string(),
    ];
    if report.active_response.total_blocks() > 0 {
        recommendations.push(
            "Review firewall actions with `vs blocks list --no-verify` and unblock trusted IPs if needed."
                .to_string(),
        );
    }
    if report.scan_runs.failed > 0 {
        recommendations.push("Check service logs because one or more scans failed.".to_string());
    }
    recommendations.push(
        "Keep baselines current only after confirming reported drift is legitimate.".to_string(),
    );
    recommendations
}

fn count_by<F>(findings: &[Finding], mut key_fn: F) -> BTreeMap<String, usize>
where
    F: FnMut(&Finding) -> String,
{
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(key_fn(finding)).or_default() += 1;
    }
    counts
}

fn top_counts(counts: BTreeMap<String, usize>) -> Vec<ReportCount> {
    let mut items = counts
        .into_iter()
        .map(|(key, count)| ReportCount { key, count })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.key.cmp(&right.key))
    });
    items.truncate(TOP_RULE_LIMIT);
    items
}

fn important_events(findings: &[Finding]) -> Vec<ReportEvent> {
    let mut events = findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::Critical | Severity::High))
        .map(|finding| ReportEvent {
            timestamp: finding.timestamp,
            severity: finding.severity,
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            subject: finding.subject.clone(),
        })
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.timestamp.cmp(&left.timestamp))
    });
    events.truncate(IMPORTANT_EVENT_LIMIT);
    events
}

fn active_response_summary(findings: &[Finding]) -> ActiveResponseReportSummary {
    let mut summary = ActiveResponseReportSummary::default();
    let mut ips = BTreeSet::new();
    for finding in findings {
        let status = evidence_value(finding, "active_response_status");
        match status.as_deref() {
            Some("blocked") => summary.temporary_blocks += 1,
            Some("permanently_blocked") => summary.permanent_blocks += 1,
            Some("failed") => summary.failed_blocks += 1,
            Some("blocked_many") => {
                summary.temporary_blocks += evidence_value(finding, "active_response_block_count")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(1);
                summary.permanent_blocks +=
                    evidence_value(finding, "active_response_permanent_count")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
            }
            _ => {}
        }
        if let Some(ip) = evidence_value(finding, "active_response_ip") {
            ips.insert(ip);
        }
    }
    summary.source_ips = ips.into_iter().take(10).collect();
    summary
}

fn evidence_value(finding: &Finding, key: &str) -> Option<String> {
    finding
        .evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.clone())
}

fn severity_count(report: &SecurityReport, severity: Severity) -> usize {
    report
        .severity_counts
        .get(&severity.to_string())
        .copied()
        .unwrap_or_default()
}

fn format_counts(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_report_counts(counts: &[ReportCount]) -> String {
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|item| format!("{}={}", item.key, item.count))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_active_response_summary(summary: &ActiveResponseReportSummary) -> String {
    let mut parts = vec![
        format!("temporary_blocks={}", summary.temporary_blocks),
        format!("permanent_blocks={}", summary.permanent_blocks),
        format!("failed_blocks={}", summary.failed_blocks),
    ];
    if !summary.source_ips.is_empty() {
        parts.push(format!("source_ips={}", summary.source_ips.join("|")));
    }
    parts.join(", ")
}

fn format_important_events(events: &[ReportEvent]) -> String {
    events
        .iter()
        .map(|event| {
            format!(
                "{} {} {} subject={}",
                event.severity, event.rule_id, event.title, event.subject
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn format_bytes(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes < 1024 * 1024 {
        format!("{bytes} B")
    } else {
        format!("{:.2} MiB", bytes as f64 / MIB)
    }
}

fn local_day_start(now: DateTime<Utc>) -> DateTime<Utc> {
    let local_now = now.with_timezone(&Local);
    let Some(naive_start) = local_now.date_naive().and_hms_opt(0, 0, 0) else {
        return now - chrono::Duration::hours(24);
    };
    Local
        .from_local_datetime(&naive_start)
        .earliest()
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|| now - chrono::Duration::hours(24))
}

impl ActiveResponseReportSummary {
    fn total_blocks(&self) -> usize {
        self.temporary_blocks + self.permanent_blocks
    }
}

#[cfg(test)]
mod tests {
    use super::{build_security_report_from_parts, local_day_start, ReportPeriod, ReportWindow};
    use crate::storage::{ScanRunSummary, StorageStats};
    use chrono::{TimeZone, Utc};
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

    #[test]
    fn last24h_period_uses_rolling_window() {
        let now = Utc.with_ymd_and_hms(2026, 6, 18, 12, 0, 0).unwrap();
        let window = ReportPeriod::Last24h.window(now);
        assert_eq!(window.until, now);
        assert_eq!(window.since, now - chrono::Duration::hours(24));
    }

    #[test]
    fn today_period_starts_before_now() {
        let now = Utc.with_ymd_and_hms(2026, 6, 18, 12, 0, 0).unwrap();
        let since = local_day_start(now);
        assert!(since <= now);
        assert!(since >= now - chrono::Duration::hours(24));
    }

    #[test]
    fn report_counts_findings_and_active_response() {
        let window = ReportWindow {
            label: "today".to_string(),
            since: Utc.with_ymd_and_hms(2026, 6, 18, 0, 0, 0).unwrap(),
            until: Utc.with_ymd_and_hms(2026, 6, 18, 12, 0, 0).unwrap(),
        };
        let findings = vec![
            Finding::new(
                "host",
                "SSH brute force pattern detected",
                "desc",
                Severity::High,
                Category::Ssh,
                "SSH-003",
                "8.8.8.8",
            )
            .with_evidence(vec![
                Evidence::new("active_response_status", "permanently_blocked"),
                Evidence::new("active_response_ip", "8.8.8.8"),
            ]),
            Finding::new(
                "host",
                "Web probing",
                "desc",
                Severity::Medium,
                Category::Web,
                "WEB-001",
                "1.1.1.1",
            ),
        ];
        let report = build_security_report_from_parts(
            &SentinelConfig::default(),
            window,
            findings,
            ScanRunSummary {
                total: 2,
                failed: 1,
                last_finished_at: None,
            },
            3,
            StorageStats {
                database_bytes: 1024,
                raw_events: 0,
                findings: 2,
                notification_logs: 3,
                finding_dedup_states: 0,
                scan_runs: 2,
                baseline_snapshots: 1,
                rule_states: 0,
            },
        );

        assert_eq!(report.finding_count, 2);
        assert_eq!(report.active_response.permanent_blocks, 1);
        assert_eq!(report.scan_runs.failed, 1);
        assert_eq!(report.top_rules[0].key, "SSH-003");
    }
}
