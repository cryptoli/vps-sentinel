use anyhow::Result;
use sentinel_agent::{run_scan, ScanOptions};
use sentinel_core::SentinelConfig;
use std::path::PathBuf;

pub async fn run_scan_command(config: SentinelConfig, notify: bool, json: bool) -> Result<()> {
    let report = run_scan(
        config,
        ScanOptions {
            persist: true,
            notify,
            active_response: notify,
            scan_root: PathBuf::from("/"),
        },
    )
    .await?;
    print_report(&report, json)?;
    Ok(())
}

pub async fn run_check(config: SentinelConfig, json: bool) -> Result<()> {
    let report = run_scan(
        config,
        ScanOptions {
            persist: false,
            notify: false,
            active_response: false,
            scan_root: PathBuf::from("/"),
        },
    )
    .await?;
    print_report(&report, json)?;
    Ok(())
}

fn print_report(report: &sentinel_agent::ScanReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "scan completed: raw_events={}, diff_events={}, findings={}, incidents={}, suppressed_duplicates={}, maintenance_suppressed={}, notifications={}/{} ok",
        report.raw_event_count,
        report.diff_event_count,
        report.finding_count,
        report.incident_count,
        report.suppressed_duplicate_count,
        report.maintenance_suppressed_count,
        report.notification_success_count,
        report.notification_attempt_count
    );
    if report.notification_failure_count > 0 {
        println!(
            "notification failures: {}",
            report.notification_failure_count
        );
    }
    if report.attack_fingerprint_observation_count > 0 {
        println!(
            "attack fingerprints: observations={}, action_hints={}",
            report.attack_fingerprint_observation_count,
            report.attack_fingerprint_action_hint_count
        );
    }
    if report.resource_budget_dropped_findings > 0
        || report.resource_budget_truncated_evidence_items > 0
        || report.resource_budget_truncated_evidence_values > 0
    {
        println!(
            "resource budget: dropped_findings={}, truncated_evidence_items={}, truncated_evidence_values={}",
            report.resource_budget_dropped_findings,
            report.resource_budget_truncated_evidence_items,
            report.resource_budget_truncated_evidence_values
        );
    }
    if let (Some(before), Some(after)) = (report.memory_rss_before_kb, report.memory_rss_after_kb) {
        println!(
            "memory rss: before={} KiB, after={} KiB, delta={} KiB",
            before,
            after,
            report.memory_rss_delta_kb.unwrap_or(0)
        );
    }
    if !report.event_count_by_source.is_empty() {
        let source_summary = report
            .event_count_by_source
            .iter()
            .map(|(source, count)| format!("{source}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("events by source: {source_summary}");
    }
    if report.quiet_suppressed_count > 0 {
        println!(
            "quiet-hours suppressed findings: {}",
            report.quiet_suppressed_count
        );
    }
    if report.notification_rate_limited_count > 0 {
        println!(
            "rate-limited notifications: {}",
            report.notification_rate_limited_count
        );
    }
    if !report.collector_errors.is_empty() {
        println!("collector warnings:");
        for error in &report.collector_errors {
            println!("- {error}");
        }
    }
    for finding in &report.findings {
        println!(
            "[{} confidence={}] {} ({}) subject={} id={}",
            finding.severity,
            finding.confidence,
            finding.title,
            finding.rule_id,
            finding.subject,
            finding.id
        );
    }
    Ok(())
}
