use anyhow::Result;
use sentinel_agent::{run_scan, ScanOptions};
use sentinel_core::SentinelConfig;
use std::path::PathBuf;

pub async fn run_scan_command(config: SentinelConfig, notify: bool) -> Result<()> {
    let report = run_scan(
        config,
        ScanOptions {
            persist: true,
            notify,
            scan_root: PathBuf::from("/"),
        },
    )
    .await?;
    print_report(&report);
    Ok(())
}

pub async fn run_check(config: SentinelConfig) -> Result<()> {
    let report = run_scan(
        config,
        ScanOptions {
            persist: false,
            notify: false,
            scan_root: PathBuf::from("/"),
        },
    )
    .await?;
    print_report(&report);
    Ok(())
}

fn print_report(report: &sentinel_agent::ScanReport) {
    println!(
        "scan completed: raw_events={}, diff_events={}, findings={}, suppressed_duplicates={}, notifications={}/{} ok",
        report.raw_event_count,
        report.diff_event_count,
        report.finding_count,
        report.suppressed_duplicate_count,
        report.notification_success_count,
        report.notification_attempt_count
    );
    if report.notification_failure_count > 0 {
        println!(
            "notification failures: {}",
            report.notification_failure_count
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
            "[{}] {} ({}) subject={} id={}",
            finding.severity, finding.title, finding.rule_id, finding.subject, finding.id
        );
    }
}
