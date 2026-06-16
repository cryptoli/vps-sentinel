use crate::scanner::{run_scan, ScanOptions};
use sentinel_core::{SentinelConfig, SentinelResult};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info};

/// Run the long-lived agent loop until Ctrl-C is received.
pub async fn run_daemon(config: SentinelConfig) -> SentinelResult<()> {
    let interval = Duration::from_secs(config.agent.scan_interval_seconds);
    info!(seconds = interval.as_secs(), "vps-sentinel daemon started");

    loop {
        tokio::select! {
            scan_result = run_scan(config.clone(), ScanOptions::default()) => {
                match scan_result {
                    Ok(report) => info!(
                        raw_events = report.raw_event_count,
                        diff_events = report.diff_event_count,
                        findings = report.finding_count,
                        "scan completed"
                    ),
                    Err(err) => error!(error = %err, "scan failed"),
                }
                sleep(interval).await;
            }
            signal = tokio::signal::ctrl_c() => {
                match signal {
                    Ok(()) => info!("shutdown signal received"),
                    Err(err) => error!(error = %err, "failed to listen for shutdown signal"),
                }
                break;
            }
        }
    }
    Ok(())
}
