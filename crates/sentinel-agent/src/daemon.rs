use crate::scanner::{run_scan, ScanOptions};
use sentinel_core::{SentinelConfig, SentinelResult};
use std::future;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

#[cfg(unix)]
type ReloadSignal = tokio::signal::unix::Signal;

#[cfg(not(unix))]
struct ReloadSignal;

/// Run the long-lived agent loop until Ctrl-C is received.
pub async fn run_daemon(
    mut config: SentinelConfig,
    reload_path: Option<PathBuf>,
) -> SentinelResult<()> {
    let mut reload_signal = reload_signal();
    let interval = Duration::from_secs(config.agent.scan_interval_seconds);
    info!(seconds = interval.as_secs(), "vps-sentinel daemon started");

    loop {
        match run_scan(config.clone(), ScanOptions::default()).await {
            Ok(report) => info!(
                raw_events = report.raw_event_count,
                diff_events = report.diff_event_count,
                findings = report.finding_count,
                suppressed_duplicates = report.suppressed_duplicate_count,
                quiet_suppressed = report.quiet_suppressed_count,
                notification_rate_limited = report.notification_rate_limited_count,
                notification_attempts = report.notification_attempt_count,
                notification_successes = report.notification_success_count,
                notification_failures = report.notification_failure_count,
                collector_errors = report.collector_errors.len(),
                "scan completed"
            ),
            Err(err) => error!(error = %err, "scan failed"),
        }

        let interval = Duration::from_secs(config.agent.scan_interval_seconds);
        tokio::select! {
            _ = sleep(interval) => {}
            signal = tokio::signal::ctrl_c() => {
                match signal {
                    Ok(()) => info!("shutdown signal received"),
                    Err(err) => error!(error = %err, "failed to listen for shutdown signal"),
                }
                break;
            }
            _ = recv_reload_signal(&mut reload_signal), if reload_path.is_some() => {
                if let Some(path) = &reload_path {
                    reload_config(&mut config, path);
                }
            }
        }
    }
    Ok(())
}

fn reload_config(config: &mut SentinelConfig, path: &Path) {
    match SentinelConfig::load(path) {
        Ok(updated) => {
            let interval = updated.agent.scan_interval_seconds;
            *config = updated;
            info!(
                config_path = %path.display(),
                scan_interval_seconds = interval,
                "configuration reloaded"
            );
        }
        Err(err) => {
            warn!(
                config_path = %path.display(),
                error = %err,
                "configuration reload failed; keeping previous configuration"
            );
        }
    }
}

fn reload_signal() -> Option<ReloadSignal> {
    #[cfg(unix)]
    {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

async fn recv_reload_signal(_signal: &mut Option<ReloadSignal>) {
    #[cfg(unix)]
    {
        if let Some(signal) = _signal {
            signal.recv().await;
            return;
        }
    }
    future::pending::<()>().await;
}
