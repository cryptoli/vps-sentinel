use crate::report::{build_report_finding, send_report_finding, ReportPeriod};
use crate::scanner::{run_scan, ScanOptions};
use crate::storage::SqliteStore;
use chrono::{DateTime, Local, Timelike, Utc};
use sentinel_core::{NotificationTimeZone, SentinelConfig, SentinelResult};
use serde::{Deserialize, Serialize};
use std::future;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};

const SCHEDULED_REPORT_STATE_RULE_ID: &str = "scheduled_report_state";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ScheduledReportState {
    last_sent_at: Option<DateTime<Utc>>,
}

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
                incidents = report.incident_count,
                suppressed_duplicates = report.suppressed_duplicate_count,
                quiet_suppressed = report.quiet_suppressed_count,
                maintenance_suppressed = report.maintenance_suppressed_count,
                notification_rate_limited = report.notification_rate_limited_count,
                notification_attempts = report.notification_attempt_count,
                notification_successes = report.notification_success_count,
                notification_failures = report.notification_failure_count,
                collector_errors = report.collector_errors.len(),
                "scan completed"
            ),
            Err(err) => error!(error = %err, "scan failed"),
        }
        if let Err(err) = maybe_send_scheduled_report(&config).await {
            warn!(error = %err, "scheduled report failed");
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

async fn maybe_send_scheduled_report(config: &SentinelConfig) -> SentinelResult<()> {
    if !config.reports.scheduled_enabled {
        return Ok(());
    }
    if !scheduled_hour_reached(config) {
        return Ok(());
    }
    let store = SqliteStore::open(config.storage.path.clone())?;
    let state = store
        .load_rule_state::<ScheduledReportState>(SCHEDULED_REPORT_STATE_RULE_ID)?
        .unwrap_or_default();
    if let Some(last_sent_at) = state.last_sent_at {
        let elapsed = Utc::now().signed_duration_since(last_sent_at);
        if elapsed >= chrono::Duration::zero()
            && elapsed
                < chrono::Duration::seconds(duration_seconds(config.reports.min_interval_seconds))
        {
            return Ok(());
        }
    }
    let period = report_period_from_config(config);
    let finding = build_report_finding(config, &store, period)?;
    let delivery = send_report_finding(config, &store, &finding).await?;
    for outcome in &delivery.outcomes {
        if outcome.status == "failed" {
            warn!(
                channel = outcome.channel,
                error = %outcome.error,
                "scheduled report notification failed"
            );
        }
    }
    if delivery.delivered > 0 {
        store.save_rule_state(
            SCHEDULED_REPORT_STATE_RULE_ID,
            &ScheduledReportState {
                last_sent_at: Some(Utc::now()),
            },
        )?;
        info!(channels = delivery.delivered, "scheduled report sent");
    }
    Ok(())
}

fn scheduled_hour_reached(config: &SentinelConfig) -> bool {
    match config.notifications.time_zone {
        NotificationTimeZone::Local => Local::now().hour() as u8 >= config.reports.scheduled_hour,
        NotificationTimeZone::Utc => Utc::now().hour() as u8 >= config.reports.scheduled_hour,
    }
}

fn report_period_from_config(config: &SentinelConfig) -> ReportPeriod {
    match config.reports.scheduled_period.as_str() {
        "last24h" => ReportPeriod::Last24h,
        _ => ReportPeriod::Today,
    }
}

fn duration_seconds(seconds: u64) -> i64 {
    if seconds > i64::MAX as u64 {
        i64::MAX
    } else {
        seconds as i64
    }
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
