use crate::report::{build_report_finding, send_report_finding, ReportPeriod};
use crate::runtime_probe::{spawn_runtime_probe, RuntimeProbeHandle, RuntimeProbeLaunch};
use crate::scanner::{run_scan, ScanOptions};
use crate::storage::SqliteStore;
use chrono::{DateTime, Local, TimeZone, Utc};
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
    #[serde(default)]
    last_scheduled_for: Option<DateTime<Utc>>,
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
    let mut runtime_probe = None;
    reconcile_runtime_probe(&mut runtime_probe, &config);

    loop {
        reconcile_runtime_probe(&mut runtime_probe, &config);
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
                    reconcile_runtime_probe(&mut runtime_probe, &config);
                }
            }
        }
    }
    Ok(())
}

fn reconcile_runtime_probe(
    runtime_probe: &mut Option<RuntimeProbeHandle>,
    config: &SentinelConfig,
) {
    if !config.advanced_collectors.ebpf_runtime_probe_enabled {
        if let Some(mut handle) = runtime_probe.take() {
            if let Err(err) = handle.stop() {
                warn!(error = %err, "failed to stop eBPF runtime probe");
            } else {
                info!("eBPF runtime probe stopped");
            }
        }
        return;
    }

    let desired = RuntimeProbeLaunch::from_config(config);
    let needs_start = if let Some(handle) = runtime_probe.as_mut() {
        if handle.launch() == &desired && handle.is_running() {
            false
        } else {
            if let Err(err) = handle.stop() {
                warn!(error = %err, "failed to stop stale eBPF runtime probe");
            }
            true
        }
    } else {
        true
    };
    if !needs_start {
        return;
    }
    match spawn_runtime_probe(desired.clone()) {
        Ok(handle) => {
            info!(
                command = %desired.program,
                output_path = %desired.output_path.display(),
                script_path = %desired.script_path.display(),
                capture_files = desired.options.capture_file_activity,
                "eBPF runtime probe started"
            );
            *runtime_probe = Some(handle);
        }
        Err(err) => {
            warn!(error = %err, "failed to start eBPF runtime probe");
            *runtime_probe = None;
        }
    }
}

async fn maybe_send_scheduled_report(config: &SentinelConfig) -> SentinelResult<()> {
    if !config.reports.scheduled_enabled {
        return Ok(());
    }
    if !any_notification_channel_enabled(config) {
        return Ok(());
    }
    let now = Utc::now();
    let Some(scheduled_for) = scheduled_report_due_slot_at(config, now) else {
        return Ok(());
    };
    let store = SqliteStore::open(config.storage.path.clone())?;
    let state = store
        .load_rule_state::<ScheduledReportState>(SCHEDULED_REPORT_STATE_RULE_ID)?
        .unwrap_or_default();
    if report_already_sent_for_slot(config, &state, scheduled_for) {
        return Ok(());
    }
    if state
        .last_sent_at
        .is_some_and(|last_sent_at| last_sent_at > now + chrono::Duration::minutes(5))
    {
        warn!("scheduled report state is in the future; skipping this scan");
        return Ok(());
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
                last_sent_at: Some(now),
                last_scheduled_for: Some(scheduled_for),
            },
        )?;
        info!(
            channels = delivery.delivered,
            scheduled_for = %scheduled_for,
            "scheduled report sent"
        );
    }
    Ok(())
}

fn any_notification_channel_enabled(config: &SentinelConfig) -> bool {
    config.notifications.telegram.enabled
        || config.notifications.email.enabled
        || config.notifications.webhook.enabled
        || config.notifications.ntfy.enabled
        || config.notifications.gotify.enabled
        || config.notifications.bark.enabled
        || config.notifications.serverchan.enabled
}

fn scheduled_report_due_slot_at(
    config: &SentinelConfig,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    match config.notifications.time_zone {
        NotificationTimeZone::Local => {
            local_scheduled_report_slot(now, config.reports.scheduled_hour)
        }
        NotificationTimeZone::Utc => utc_scheduled_report_slot(now, config.reports.scheduled_hour),
    }
}

fn utc_scheduled_report_slot(now: DateTime<Utc>, scheduled_hour: u8) -> Option<DateTime<Utc>> {
    let slot = Utc.from_utc_datetime(&now.date_naive().and_hms_opt(scheduled_hour as u32, 0, 0)?);
    (now >= slot).then_some(slot)
}

fn local_scheduled_report_slot(now: DateTime<Utc>, scheduled_hour: u8) -> Option<DateTime<Utc>> {
    let local_now = now.with_timezone(&Local);
    let naive_slot = local_now
        .date_naive()
        .and_hms_opt(scheduled_hour as u32, 0, 0)?;
    let slot = Local.from_local_datetime(&naive_slot).earliest()?;
    (local_now >= slot).then_some(slot.with_timezone(&Utc))
}

fn report_already_sent_for_slot(
    config: &SentinelConfig,
    state: &ScheduledReportState,
    scheduled_for: DateTime<Utc>,
) -> bool {
    if state.last_scheduled_for == Some(scheduled_for) {
        return true;
    }
    state.last_sent_at.is_some_and(|last_sent_at| {
        scheduled_report_due_slot_at(config, last_sent_at) == Some(scheduled_for)
    })
}

fn report_period_from_config(config: &SentinelConfig) -> ReportPeriod {
    match config.reports.scheduled_period.as_str() {
        "last24h" => ReportPeriod::Last24h,
        _ => ReportPeriod::Today,
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

#[cfg(test)]
mod tests {
    use super::{report_already_sent_for_slot, scheduled_report_due_slot_at, ScheduledReportState};
    use chrono::{TimeZone, Utc};
    use sentinel_core::{NotificationTimeZone, SentinelConfig};

    fn utc_report_config(hour: u8) -> SentinelConfig {
        let mut config = SentinelConfig::default();
        config.notifications.time_zone = NotificationTimeZone::Utc;
        config.reports.scheduled_hour = hour;
        config
    }

    #[test]
    fn scheduled_report_waits_until_configured_utc_hour() {
        let config = utc_report_config(8);
        let before = Utc.with_ymd_and_hms(2026, 6, 18, 7, 59, 59).unwrap();
        let due = Utc.with_ymd_and_hms(2026, 6, 18, 8, 0, 0).unwrap();
        let later = Utc.with_ymd_and_hms(2026, 6, 18, 23, 0, 0).unwrap();

        assert_eq!(scheduled_report_due_slot_at(&config, before), None);
        assert_eq!(scheduled_report_due_slot_at(&config, due), Some(due));
        assert_eq!(scheduled_report_due_slot_at(&config, later), Some(due));
    }

    #[test]
    fn scheduled_report_state_suppresses_only_the_same_daily_slot() {
        let config = utc_report_config(8);
        let yesterday_slot = Utc.with_ymd_and_hms(2026, 6, 18, 8, 0, 0).unwrap();
        let today_slot = Utc.with_ymd_and_hms(2026, 6, 19, 8, 0, 0).unwrap();
        let state = ScheduledReportState {
            last_sent_at: Some(Utc.with_ymd_and_hms(2026, 6, 18, 23, 0, 0).unwrap()),
            last_scheduled_for: Some(yesterday_slot),
        };

        assert!(!report_already_sent_for_slot(&config, &state, today_slot));
        assert!(report_already_sent_for_slot(
            &config,
            &state,
            yesterday_slot
        ));
    }

    #[test]
    fn legacy_scheduled_report_state_is_mapped_to_its_daily_slot() {
        let config = utc_report_config(8);
        let slot = Utc.with_ymd_and_hms(2026, 6, 18, 8, 0, 0).unwrap();
        let state = ScheduledReportState {
            last_sent_at: Some(Utc.with_ymd_and_hms(2026, 6, 18, 12, 30, 0).unwrap()),
            last_scheduled_for: None,
        };

        assert!(report_already_sent_for_slot(&config, &state, slot));
    }
}
