use crate::baseline::{diff_snapshots, BaselineSnapshot};
use crate::collectors::{default_collectors, CollectContext};
use crate::detectors::{default_detectors, DetectContext};
use crate::notify::{NotificationManager, NotifyContext};
use crate::storage::SqliteStore;
use chrono::{Duration, Utc};
use sentinel_core::{Finding, RawEvent, SentinelConfig, SentinelResult};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, warn};

/// Controls side effects performed by one scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub persist: bool,
    pub notify: bool,
    pub scan_root: PathBuf,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            persist: true,
            notify: true,
            scan_root: PathBuf::from("/"),
        }
    }
}

/// Result summary for one scan run.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub raw_event_count: usize,
    pub diff_event_count: usize,
    pub finding_count: usize,
    pub suppressed_duplicate_count: usize,
    pub notification_attempt_count: usize,
    pub notification_success_count: usize,
    pub notification_failure_count: usize,
    pub findings: Vec<Finding>,
    pub collector_errors: Vec<String>,
}

/// Run one complete scan: collect facts, diff baseline, detect findings, persist, and notify.
pub async fn run_scan(config: SentinelConfig, options: ScanOptions) -> SentinelResult<ScanReport> {
    debug!(
        persist = options.persist,
        notify = options.notify,
        scan_root = %options.scan_root.display(),
        "scan started"
    );
    let config = Arc::new(config);
    let store = if options.persist {
        Some(SqliteStore::open(config.storage.path.clone())?)
    } else {
        None
    };
    let collect_context =
        CollectContext::new(Arc::clone(&config)).with_scan_root(options.scan_root);
    let mut raw_events = Vec::new();
    let mut collector_errors = Vec::new();

    for collector in default_collectors() {
        debug!(collector = collector.name(), "collector started");
        match collector.collect(&collect_context).await {
            Ok(mut events) => {
                debug!(
                    collector = collector.name(),
                    events = events.len(),
                    "collector finished"
                );
                raw_events.append(&mut events);
            }
            Err(err) => {
                warn!(collector = collector.name(), error = %err, "collector failed");
                collector_errors.push(format!("{}: {err}", collector.name()));
            }
        }
    }

    let current_snapshot = BaselineSnapshot::from_events(&raw_events);
    let diff_events = match &store {
        Some(store) => match store.latest_baseline_snapshot()? {
            Some(previous) => diff_snapshots(&previous, &current_snapshot),
            None => Vec::new(),
        },
        None => Vec::new(),
    };
    let diff_event_count = diff_events.len();
    let mut detection_events = raw_events.clone();
    detection_events.extend(diff_events);

    let detect_context = DetectContext::new(Arc::clone(&config));
    let mut findings = Vec::new();
    for detector in default_detectors() {
        findings.extend(detector.detect(&detection_events, &detect_context));
    }
    let detected_finding_count = findings.len();
    let mut suppressed_duplicate_count = 0;
    if options.persist {
        if let Some(store) = &store {
            let suppression = suppress_recent_duplicates(
                store,
                findings,
                config.noise_control.dedup_window_seconds,
            )?;
            findings = suppression.0;
            suppressed_duplicate_count = suppression.1;
            if suppressed_duplicate_count > 0 {
                debug!(
                    suppressed_duplicates = suppressed_duplicate_count,
                    "duplicate findings suppressed"
                );
            }
        }
    }

    if options.persist {
        if let Some(store) = &store {
            store.save_raw_events(&detection_events)?;
            store.save_findings(&findings)?;
            store.record_scan_run(detection_events.len(), findings.len(), "ok")?;
        }
    }

    let mut notification_attempt_count = 0;
    let mut notification_success_count = 0;
    let mut notification_failure_count = 0;
    if options.notify {
        let manager = NotificationManager::from_config(&config);
        let notify_context = NotifyContext {
            config: Arc::clone(&config),
        };
        let notification_results = manager.notify_all(&findings, &notify_context).await;
        notification_attempt_count = notification_results.len();
        for (finding_id, channel, result) in notification_results {
            match &result {
                Ok(()) => {
                    notification_success_count += 1;
                    debug!(
                        finding_id = finding_id,
                        channel = channel,
                        "notification sent"
                    );
                }
                Err(err) => {
                    notification_failure_count += 1;
                    warn!(finding_id = finding_id, channel = channel, error = %err, "notification failed");
                }
            }
            if options.persist {
                let Some(store) = &store else {
                    continue;
                };
                let (status, error) = match &result {
                    Ok(()) => ("ok", String::new()),
                    Err(err) => ("failed", err.to_string()),
                };
                if let Err(err) =
                    store.record_notification_log(&finding_id, &channel, status, &error)
                {
                    warn!(channel = channel, error = %err, "failed to record notification log");
                }
            }
        }
    }

    debug!(
        raw_events = raw_events.len(),
        diff_events = diff_event_count,
        detected_findings = detected_finding_count,
        findings = findings.len(),
        suppressed_duplicates = suppressed_duplicate_count,
        notification_attempts = notification_attempt_count,
        notification_successes = notification_success_count,
        notification_failures = notification_failure_count,
        collector_errors = collector_errors.len(),
        "scan completed"
    );
    Ok(ScanReport {
        raw_event_count: raw_events.len(),
        diff_event_count,
        finding_count: findings.len(),
        suppressed_duplicate_count,
        notification_attempt_count,
        notification_success_count,
        notification_failure_count,
        findings,
        collector_errors,
    })
}

fn suppress_recent_duplicates(
    store: &SqliteStore,
    findings: Vec<Finding>,
    dedup_window_seconds: u64,
) -> SentinelResult<(Vec<Finding>, usize)> {
    if dedup_window_seconds == 0 {
        return Ok((findings, 0));
    }
    let seconds = if dedup_window_seconds > i64::MAX as u64 {
        i64::MAX
    } else {
        dedup_window_seconds as i64
    };
    let since = Utc::now() - Duration::seconds(seconds);
    let mut retained = Vec::new();
    let mut suppressed = 0;
    for finding in findings {
        if !store.finding_seen_since(&finding.dedup_key, since)? {
            retained.push(finding);
        } else {
            suppressed += 1;
        }
    }
    Ok((retained, suppressed))
}

/// Collect current host facts and turn them into a baseline snapshot.
pub async fn create_baseline_snapshot(
    config: SentinelConfig,
    scan_root: PathBuf,
) -> SentinelResult<BaselineSnapshot> {
    let config = Arc::new(config);
    let collect_context = CollectContext::new(config).with_scan_root(scan_root);
    let mut raw_events = Vec::<RawEvent>::new();
    for collector in default_collectors() {
        match collector.collect(&collect_context).await {
            Ok(mut events) => raw_events.append(&mut events),
            Err(err) => {
                warn!(collector = collector.name(), error = %err, "collector failed during baseline creation")
            }
        }
    }
    Ok(BaselineSnapshot::from_events(&raw_events))
}
