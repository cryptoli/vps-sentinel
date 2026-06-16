use crate::baseline::{diff_snapshots, BaselineSnapshot};
use crate::collectors::{default_collectors, CollectContext};
use crate::detectors::{default_detectors, DetectContext};
use crate::notify::{NotificationManager, NotifyContext};
use crate::storage::SqliteStore;
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
    pub findings: Vec<Finding>,
    pub collector_errors: Vec<String>,
}

/// Run one complete scan: collect facts, diff baseline, detect findings, persist, and notify.
pub async fn run_scan(config: SentinelConfig, options: ScanOptions) -> SentinelResult<ScanReport> {
    let config = Arc::new(config);
    let store = SqliteStore::open(config.storage.path.clone())?;
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
    let diff_events = match store.latest_baseline_snapshot()? {
        Some(previous) => diff_snapshots(&previous, &current_snapshot),
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

    if options.persist {
        store.save_raw_events(&detection_events)?;
        store.save_findings(&findings)?;
        store.record_scan_run(detection_events.len(), findings.len(), "ok")?;
    }

    if options.notify {
        let manager = NotificationManager::from_config(&config);
        let notify_context = NotifyContext {
            config: Arc::clone(&config),
        };
        for (channel, result) in manager.notify_all(&findings, &notify_context).await {
            if let Err(err) = result {
                warn!(channel = channel, error = %err, "notification failed");
            }
        }
    }

    Ok(ScanReport {
        raw_event_count: raw_events.len(),
        diff_event_count,
        finding_count: findings.len(),
        findings,
        collector_errors,
    })
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
