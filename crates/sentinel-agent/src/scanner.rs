use crate::active_response::{apply_active_response, ActiveResponseReport, BlockActionStatus};
use crate::baseline::{diff_snapshots, BaselineSnapshot};
use crate::collectors::{default_collectors, CollectContext};
use crate::detectors::{default_detectors, DetectContext};
use crate::findings::coalesce_related_findings;
use crate::notify::{NotificationManager, NotifyContext};
use crate::rules::system::ACTIVE_RESPONSE_SUMMARY_RULE_ID;
use crate::storage::SqliteStore;
use crate::utils::fs::path_string;
use crate::utils::redact::{mask_command_args, mask_ip, mask_ips_in_text};
use chrono::{Duration, Local, Timelike, Utc};
use sentinel_core::{
    Category, Evidence, Finding, MinuteWindow, NotificationTimeZone, RawEvent, SentinelConfig,
    SentinelResult, Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, warn};

const PROCESS_START_STATE_RULE_ID: &str = "process_start_times";
const LOG_INTEGRITY_STATE_RULE_ID: &str = "log_integrity_state";

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
    pub quiet_suppressed_count: usize,
    pub notification_rate_limited_count: usize,
    pub notification_attempt_count: usize,
    pub notification_success_count: usize,
    pub notification_failure_count: usize,
    pub active_response_planned_count: usize,
    pub active_response_applied_count: usize,
    pub active_response_failed_count: usize,
    pub active_response_expired_count: usize,
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
    let raw_event_count = raw_events.len();
    let mut detection_events = raw_events;
    detection_events.extend(diff_events);
    if options.persist {
        if let Some(store) = &store {
            enrich_process_start_drift(&mut detection_events, store)?;
            enrich_log_integrity_state(&mut detection_events, store, config.as_ref())?;
        }
    }

    let detect_context = DetectContext::new(Arc::clone(&config));
    let mut findings = Vec::new();
    for detector in default_detectors() {
        findings.extend(detector.detect(&detection_events, &detect_context));
    }
    findings = coalesce_related_findings(findings);
    let detected_finding_count = findings.len();
    let mut suppressed_duplicate_count = 0;
    let suppression = suppress_in_scan_duplicates(findings);
    findings = suppression.0;
    suppressed_duplicate_count += suppression.1;

    // Active response must evaluate current evidence before persisted duplicate
    // suppression can hide an escalated failure/probe count. Block state prevents
    // repeated firewall writes for already-blocked sources.
    let mut active_response_report = ActiveResponseReport::default();
    if config.active_response.enabled && options.persist {
        if let Some(store) = &store {
            match apply_active_response(&findings, &config, store) {
                Ok(report) => {
                    if report.applied_blocks > 0
                        || report.failed_blocks > 0
                        || report.expired_blocks > 0
                    {
                        warn!(
                            planned_blocks = report.planned_blocks,
                            applied_blocks = report.applied_blocks,
                            failed_blocks = report.failed_blocks,
                            expired_blocks = report.expired_blocks,
                            failed_expirations = report.failed_expirations,
                            stale_blocks = report.stale_blocks,
                            failed_state_checks = report.failed_state_checks,
                            skipped_existing_blocks = report.skipped_existing_blocks,
                            "active response completed"
                        );
                    }
                    apply_active_response_notification_policy(
                        &mut findings,
                        &report,
                        config.as_ref(),
                    );
                    active_response_report = report;
                }
                Err(err) => {
                    warn!(error = %err, "active response failed");
                }
            }
        }
    } else if config.active_response.enabled && !options.persist {
        warn!("active response skipped because persistence is disabled");
    }

    if options.persist {
        if let Some(store) = &store {
            let suppression = suppress_recent_duplicates(store, findings, &config)?;
            findings = suppression.0;
            suppressed_duplicate_count += suppression.1;
            if suppressed_duplicate_count > 0 {
                debug!(
                    suppressed_duplicates = suppressed_duplicate_count,
                    "duplicate findings suppressed"
                );
            }
        }
    }

    if privacy_redaction_enabled(&config) {
        findings = redact_findings(findings, &config);
    }

    if options.persist {
        if let Some(store) = &store {
            if privacy_redaction_enabled(&config) {
                let redacted_events = redact_raw_events(&detection_events, &config);
                store.save_raw_events(&redacted_events)?;
            } else {
                store.save_raw_events(&detection_events)?;
            }
            save_process_start_state(&detection_events, store)?;
            save_log_integrity_state(&detection_events, store)?;
            store.save_findings(&findings)?;
            store.record_scan_run(detection_events.len(), findings.len(), "ok")?;
        }
    }

    let mut notification_attempt_count = 0;
    let mut notification_success_count = 0;
    let mut notification_failure_count = 0;
    let mut quiet_suppressed_count = 0;
    let mut notification_rate_limited_count = 0;
    if options.notify {
        let manager = NotificationManager::from_config(&config);
        let notify_context = NotifyContext {
            config: Arc::clone(&config),
        };
        let notification_findings = if quiet_hours_active(&config) {
            let filtered = quiet_hours_allowed_findings(&findings, &config);
            quiet_suppressed_count = findings.len().saturating_sub(filtered.len());
            if quiet_suppressed_count > 0 {
                warn!(
                    suppressed_findings = quiet_suppressed_count,
                    bypass_min_severity = %config.noise_control.quiet_hours_bypass_min_severity,
                    "quiet hours active; lower-severity notifications suppressed"
                );
            }
            filtered
        } else {
            findings.clone()
        };
        let delivery_limit = notification_delivery_limit(&store, &config)?;
        let plan = manager.delivery_plan(
            &notification_findings,
            delivery_limit,
            config.noise_control.rate_limit_bypass_min_severity,
        );
        notification_rate_limited_count = plan.suppressed_by_rate_limit;
        if notification_rate_limited_count > 0 {
            warn!(
                planned_notifications = plan.planned,
                allowed_notifications = plan.allowed,
                suppressed_notifications = notification_rate_limited_count,
                bypass_min_severity = %config.noise_control.rate_limit_bypass_min_severity,
                "notification hourly rate limit reached"
            );
        }
        let notification_results = manager
            .notify_all_with_budget(
                &notification_findings,
                &notify_context,
                delivery_limit,
                config.noise_control.rate_limit_bypass_min_severity,
            )
            .await;
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

    if options.persist {
        if let Some(store) = &store {
            let pruned = store.prune_older_than(config.storage.retention_days)?;
            if pruned > 0 {
                debug!(deleted_rows = pruned, "old storage rows pruned");
            }
            if let Some(report) = store.enforce_size_limit(config.storage.max_database_size_mb)? {
                if report.size_after_bytes
                    > config
                        .storage
                        .max_database_size_mb
                        .saturating_mul(1024 * 1024)
                {
                    warn!(
                        size_before_bytes = report.size_before_bytes,
                        size_after_bytes = report.size_after_bytes,
                        deleted_rows = report.deleted_rows,
                        max_database_size_mb = config.storage.max_database_size_mb,
                        "storage size limit cleanup ran but database remains above configured limit"
                    );
                } else {
                    debug!(
                        size_before_bytes = report.size_before_bytes,
                        size_after_bytes = report.size_after_bytes,
                        deleted_rows = report.deleted_rows,
                        vacuumed = report.vacuumed,
                        max_database_size_mb = config.storage.max_database_size_mb,
                        "storage size limit cleanup completed"
                    );
                }
            }
        }
    }

    debug!(
        raw_events = raw_event_count,
        diff_events = diff_event_count,
        detected_findings = detected_finding_count,
        findings = findings.len(),
        suppressed_duplicates = suppressed_duplicate_count,
        quiet_suppressed = quiet_suppressed_count,
        notification_rate_limited = notification_rate_limited_count,
        notification_attempts = notification_attempt_count,
        notification_successes = notification_success_count,
        notification_failures = notification_failure_count,
        active_response_planned = active_response_report.planned_blocks,
        active_response_applied = active_response_report.applied_blocks,
        active_response_failed = active_response_report.failed_blocks,
        active_response_expired = active_response_report.expired_blocks,
        collector_errors = collector_errors.len(),
        "scan completed"
    );
    Ok(ScanReport {
        raw_event_count,
        diff_event_count,
        finding_count: findings.len(),
        suppressed_duplicate_count,
        quiet_suppressed_count,
        notification_rate_limited_count,
        notification_attempt_count,
        notification_success_count,
        notification_failure_count,
        active_response_planned_count: active_response_report.planned_blocks,
        active_response_applied_count: active_response_report.applied_blocks,
        active_response_failed_count: active_response_report.failed_blocks,
        active_response_expired_count: active_response_report.expired_blocks,
        findings,
        collector_errors,
    })
}

fn apply_active_response_notification_policy(
    findings: &mut Vec<Finding>,
    report: &ActiveResponseReport,
    config: &SentinelConfig,
) {
    let new_blocks = report
        .block_actions
        .iter()
        .filter(|action| action.status == BlockActionStatus::Blocked)
        .collect::<Vec<_>>();
    if new_blocks.len() > config.active_response.notification_detail_limit {
        findings.push(active_response_summary_finding(&new_blocks, report, config));
        return;
    }
    annotate_active_response(findings, report, config);
}

fn active_response_summary_finding(
    new_blocks: &[&crate::active_response::BlockAction],
    report: &ActiveResponseReport,
    config: &SentinelConfig,
) -> Finding {
    let mut evidence = vec![
        Evidence::new("active_response_status", "blocked_many"),
        Evidence::new("active_response_block_count", new_blocks.len().to_string()),
        Evidence::new(
            "active_response_reason_summary",
            summarize_block_reasons(new_blocks),
        ),
        Evidence::new(
            "active_response_detail_limit",
            config.active_response.notification_detail_limit.to_string(),
        ),
        Evidence::new("active_response_window", "current_scan"),
        Evidence::new("active_response_command", "vs blocks list --no-verify"),
    ];
    if report.failed_blocks > 0 {
        evidence.push(Evidence::new(
            "active_response_failed_count",
            report.failed_blocks.to_string(),
        ));
    }

    Finding::new(
        config.host_id(),
        "Multiple IPs blocked by active response",
        "Active response blocked many source IPs in one scan window. Details are available on the server.",
        Severity::High,
        Category::System,
        ACTIVE_RESPONSE_SUMMARY_RULE_ID,
        "active-response",
    )
    .with_evidence_deduped_by(
        evidence,
        &[
            "active_response_status",
            "active_response_block_count",
            "active_response_reason_summary",
        ],
    )
    .with_impact(vec![
        "A high-volume attack or scan burst was blocked by the local firewall.".to_string(),
    ])
    .with_recommendations(vec![
        "Run `vs blocks list --no-verify` on the server to review blocked IPs and reasons."
            .to_string(),
        "Review web and SSH logs around the same scan window before widening allowlists."
            .to_string(),
    ])
}

fn summarize_block_reasons(new_blocks: &[&crate::active_response::BlockAction]) -> String {
    let mut counts = BTreeMap::<&'static str, usize>::new();
    for action in new_blocks {
        let reason = if action.reason.starts_with("web probe ") {
            "web_probe"
        } else if action.reason.starts_with("web error burst ") {
            "web_error_burst"
        } else if action.reason.starts_with("ssh brute force ") {
            "ssh_brute_force"
        } else {
            "other"
        };
        *counts.entry(reason).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(reason, count)| format!("{reason}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn annotate_active_response(
    findings: &mut [Finding],
    report: &ActiveResponseReport,
    config: &SentinelConfig,
) {
    if report.block_actions.is_empty() {
        return;
    }

    let mut actions_by_finding = BTreeMap::new();
    for action in &report.block_actions {
        actions_by_finding.insert(action.finding_id.as_str(), action);
    }

    for finding in findings {
        let Some(action) = actions_by_finding.get(finding.id.as_str()) else {
            continue;
        };
        finding.evidence.push(Evidence::new(
            "active_response_status",
            action.status.as_str(),
        ));
        finding
            .evidence
            .push(Evidence::new("active_response_ip", action.ip.to_string()));
        finding
            .evidence
            .push(Evidence::new("active_response_reason", &action.reason));
        if let Some(backend) = &action.backend {
            finding
                .evidence
                .push(Evidence::new("active_response_backend", backend));
        }
        if let Some(expires_at) = action.expires_at {
            finding.evidence.push(Evidence::new(
                "active_response_expires_at",
                format_active_response_timestamp(expires_at, config.notifications.time_zone),
            ));
        }
        if let Some(detail) = &action.detail {
            finding
                .evidence
                .push(Evidence::new("active_response_detail", detail));
        }
    }
}

fn format_active_response_timestamp(
    timestamp: chrono::DateTime<Utc>,
    time_zone: NotificationTimeZone,
) -> String {
    match time_zone {
        NotificationTimeZone::Local => timestamp
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %:z")
            .to_string(),
        NotificationTimeZone::Utc => timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    }
}

fn notification_delivery_limit(
    store: &Option<SqliteStore>,
    config: &SentinelConfig,
) -> SentinelResult<Option<usize>> {
    let Some(store) = store else {
        return Ok(Some(config.noise_control.max_alerts_per_hour as usize));
    };
    let since = Utc::now() - Duration::hours(1);
    let already_attempted = store.notification_attempt_count_since(since)?;
    let remaining =
        (config.noise_control.max_alerts_per_hour as usize).saturating_sub(already_attempted);
    Ok(Some(remaining))
}

fn quiet_hours_active(config: &SentinelConfig) -> bool {
    if config.noise_control.quiet_hours.is_empty() {
        return false;
    }
    let now = Local::now();
    let minute = (now.hour() * 60 + now.minute()) as u16;
    config
        .noise_control
        .quiet_hours
        .iter()
        .filter_map(|value| value.parse::<MinuteWindow>().ok())
        .any(|window| window.contains(minute))
}

fn quiet_hours_allowed_findings(findings: &[Finding], config: &SentinelConfig) -> Vec<Finding> {
    findings
        .iter()
        .filter(|finding| {
            finding
                .severity
                .meets(config.noise_control.quiet_hours_bypass_min_severity)
        })
        .cloned()
        .collect()
}

fn privacy_redaction_enabled(config: &SentinelConfig) -> bool {
    config.privacy.mask_ip || config.privacy.mask_command_args
}

fn redact_raw_events(events: &[RawEvent], config: &SentinelConfig) -> Vec<RawEvent> {
    events
        .iter()
        .cloned()
        .map(|mut event| {
            for (key, value) in &mut event.fields {
                *value = redact_field_value(key, value, config);
            }
            event
        })
        .collect()
}

fn redact_findings(findings: Vec<Finding>, config: &SentinelConfig) -> Vec<Finding> {
    findings
        .into_iter()
        .map(|mut finding| {
            finding.subject = redact_text(&finding.subject, config);
            finding.evidence = finding
                .evidence
                .into_iter()
                .map(|item| Evidence {
                    value: redact_field_value(&item.key, &item.value, config),
                    ..item
                })
                .collect();
            finding
        })
        .collect()
}

fn redact_field_value(key: &str, value: &str, config: &SentinelConfig) -> String {
    if key == "raw" && privacy_redaction_enabled(config) {
        return "[masked by privacy config]".to_string();
    }
    let mut redacted = if config.privacy.mask_command_args && key == "cmdline" {
        mask_command_args(value)
    } else {
        value.to_string()
    };
    if config.privacy.mask_ip {
        redacted = if key.contains("ip") || key.ends_with("_addr") {
            mask_ip(&redacted)
        } else {
            mask_ips_in_text(&redacted)
        };
    }
    redacted
}

fn redact_text(value: &str, config: &SentinelConfig) -> String {
    if config.privacy.mask_ip {
        mask_ips_in_text(value)
    } else {
        value.to_string()
    }
}

fn suppress_recent_duplicates(
    store: &SqliteStore,
    findings: Vec<Finding>,
    config: &SentinelConfig,
) -> SentinelResult<(Vec<Finding>, usize)> {
    let mut retained = Vec::new();
    let mut suppressed = 0;
    for finding in findings {
        let window_seconds = duplicate_suppression_window_seconds(&finding, config);
        if window_seconds == 0 {
            retained.push(finding);
            continue;
        }
        if has_new_active_response_block(&finding) {
            retained.push(finding);
            continue;
        }
        let since = Utc::now() - Duration::seconds(duration_seconds(window_seconds));
        if !store.finding_seen_since(&finding.dedup_key, since)? {
            retained.push(finding);
        } else {
            suppressed += 1;
        }
    }
    Ok((retained, suppressed))
}

fn has_new_active_response_block(finding: &Finding) -> bool {
    finding
        .evidence
        .iter()
        .any(|item| item.key == "active_response_status" && item.value == "blocked")
}

fn duplicate_suppression_window_seconds(finding: &Finding, config: &SentinelConfig) -> u64 {
    if is_state_finding(finding) {
        return config
            .noise_control
            .dedup_window_seconds
            .max(config.noise_control.state_reminder_interval_seconds);
    }
    config.noise_control.dedup_window_seconds
}

fn duration_seconds(seconds: u64) -> i64 {
    if seconds > i64::MAX as u64 {
        i64::MAX
    } else {
        seconds as i64
    }
}

fn is_state_finding(finding: &Finding) -> bool {
    matches!(
        finding.category,
        Category::ConfigRisk
            | Category::Docker
            | Category::FileIntegrity
            | Category::Network
            | Category::Persistence
            | Category::Privilege
            | Category::Process
            | Category::Rootkit
            | Category::User
    ) || matches!(
        finding.rule_id.as_str(),
        "SSH-005" | "SSH-006" | "TAMPER-001" | "TAMPER-002" | "TAMPER-003"
    )
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProcessStartState {
    processes: BTreeMap<String, ProcessStartRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessStartRecord {
    start_ticks: String,
    name: String,
    exe_path: String,
    exe_hash_blake3: String,
    systemd_unit: String,
}

fn enrich_process_start_drift(events: &mut [RawEvent], store: &SqliteStore) -> SentinelResult<()> {
    let Some(previous) = store.load_rule_state::<ProcessStartState>(PROCESS_START_STATE_RULE_ID)?
    else {
        return Ok(());
    };

    for event in events
        .iter_mut()
        .filter(|event| event.kind == "process_snapshot")
    {
        let Some(current) = process_start_record(event) else {
            continue;
        };
        let Some(identity) = process_start_identity_from_record(&current) else {
            continue;
        };
        let Some(old) = previous.processes.get(&identity) else {
            continue;
        };
        if old.start_ticks != current.start_ticks {
            event
                .fields
                .insert("process_start_changed".to_string(), "true".to_string());
            event
                .fields
                .insert("process_start_drift".to_string(), "changed".to_string());
            event.fields.insert(
                "previous_process_start_ticks".to_string(),
                old.start_ticks.clone(),
            );
            event.fields.insert(
                "current_process_start_ticks".to_string(),
                current.start_ticks,
            );
        }
    }
    Ok(())
}

fn save_process_start_state(events: &[RawEvent], store: &SqliteStore) -> SentinelResult<()> {
    let processes = events
        .iter()
        .filter(|event| event.kind == "process_snapshot")
        .filter_map(|event| {
            let record = process_start_record(event)?;
            Some((process_start_identity_from_record(&record)?, record))
        })
        .collect::<BTreeMap<_, _>>();
    if processes.is_empty() {
        return Ok(());
    }
    store.save_rule_state(
        PROCESS_START_STATE_RULE_ID,
        &ProcessStartState { processes },
    )
}

fn process_start_identity_from_record(record: &ProcessStartRecord) -> Option<String> {
    let exe_path = record.exe_path.trim();
    let name = record.name.trim();
    if exe_path.is_empty() && name.is_empty() {
        return None;
    }
    Some(
        [
            ("exe", exe_path),
            ("name", name),
            ("hash", record.exe_hash_blake3.trim()),
            ("unit", record.systemd_unit.trim()),
        ]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("|"),
    )
}

fn process_start_record(event: &RawEvent) -> Option<ProcessStartRecord> {
    let start_ticks = event.field("process_start_ticks")?.trim();
    if start_ticks.is_empty() {
        return None;
    }
    Some(ProcessStartRecord {
        start_ticks: start_ticks.to_string(),
        name: event.field("name").unwrap_or("").trim().to_string(),
        exe_path: normalized_process_path(event.field("exe_path").unwrap_or("")),
        exe_hash_blake3: event
            .field("exe_hash_blake3")
            .unwrap_or("")
            .trim()
            .to_string(),
        systemd_unit: event.field("systemd_unit").unwrap_or("").trim().to_string(),
    })
}

fn normalized_process_path(path: &str) -> String {
    path.trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| path.trim())
        .to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LogIntegrityState {
    files: BTreeMap<String, LogFileRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogFileRecord {
    size: u64,
    file_type: String,
    symlink_target: String,
    modified_unix: String,
}

fn enrich_log_integrity_state(
    events: &mut Vec<RawEvent>,
    store: &SqliteStore,
    config: &SentinelConfig,
) -> SentinelResult<()> {
    if !config.log_integrity.enabled {
        return Ok(());
    }
    let Some(previous) = store.load_rule_state::<LogIntegrityState>(LOG_INTEGRITY_STATE_RULE_ID)?
    else {
        return Ok(());
    };

    let configured_paths = config
        .log_integrity
        .paths
        .iter()
        .map(|path| path_string(path))
        .collect::<BTreeSet<_>>();
    let current_paths = events
        .iter()
        .filter(|event| event.kind == "log_file_snapshot")
        .filter_map(|event| event.field("path"))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();

    for event in events
        .iter_mut()
        .filter(|event| event.kind == "log_file_snapshot")
    {
        let Some(path) = event.field("path").filter(|path| !path.trim().is_empty()) else {
            continue;
        };
        let Some(old) = previous.files.get(path) else {
            continue;
        };
        let current = log_file_record(event);
        if significant_log_size_drop(old, &current, config)
            && event.field("recent_rotated_sibling") != Some("true")
        {
            let dropped = old.size.saturating_sub(current.size);
            let drop_percent = dropped
                .saturating_mul(100)
                .checked_div(old.size)
                .unwrap_or(0);
            event
                .fields
                .insert("log_size_drop".to_string(), "true".to_string());
            event
                .fields
                .insert("previous_size".to_string(), old.size.to_string());
            event
                .fields
                .insert("current_size".to_string(), current.size.to_string());
            event
                .fields
                .insert("dropped_bytes".to_string(), dropped.to_string());
            event
                .fields
                .insert("drop_percent".to_string(), drop_percent.to_string());
        }
    }

    for (path, old) in &previous.files {
        if !configured_paths.contains(path) || current_paths.contains(path) {
            continue;
        }
        events.push(
            RawEvent::new("log_integrity", "log_file_snapshot")
                .with_field("path", path.as_str())
                .with_field("file_type", "missing")
                .with_field("size", "0")
                .with_field("log_file_missing", "true")
                .with_field("previous_size", old.size.to_string())
                .with_field("previous_file_type", old.file_type.clone())
                .with_field("previous_symlink_target", old.symlink_target.clone())
                .with_field("previous_modified_unix", old.modified_unix.clone()),
        );
    }
    Ok(())
}

fn save_log_integrity_state(events: &[RawEvent], store: &SqliteStore) -> SentinelResult<()> {
    let files = events
        .iter()
        .filter(|event| event.kind == "log_file_snapshot")
        .filter(|event| event.field("log_file_missing") != Some("true"))
        .filter_map(|event| {
            let path = event.field("path")?.trim();
            (!path.is_empty()).then(|| (path.to_string(), log_file_record(event)))
        })
        .collect::<BTreeMap<_, _>>();
    if files.is_empty() {
        return Ok(());
    }
    store.save_rule_state(LOG_INTEGRITY_STATE_RULE_ID, &LogIntegrityState { files })
}

fn log_file_record(event: &RawEvent) -> LogFileRecord {
    LogFileRecord {
        size: event
            .field("size")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0),
        file_type: event.field("file_type").unwrap_or("").trim().to_string(),
        symlink_target: event
            .field("symlink_target")
            .unwrap_or("")
            .trim()
            .to_string(),
        modified_unix: event
            .field("modified_unix")
            .unwrap_or("")
            .trim()
            .to_string(),
    }
}

fn significant_log_size_drop(
    old: &LogFileRecord,
    current: &LogFileRecord,
    config: &SentinelConfig,
) -> bool {
    if old.file_type != "file" || current.file_type != "file" || current.size >= old.size {
        return false;
    }
    let dropped = old.size.saturating_sub(current.size);
    if dropped < config.log_integrity.truncate_min_drop_bytes {
        return false;
    }
    if old.size == 0 {
        return false;
    }
    let drop_percent = dropped
        .saturating_mul(100)
        .checked_div(old.size)
        .unwrap_or(0);
    drop_percent >= config.log_integrity.truncate_drop_percent as u64
}

fn suppress_in_scan_duplicates(findings: Vec<Finding>) -> (Vec<Finding>, usize) {
    let mut seen = BTreeSet::new();
    let mut retained = Vec::new();
    let mut suppressed = 0;
    for finding in findings {
        if seen.insert(finding.dedup_key.clone()) {
            retained.push(finding);
        } else {
            suppressed += 1;
        }
    }
    (retained, suppressed)
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

#[cfg(test)]
mod tests;
