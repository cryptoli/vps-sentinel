use crate::active_response::{list_active_blocks, BlockEntry};
use crate::baseline::assess_baseline_event;
use crate::incident::{list_incidents, Incident};
use crate::scanner::ScanReport;
use crate::storage::{SqliteStore, StorageStats};
use crate::utils::redact::{mask_command_args, mask_ip, mask_ips_in_text};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sentinel_core::panel_auth::{
    panel_body_sha256_hex, panel_header_nonce, panel_signature_hex, PANEL_INGEST_PATH,
};
use sentinel_core::{
    evidence_value, Evidence, Finding, RawEvent, SentinelConfig, SentinelError, SentinelResult,
    Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::{debug, warn};
use uuid::Uuid;

const PANEL_OUTBOX_RULE_ID: &str = "panel_outbox";
const PANEL_SCHEMA_VERSION: u16 = 1;
const MAX_RETRY_PER_SCAN: usize = 3;
const MAX_PANEL_EVIDENCE_ITEMS: usize = 24;
const MAX_PANEL_EVIDENCE_VALUE_BYTES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelEnvelope {
    pub schema_version: u16,
    pub message_id: String,
    pub sent_at: DateTime<Utc>,
    pub node: PanelNodeSnapshot,
    pub scan: PanelScanSummary,
    pub findings: Vec<PanelFinding>,
    pub incidents: Vec<Incident>,
    pub baseline_drifts: Vec<PanelBaselineDrift>,
    pub active_blocks: Vec<BlockEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelNodeSnapshot {
    pub node_id: String,
    pub node_name: String,
    pub host_id: String,
    pub hostname: String,
    pub agent_version: String,
    pub privacy_mode: String,
    pub enabled_features: Vec<String>,
    pub storage: Option<StorageStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelScanSummary {
    pub finished_at: DateTime<Utc>,
    pub raw_events: usize,
    pub diff_events: usize,
    pub findings: usize,
    pub incidents: usize,
    pub suppressed_duplicates: usize,
    pub maintenance_suppressed: usize,
    pub active_response_applied: usize,
    pub active_response_failed: usize,
    pub collector_errors: usize,
    pub event_count_by_source: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelFinding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: String,
    pub category: String,
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub dedup_key: String,
    pub evidence: Vec<Evidence>,
    pub impact: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelBaselineDrift {
    pub finding_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub tier: String,
    pub score: Option<u16>,
    pub review_action: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelOutboxSummary {
    pub pending: usize,
    pub oldest_created_at: Option<DateTime<Utc>>,
    pub newest_created_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PanelOutboxState {
    items: Vec<PanelOutboxItem>,
    last_success_at: Option<DateTime<Utc>>,
    last_attempt_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PanelOutboxItem {
    id: String,
    created_at: DateTime<Utc>,
    attempts: u32,
    last_error: String,
    payload_json: String,
}

#[derive(Debug, Clone)]
struct SignedRequest {
    timestamp: i64,
    nonce: String,
    body_hash: String,
    signature: String,
}

pub async fn publish_scan(
    config: &SentinelConfig,
    store: &SqliteStore,
    report: &ScanReport,
    incidents: &[Incident],
) -> SentinelResult<PanelOutboxSummary> {
    if !config.panel.enabled {
        return outbox_summary(store);
    }

    let mut state = load_outbox(store)?;
    retry_outbox(config, &mut state, Some(MAX_RETRY_PER_SCAN)).await;

    if should_send_scan_payload(config, &state, report) {
        let payload = build_scan_payload(config, store, report, incidents)?;
        match send_envelope(config, &payload).await {
            Ok(()) => {
                state.last_success_at = Some(Utc::now());
            }
            Err(err) => {
                warn!(error = %err, "panel scan payload push failed; queued in outbox");
                enqueue_payload(config, &mut state, payload, err.to_string())?;
            }
        }
        state.last_attempt_at = Some(Utc::now());
    }

    save_outbox(store, &state)?;
    Ok(summary_from_state(&state))
}

pub async fn push_snapshot(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<PanelOutboxSummary> {
    if !config.panel.enabled {
        return Err(SentinelError::Config(
            "panel.enabled must be true before pushing to a panel".to_string(),
        ));
    }
    let mut state = load_outbox(store)?;
    retry_outbox(config, &mut state, None).await;
    let payload = build_snapshot_payload(config, store)?;
    match send_envelope(config, &payload).await {
        Ok(()) => state.last_success_at = Some(Utc::now()),
        Err(err) => enqueue_payload(config, &mut state, payload, err.to_string())?,
    }
    state.last_attempt_at = Some(Utc::now());
    save_outbox(store, &state)?;
    Ok(summary_from_state(&state))
}

pub async fn flush_outbox(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<PanelOutboxSummary> {
    if !config.panel.enabled {
        return Err(SentinelError::Config(
            "panel.enabled must be true before flushing panel outbox".to_string(),
        ));
    }
    let mut state = load_outbox(store)?;
    retry_outbox(config, &mut state, None).await;
    save_outbox(store, &state)?;
    Ok(summary_from_state(&state))
}

pub fn outbox_summary(store: &SqliteStore) -> SentinelResult<PanelOutboxSummary> {
    let state = load_outbox(store)?;
    Ok(summary_from_state(&state))
}

fn build_scan_payload(
    config: &SentinelConfig,
    store: &SqliteStore,
    report: &ScanReport,
    incidents: &[Incident],
) -> SentinelResult<PanelEnvelope> {
    let findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity.meets(config.panel.min_severity))
        .take(config.panel.batch_size)
        .map(|finding| panel_finding(config, finding))
        .collect::<Vec<_>>();
    let incidents = incidents
        .iter()
        .filter(|incident| incident.severity.meets(config.panel.min_severity))
        .take(config.panel.batch_size)
        .cloned()
        .collect::<Vec<_>>();
    let baseline_drifts = baseline_drifts_from_findings(config, &report.findings);
    let active_blocks = active_blocks(config, store)?;
    let scan = PanelScanSummary {
        finished_at: Utc::now(),
        raw_events: report.raw_event_count,
        diff_events: report.diff_event_count,
        findings: report.finding_count,
        incidents: report.incident_count,
        suppressed_duplicates: report.suppressed_duplicate_count,
        maintenance_suppressed: report.maintenance_suppressed_count,
        active_response_applied: report.active_response_applied_count,
        active_response_failed: report.active_response_failed_count,
        collector_errors: report.collector_errors.len(),
        event_count_by_source: report.event_count_by_source.clone(),
    };
    limited_payload(
        config,
        panel_envelope(
            config,
            store,
            scan,
            findings,
            incidents,
            baseline_drifts,
            active_blocks,
        )?,
    )
}

fn build_snapshot_payload(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<PanelEnvelope> {
    let findings = store
        .list_findings(config.panel.batch_size)?
        .into_iter()
        .filter(|finding| finding.severity.meets(config.panel.min_severity))
        .map(|finding| panel_finding(config, &finding))
        .collect::<Vec<_>>();
    let incidents = list_incidents(store, config.panel.batch_size)?
        .into_iter()
        .filter(|incident| incident.severity.meets(config.panel.min_severity))
        .collect::<Vec<_>>();
    let baseline_drifts = baseline_drifts_from_panel_findings(&findings);
    let active_blocks = active_blocks(config, store)?;
    let scan = PanelScanSummary {
        finished_at: Utc::now(),
        raw_events: 0,
        diff_events: 0,
        findings: findings.len(),
        incidents: incidents.len(),
        suppressed_duplicates: 0,
        maintenance_suppressed: 0,
        active_response_applied: 0,
        active_response_failed: 0,
        collector_errors: 0,
        event_count_by_source: BTreeMap::new(),
    };
    limited_payload(
        config,
        panel_envelope(
            config,
            store,
            scan,
            findings,
            incidents,
            baseline_drifts,
            active_blocks,
        )?,
    )
}

fn panel_envelope(
    config: &SentinelConfig,
    store: &SqliteStore,
    scan: PanelScanSummary,
    findings: Vec<PanelFinding>,
    incidents: Vec<Incident>,
    baseline_drifts: Vec<PanelBaselineDrift>,
    active_blocks: Vec<BlockEntry>,
) -> SentinelResult<PanelEnvelope> {
    Ok(PanelEnvelope {
        schema_version: PANEL_SCHEMA_VERSION,
        message_id: Uuid::new_v4().to_string(),
        sent_at: Utc::now(),
        node: node_snapshot(config, store)?,
        scan,
        findings,
        incidents,
        baseline_drifts,
        active_blocks,
    })
}

fn node_snapshot(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<PanelNodeSnapshot> {
    Ok(PanelNodeSnapshot {
        node_id: panel_node_id(config),
        node_name: panel_node_name(config),
        host_id: config.host_id(),
        hostname: config.agent.hostname.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        privacy_mode: config.panel.privacy_mode.clone(),
        enabled_features: enabled_features(config),
        storage: store.stats().ok(),
    })
}

fn should_send_scan_payload(
    config: &SentinelConfig,
    state: &PanelOutboxState,
    report: &ScanReport,
) -> bool {
    let has_security_items = report
        .findings
        .iter()
        .any(|finding| finding.severity.meets(config.panel.min_severity))
        || report.active_response_applied_count > 0
        || report.active_response_failed_count > 0
        || report.incident_count > 0;
    if has_security_items {
        return true;
    }
    let Some(last_success_at) = state.last_success_at else {
        return true;
    };
    let elapsed = Utc::now().signed_duration_since(last_success_at);
    elapsed >= ChronoDuration::seconds(duration_seconds(config.panel.push_interval_seconds))
}

async fn retry_outbox(
    config: &SentinelConfig,
    state: &mut PanelOutboxState,
    max_successful_retries: Option<usize>,
) {
    let mut retained = Vec::new();
    let mut sent = 0usize;
    for mut item in state.items.drain(..) {
        if max_successful_retries.map_or(true, |limit| sent < limit) {
            match serde_json::from_str::<PanelEnvelope>(&item.payload_json)
                .map_err(|err| SentinelError::Notify(err.to_string()))
                .and_then(|payload| validate_payload_size(config, &payload).map(|_| payload))
            {
                Ok(payload) => match send_envelope(config, &payload).await {
                    Ok(()) => {
                        sent += 1;
                        state.last_success_at = Some(Utc::now());
                        continue;
                    }
                    Err(err) => {
                        item.attempts = item.attempts.saturating_add(1);
                        item.last_error = err.to_string();
                    }
                },
                Err(err) => {
                    item.attempts = item.attempts.saturating_add(1);
                    item.last_error = err.to_string();
                }
            }
        }
        retained.push(item);
    }
    state.items = retained;
}

async fn send_envelope(config: &SentinelConfig, payload: &PanelEnvelope) -> SentinelResult<()> {
    let body = serde_json::to_vec(payload).map_err(|err| SentinelError::Notify(err.to_string()))?;
    if body.len() > config.panel.max_payload_bytes {
        return Err(SentinelError::Notify(format!(
            "panel payload exceeds panel.max_payload_bytes: {} > {}",
            body.len(),
            config.panel.max_payload_bytes
        )));
    }
    let signed = sign_request(
        "POST",
        PANEL_INGEST_PATH,
        &body,
        &config.panel.secret,
        &payload.node.node_id,
    )?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.panel.request_timeout_seconds))
        .build()
        .map_err(|err| SentinelError::Notify(err.to_string()))?;
    let response = client
        .post(config.panel.url.trim())
        .header("content-type", "application/json")
        .header("x-vps-sentinel-node", &payload.node.node_id)
        .header("x-vps-sentinel-timestamp", signed.timestamp.to_string())
        .header("x-vps-sentinel-nonce", signed.nonce)
        .header("x-vps-sentinel-body-sha256", signed.body_hash)
        .header("x-vps-sentinel-signature", signed.signature)
        .body(body)
        .send()
        .await
        .map_err(|err| SentinelError::Notify(err.to_string()))?;
    if !response.status().is_success() {
        return Err(SentinelError::Notify(format!(
            "panel returned HTTP {}",
            response.status()
        )));
    }
    debug!("panel payload delivered");
    Ok(())
}

fn sign_request(
    method: &str,
    path: &str,
    body: &[u8],
    secret: &str,
    node_id: &str,
) -> SentinelResult<SignedRequest> {
    let timestamp = Utc::now().timestamp();
    let nonce = panel_header_nonce(node_id, &Uuid::new_v4().to_string());
    let body_hash = panel_body_sha256_hex(body);
    let signature = panel_signature_hex(secret, method, path, timestamp, &nonce, &body_hash);
    Ok(SignedRequest {
        timestamp,
        nonce,
        body_hash,
        signature,
    })
}

fn enqueue_payload(
    config: &SentinelConfig,
    state: &mut PanelOutboxState,
    payload: PanelEnvelope,
    error: String,
) -> SentinelResult<()> {
    let payload_json =
        serde_json::to_string(&payload).map_err(|err| SentinelError::Notify(err.to_string()))?;
    state.items.push(PanelOutboxItem {
        id: payload.message_id,
        created_at: Utc::now(),
        attempts: 1,
        last_error: error,
        payload_json,
    });
    if state.items.len() > config.panel.outbox_max_items {
        let remove_count = state.items.len() - config.panel.outbox_max_items;
        state.items.drain(0..remove_count);
    }
    Ok(())
}

fn load_outbox(store: &SqliteStore) -> SentinelResult<PanelOutboxState> {
    store
        .load_rule_state::<PanelOutboxState>(PANEL_OUTBOX_RULE_ID)
        .map(|state| state.unwrap_or_default())
}

fn save_outbox(store: &SqliteStore, state: &PanelOutboxState) -> SentinelResult<()> {
    store.save_rule_state(PANEL_OUTBOX_RULE_ID, state)
}

fn summary_from_state(state: &PanelOutboxState) -> PanelOutboxSummary {
    PanelOutboxSummary {
        pending: state.items.len(),
        oldest_created_at: state.items.first().map(|item| item.created_at),
        newest_created_at: state.items.last().map(|item| item.created_at),
        last_success_at: state.last_success_at,
        last_attempt_at: state.last_attempt_at,
    }
}

fn active_blocks(config: &SentinelConfig, store: &SqliteStore) -> SentinelResult<Vec<BlockEntry>> {
    let mut blocks = list_active_blocks(config, store, false)?;
    blocks.truncate(config.panel.batch_size);
    Ok(blocks)
}

fn panel_finding(config: &SentinelConfig, finding: &Finding) -> PanelFinding {
    PanelFinding {
        id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        title: redact_text(config, &finding.title),
        severity: finding.severity,
        confidence: finding.confidence.to_string(),
        category: finding.category.to_string(),
        subject: redact_subject(config, &finding.subject),
        timestamp: finding.timestamp,
        dedup_key: finding.dedup_key.clone(),
        evidence: panel_evidence(config, &finding.evidence),
        impact: finding
            .impact
            .iter()
            .map(|item| redact_text(config, item))
            .collect(),
        recommendations: finding
            .recommendations
            .iter()
            .map(|item| redact_text(config, item))
            .collect(),
    }
}

fn panel_evidence(config: &SentinelConfig, evidence: &[Evidence]) -> Vec<Evidence> {
    evidence
        .iter()
        .take(MAX_PANEL_EVIDENCE_ITEMS)
        .map(|item| Evidence {
            key: item.key.clone(),
            value: truncate_panel_value(&redact_evidence_value(config, &item.key, &item.value)),
        })
        .collect()
}

fn baseline_drifts_from_findings(
    config: &SentinelConfig,
    findings: &[Finding],
) -> Vec<PanelBaselineDrift> {
    findings
        .iter()
        .filter(|finding| finding.severity.meets(config.panel.min_severity))
        .filter_map(|finding| baseline_drift_from_finding(config, finding))
        .take(config.panel.batch_size)
        .collect()
}

fn baseline_drifts_from_panel_findings(findings: &[PanelFinding]) -> Vec<PanelBaselineDrift> {
    findings
        .iter()
        .filter_map(|finding| {
            let tier = evidence_value(&finding.evidence, "baseline_drift_tier")?;
            Some(PanelBaselineDrift {
                finding_id: finding.id.clone(),
                rule_id: finding.rule_id.clone(),
                severity: finding.severity,
                subject: finding.subject.clone(),
                timestamp: finding.timestamp,
                tier: tier.to_string(),
                score: evidence_value(&finding.evidence, "baseline_drift_score")
                    .and_then(|value| value.parse::<u16>().ok()),
                review_action: evidence_value(&finding.evidence, "baseline_review_action")
                    .unwrap_or("review_change_before_refresh")
                    .to_string(),
                reasons: evidence_value(&finding.evidence, "baseline_drift_reasons")
                    .map(split_panel_reasons)
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn baseline_drift_from_finding(
    config: &SentinelConfig,
    finding: &Finding,
) -> Option<PanelBaselineDrift> {
    let tier = evidence_value(&finding.evidence, "baseline_drift_tier")?.to_string();
    Some(PanelBaselineDrift {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        severity: finding.severity,
        subject: redact_subject(config, &finding.subject),
        timestamp: finding.timestamp,
        tier,
        score: evidence_value(&finding.evidence, "baseline_drift_score")
            .and_then(|value| value.parse::<u16>().ok()),
        review_action: evidence_value(&finding.evidence, "baseline_review_action")
            .unwrap_or("review_change_before_refresh")
            .to_string(),
        reasons: evidence_value(&finding.evidence, "baseline_drift_reasons")
            .map(split_panel_reasons)
            .unwrap_or_default(),
    })
}

pub fn baseline_drift_from_event(event: &RawEvent) -> Option<PanelBaselineDrift> {
    let assessment = assess_baseline_event(event)?;
    Some(PanelBaselineDrift {
        finding_id: String::new(),
        rule_id: "BASELINE".to_string(),
        severity: Severity::Low,
        subject: event
            .field("path")
            .or_else(|| event.field("name"))
            .or_else(|| event.field("local_port"))
            .unwrap_or("baseline")
            .to_string(),
        timestamp: event.timestamp,
        tier: assessment.tier.to_string(),
        score: Some(assessment.score),
        review_action: assessment.review_action.to_string(),
        reasons: assessment.reasons,
    })
}

fn split_panel_reasons(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn limited_payload(
    config: &SentinelConfig,
    mut payload: PanelEnvelope,
) -> SentinelResult<PanelEnvelope> {
    loop {
        if validate_payload_size(config, &payload).is_ok() {
            return Ok(payload);
        }
        if payload.findings.len() > 1 {
            payload.findings.truncate(payload.findings.len() / 2);
            continue;
        }
        if payload.incidents.len() > 1 {
            payload.incidents.truncate(payload.incidents.len() / 2);
            continue;
        }
        if payload.baseline_drifts.len() > 1 {
            payload
                .baseline_drifts
                .truncate(payload.baseline_drifts.len() / 2);
            continue;
        }
        if payload.active_blocks.len() > 1 {
            payload
                .active_blocks
                .truncate(payload.active_blocks.len() / 2);
            continue;
        }
        validate_payload_size(config, &payload)?;
    }
}

fn validate_payload_size(config: &SentinelConfig, payload: &PanelEnvelope) -> SentinelResult<()> {
    let size = serde_json::to_vec(payload)
        .map_err(|err| SentinelError::Notify(err.to_string()))?
        .len();
    if size > config.panel.max_payload_bytes {
        return Err(SentinelError::Notify(format!(
            "panel payload is too large: {size} > {} bytes",
            config.panel.max_payload_bytes
        )));
    }
    Ok(())
}

fn panel_node_id(config: &SentinelConfig) -> String {
    if !config.panel.node_id.trim().is_empty() {
        return config.panel.node_id.trim().to_string();
    }
    config.host_id()
}

fn panel_node_name(config: &SentinelConfig) -> String {
    if !config.panel.node_name.trim().is_empty() {
        return config.panel.node_name.trim().to_string();
    }
    config.display_name()
}

fn enabled_features(config: &SentinelConfig) -> Vec<String> {
    [
        ("ssh", config.ssh.enabled),
        ("web", config.web.enabled),
        ("process", config.process.enabled),
        ("gpu", config.gpu.enabled),
        ("network", config.network.enabled),
        ("persistence", config.persistence.enabled),
        ("docker", config.docker.enabled),
        ("file_integrity", config.file_integrity.enabled),
        ("log_integrity", config.log_integrity.enabled),
        ("attack_fingerprints", config.attack_fingerprints.enabled),
        ("active_response", config.active_response.enabled),
        ("panel", config.panel.enabled),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name.to_string()))
    .collect()
}

fn redact_subject(config: &SentinelConfig, value: &str) -> String {
    if config.panel.privacy_mode == "strict" {
        return mask_ips_in_text(value);
    }
    value.to_string()
}

fn redact_text(config: &SentinelConfig, value: &str) -> String {
    if config.panel.privacy_mode == "strict" {
        return mask_ips_in_text(value);
    }
    value.to_string()
}

fn redact_evidence_value(config: &SentinelConfig, key: &str, value: &str) -> String {
    if config.panel.privacy_mode != "strict" {
        return value.to_string();
    }
    if key.contains("command") || key == "cmdline" {
        return mask_command_args(value);
    }
    if key.contains("ip") || key.contains("addr") {
        return mask_ip(value);
    }
    mask_ips_in_text(value)
}

fn truncate_panel_value(value: &str) -> String {
    if value.len() <= MAX_PANEL_EVIDENCE_VALUE_BYTES {
        return value.to_string();
    }
    let mut end = MAX_PANEL_EVIDENCE_VALUE_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

fn duration_seconds(seconds: u64) -> i64 {
    if seconds > i64::MAX as u64 {
        i64::MAX
    } else {
        seconds as i64
    }
}

#[cfg(test)]
mod tests {
    use super::{
        enqueue_payload, panel_envelope, sign_request, summary_from_state, PanelOutboxState,
        PanelScanSummary,
    };
    use crate::storage::SqliteStore;
    use chrono::Utc;
    use sentinel_core::panel_auth::{panel_signature_hex, PANEL_INGEST_METHOD, PANEL_INGEST_PATH};
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};
    use std::collections::BTreeMap;

    #[test]
    fn signing_is_deterministic_for_payload_hash_shape() {
        let signed = sign_request(
            "post",
            "/api/v1/ingest",
            b"{}",
            "secret-secret-secret",
            "node",
        )
        .expect("signed request");

        assert_eq!(signed.body_hash.len(), 64);
        assert_eq!(signed.signature.len(), 64);
        assert!(signed.nonce.starts_with("node:"));
        assert_eq!(
            signed.signature,
            panel_signature_hex(
                "secret-secret-secret",
                PANEL_INGEST_METHOD,
                PANEL_INGEST_PATH,
                signed.timestamp,
                &signed.nonce,
                &signed.body_hash,
            )
        );
    }

    #[test]
    fn outbox_respects_max_items() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.panel.enabled = true;
        config.panel.secret = "secret-secret-secret".to_string();
        config.panel.url = "https://panel.example.test/api/v1/ingest".to_string();
        config.panel.outbox_max_items = 2;
        let scan = PanelScanSummary {
            finished_at: Utc::now(),
            raw_events: 0,
            diff_events: 0,
            findings: 0,
            incidents: 0,
            suppressed_duplicates: 0,
            maintenance_suppressed: 0,
            active_response_applied: 0,
            active_response_failed: 0,
            collector_errors: 0,
            event_count_by_source: BTreeMap::new(),
        };
        let payload = panel_envelope(
            &config,
            &store,
            scan,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?;
        let mut state = PanelOutboxState::default();

        enqueue_payload(&config, &mut state, payload.clone(), "first".to_string())?;
        enqueue_payload(&config, &mut state, payload.clone(), "second".to_string())?;
        enqueue_payload(&config, &mut state, payload, "third".to_string())?;

        assert_eq!(summary_from_state(&state).pending, 2);
        assert_eq!(state.items[0].last_error, "second");
        Ok(())
    }

    #[test]
    fn evidence_is_filtered_and_truncated_for_panel_findings() {
        let mut config = SentinelConfig::default();
        config.panel.privacy_mode = "strict".to_string();
        let finding = Finding::new(
            "host",
            "ssh",
            "ssh",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root@203.0.113.10",
        )
        .with_evidence(vec![
            Evidence::new("source_ip", "203.0.113.10"),
            Evidence::new("command_line", "/bin/bash -c whoami"),
        ]);

        let panel = super::panel_finding(&config, &finding);

        assert_eq!(panel.subject, "root@203.0.x.x");
        assert_eq!(panel.evidence[0].value, "203.0.x.x");
        assert_eq!(panel.evidence[1].value, "/bin/bash [args masked]");
    }
}
