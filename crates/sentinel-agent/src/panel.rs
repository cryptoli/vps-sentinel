use crate::active_response::{list_active_blocks, BlockEntry};
use crate::baseline::assess_baseline_event;
use crate::incident::{list_incidents, Incident};
use crate::node_metrics::{collect_node_metrics, NodeMetrics};
use crate::scanner::ScanReport;
use crate::storage::{SqliteStore, StorageStats};
use crate::utils::ip::{ip_in_cidr, is_public_remote_ip};
use crate::utils::redact::{mask_command_args, remove_ip, remove_ips_in_text};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sentinel_core::panel_auth::{
    panel_body_sha256_hex, panel_header_nonce, panel_signature_hex, PANEL_INGEST_PATH,
};
use sentinel_core::{
    evidence_value, Evidence, Finding, RawEvent, SentinelConfig, SentinelError, SentinelResult,
    Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use tracing::{debug, warn};
use uuid::Uuid;

const PANEL_OUTBOX_RULE_ID: &str = "panel_outbox";
const PANEL_SCHEMA_VERSION: u16 = 2;
const MAX_RETRY_PER_SCAN: usize = 3;
const MAX_PANEL_EVIDENCE_ITEMS: usize = 24;
const MAX_PANEL_EVIDENCE_VALUE_BYTES: usize = 512;
const PANEL_TRANSPORT_ENCODING: &str = "json-base64";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelEnvelope {
    pub schema_version: u16,
    pub message_id: String,
    pub sent_at: DateTime<Utc>,
    pub node: PanelNodeSnapshot,
    pub scan: PanelScanSummary,
    pub findings: Vec<PanelFinding>,
    pub incidents: Vec<PanelIncident>,
    pub baseline_drifts: Vec<PanelBaselineDrift>,
    pub active_blocks: Vec<PanelActiveBlock>,
    #[serde(default)]
    pub probe_sources: Vec<PanelProbeSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelNodeSnapshot {
    #[serde(default, skip_serializing)]
    pub node_id: String,
    pub node_name: String,
    #[serde(default, skip_serializing)]
    pub host_id: String,
    #[serde(default, skip_serializing)]
    pub hostname: String,
    pub agent_version: String,
    pub privacy_mode: String,
    pub enabled_features: Vec<String>,
    pub storage: Option<StorageStats>,
    pub metrics: Option<NodeMetrics>,
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
pub struct PanelIncident {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub score: u16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelBaselineDrift {
    pub finding_id: String,
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub tier: String,
    pub score: Option<u16>,
    pub review_action: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelActiveBlock {
    pub ip: String,
    pub rule_id: String,
    pub finding_id: String,
    pub reason: String,
    pub backend: String,
    pub blocked_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub expired: bool,
    pub firewall_present: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelProbeSource {
    pub source_ip: String,
    pub ip_version: String,
    pub network_prefix: String,
    pub country: String,
    pub asn: String,
    pub organization: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub seen_count: usize,
    pub categories: Vec<String>,
    pub rule_ids: Vec<String>,
    pub latest_reason: String,
    pub block_status: String,
    pub block_reason: String,
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

struct PanelEnvelopeParts {
    scan: PanelScanSummary,
    findings: Vec<PanelFinding>,
    incidents: Vec<PanelIncident>,
    baseline_drifts: Vec<PanelBaselineDrift>,
    active_blocks: Vec<PanelActiveBlock>,
    probe_sources: Vec<PanelProbeSource>,
}

#[derive(Debug, Clone)]
struct SignedRequest {
    timestamp: i64,
    nonce: String,
    body_hash: String,
    signature: String,
}

#[derive(Serialize)]
struct PanelTransportBody {
    encoding: &'static str,
    payload: String,
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
    let block_entries = active_blocks(config, store)?;
    let probe_sources = panel_probe_sources(config, &report.findings, &block_entries);
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
        .map(|incident| panel_incident(config, incident))
        .collect::<Vec<_>>();
    let baseline_drifts = baseline_drifts_from_findings(config, &report.findings);
    let active_blocks = block_entries
        .into_iter()
        .map(|block| panel_active_block(config, block))
        .collect::<Vec<_>>();
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
            PanelEnvelopeParts {
                scan,
                findings,
                incidents,
                baseline_drifts,
                active_blocks,
                probe_sources,
            },
        )?,
    )
}

fn build_snapshot_payload(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<PanelEnvelope> {
    let stored_findings = store.list_findings(config.panel.batch_size)?;
    let block_entries = active_blocks(config, store)?;
    let probe_sources = panel_probe_sources(config, &stored_findings, &block_entries);
    let findings = stored_findings
        .into_iter()
        .filter(|finding| finding.severity.meets(config.panel.min_severity))
        .map(|finding| panel_finding(config, &finding))
        .collect::<Vec<_>>();
    let incidents = list_incidents(store, config.panel.batch_size)?
        .into_iter()
        .filter(|incident| incident.severity.meets(config.panel.min_severity))
        .map(|incident| panel_incident(config, &incident))
        .collect::<Vec<_>>();
    let baseline_drifts = baseline_drifts_from_panel_findings(&findings);
    let active_blocks = block_entries
        .into_iter()
        .map(|block| panel_active_block(config, block))
        .collect::<Vec<_>>();
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
            PanelEnvelopeParts {
                scan,
                findings,
                incidents,
                baseline_drifts,
                active_blocks,
                probe_sources,
            },
        )?,
    )
}

fn panel_envelope(
    config: &SentinelConfig,
    store: &SqliteStore,
    parts: PanelEnvelopeParts,
) -> SentinelResult<PanelEnvelope> {
    Ok(PanelEnvelope {
        schema_version: PANEL_SCHEMA_VERSION,
        message_id: Uuid::new_v4().to_string(),
        sent_at: Utc::now(),
        node: node_snapshot(config, store)?,
        scan: parts.scan,
        findings: parts.findings,
        incidents: parts.incidents,
        baseline_drifts: parts.baseline_drifts,
        active_blocks: parts.active_blocks,
        probe_sources: parts.probe_sources,
    })
}

fn node_snapshot(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<PanelNodeSnapshot> {
    let node_name = panel_node_name(config);
    let mut metrics = collect_node_metrics(store).ok();
    if let Some(metrics) = metrics.as_mut() {
        apply_configured_node_location(config, metrics);
    }
    Ok(PanelNodeSnapshot {
        node_id: node_name.clone(),
        node_name,
        host_id: String::new(),
        hostname: String::new(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        privacy_mode: config.panel.privacy_mode.clone(),
        enabled_features: enabled_features(config),
        storage: store.stats().ok(),
        metrics,
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
                .map(|payload| sanitize_panel_envelope(config, payload))
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
    let body = panel_transport_body(payload)?;
    if body.len() > config.panel.max_payload_bytes {
        return Err(SentinelError::Notify(format!(
            "panel payload exceeds panel.max_payload_bytes: {} > {}",
            body.len(),
            config.panel.max_payload_bytes
        )));
    }
    let node_name = payload.node.node_name.trim();
    if node_name.is_empty() {
        return Err(SentinelError::Notify(
            "panel node_name cannot be empty".to_string(),
        ));
    }
    let signed = sign_request(
        "POST",
        PANEL_INGEST_PATH,
        &body,
        &config.panel.secret,
        node_name,
    )?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.panel.request_timeout_seconds))
        .build()
        .map_err(|err| SentinelError::Notify(err.to_string()))?;
    let response = client
        .post(config.panel.url.trim())
        .header("content-type", "application/json")
        .header(
            reqwest::header::USER_AGENT,
            format!("vps-sentinel-agent/{}", env!("CARGO_PKG_VERSION")),
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .header("x-vps-sentinel-payload-encoding", PANEL_TRANSPORT_ENCODING)
        .header("x-vps-sentinel-node-name", node_name)
        .header("x-vps-sentinel-timestamp", signed.timestamp.to_string())
        .header("x-vps-sentinel-nonce", signed.nonce)
        .header("x-vps-sentinel-body-sha256", signed.body_hash)
        .header("x-vps-sentinel-signature", signed.signature)
        .body(body)
        .send()
        .await
        .map_err(|err| SentinelError::Notify(err.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let detail = panel_error_detail(&body);
        return Err(SentinelError::Notify(format!(
            "panel returned HTTP {}{}",
            status, detail
        )));
    }
    debug!("panel payload delivered");
    Ok(())
}

fn panel_error_detail(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return String::new();
    };
    let detail = value
        .get("detail")
        .and_then(|item| item.as_str())
        .or_else(|| value.get("error").and_then(|item| item.as_str()))
        .unwrap_or("")
        .trim();
    if detail.is_empty() {
        String::new()
    } else {
        format!(" ({detail})")
    }
}

fn sign_request(
    method: &str,
    path: &str,
    body: &[u8],
    secret: &str,
    node_name: &str,
) -> SentinelResult<SignedRequest> {
    let timestamp = Utc::now().timestamp();
    let nonce = panel_header_nonce(node_name, &Uuid::new_v4().to_string());
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
    let payload = sanitize_panel_envelope(config, payload);
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

fn panel_active_block(config: &SentinelConfig, block: BlockEntry) -> PanelActiveBlock {
    PanelActiveBlock {
        ip: block.ip,
        rule_id: block.rule_id,
        finding_id: block.finding_id,
        reason: redact_text(config, &block.reason),
        backend: block.backend,
        blocked_at: block.blocked_at,
        expires_at: block.expires_at,
        expired: block.expired,
        firewall_present: block.firewall_present,
    }
}

#[derive(Debug)]
struct ProbeSourceAggregate {
    ip: IpAddr,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    seen_count: usize,
    categories: BTreeSet<String>,
    rule_ids: BTreeSet<String>,
    latest_reason: String,
    block_status: String,
    block_reason: String,
}

fn panel_probe_sources(
    config: &SentinelConfig,
    findings: &[Finding],
    blocks: &[BlockEntry],
) -> Vec<PanelProbeSource> {
    let mut sources = BTreeMap::<IpAddr, ProbeSourceAggregate>::new();
    for finding in findings {
        let Some(ip) = finding_source_ip(finding) else {
            continue;
        };
        if !is_public_remote_ip(ip) {
            continue;
        }
        let request_count = evidence_value(&finding.evidence, "request_count")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let source = sources.entry(ip).or_insert_with(|| ProbeSourceAggregate {
            ip,
            first_seen: finding.timestamp,
            last_seen: finding.timestamp,
            seen_count: 0,
            categories: BTreeSet::new(),
            rule_ids: BTreeSet::new(),
            latest_reason: String::new(),
            block_status: "observed".to_string(),
            block_reason: String::new(),
        });
        if finding.timestamp < source.first_seen {
            source.first_seen = finding.timestamp;
        }
        if finding.timestamp >= source.last_seen {
            source.last_seen = finding.timestamp;
            source.latest_reason = probe_source_reason(finding);
        }
        source.seen_count = source.seen_count.saturating_add(request_count);
        source.categories.insert(finding.category.to_string());
        source.rule_ids.insert(finding.rule_id.clone());
    }

    for block in blocks {
        let Ok(ip) = block.ip.parse::<IpAddr>() else {
            continue;
        };
        if !is_public_remote_ip(ip) {
            continue;
        }
        let source = sources.entry(ip).or_insert_with(|| ProbeSourceAggregate {
            ip,
            first_seen: block.blocked_at,
            last_seen: block.blocked_at,
            seen_count: 1,
            categories: BTreeSet::new(),
            rule_ids: BTreeSet::new(),
            latest_reason: redact_text(config, &block.reason),
            block_status: String::new(),
            block_reason: String::new(),
        });
        source.rule_ids.insert(block.rule_id.clone());
        if block.blocked_at < source.first_seen {
            source.first_seen = block.blocked_at;
        }
        if block.blocked_at > source.last_seen {
            source.last_seen = block.blocked_at;
        }
        source.block_status = if block.expires_at.is_none() {
            "permanent_block".to_string()
        } else if block.expired {
            "expired".to_string()
        } else {
            "blocked".to_string()
        };
        source.block_reason = redact_text(config, &block.reason);
    }

    let mut ip_intel_catalog = IpIntelCatalog::load(config);
    ip_intel_catalog.extend_remote(config, sources.keys().copied());

    let mut items = sources
        .into_values()
        .map(|source| {
            let intel = ip_intel(source.ip, &ip_intel_catalog);
            PanelProbeSource {
                source_ip: source.ip.to_string(),
                ip_version: intel.ip_version,
                network_prefix: intel.network_prefix,
                country: intel.country,
                asn: intel.asn,
                organization: intel.organization,
                first_seen: source.first_seen,
                last_seen: source.last_seen,
                seen_count: source.seen_count,
                categories: source.categories.into_iter().collect(),
                rule_ids: source.rule_ids.into_iter().collect(),
                latest_reason: redact_text(config, &source.latest_reason),
                block_status: if source.block_status.is_empty() {
                    "observed".to_string()
                } else {
                    source.block_status
                },
                block_reason: redact_text(config, &source.block_reason),
            }
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .last_seen
            .cmp(&left.last_seen)
            .then_with(|| right.seen_count.cmp(&left.seen_count))
    });
    items.truncate(config.panel.batch_size);
    items
}

struct ProbeIpIntel {
    ip_version: String,
    network_prefix: String,
    country: String,
    asn: String,
    organization: String,
}

fn ip_intel(ip: IpAddr, catalog: &IpIntelCatalog) -> ProbeIpIntel {
    let mut intel = ProbeIpIntel {
        ip_version: match ip {
            IpAddr::V4(_) => "ipv4".to_string(),
            IpAddr::V6(_) => "ipv6".to_string(),
        },
        network_prefix: network_prefix(ip),
        country: "unknown".to_string(),
        asn: "unknown".to_string(),
        organization: "unknown".to_string(),
    };
    if let Some(match_result) = catalog.lookup(ip) {
        intel.country = match_result.country.clone();
        intel.asn = match_result.asn.clone();
        intel.organization = match_result.organization.clone();
    }
    intel
}

#[derive(Debug, Default)]
struct IpIntelCatalog {
    entries: Vec<IpIntelEntry>,
}

impl IpIntelCatalog {
    fn load(config: &SentinelConfig) -> Self {
        let mut entries = Vec::new();
        for path in &config.panel.ip_intel_paths {
            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            for line in content.lines() {
                if entries.len() >= config.panel.ip_intel_max_entries {
                    return Self::new(entries);
                }
                if let Some(entry) = parse_ip_intel_line(line) {
                    entries.push(entry);
                }
            }
        }
        Self::new(entries)
    }

    fn new(mut entries: Vec<IpIntelEntry>) -> Self {
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.prefix));
        Self { entries }
    }

    fn extend_remote(&mut self, config: &SentinelConfig, ips: impl Iterator<Item = IpAddr>) {
        if !config.panel.ip_intel_remote_enabled {
            return;
        }
        let lookup_ips = ips
            .filter(|ip| self.lookup(*ip).is_none())
            .take(config.panel.ip_intel_remote_max_lookups)
            .collect::<Vec<_>>();
        if lookup_ips.is_empty() {
            return;
        }
        match query_cymru_ip_intel(config, &lookup_ips) {
            Ok(mut remote_entries) => {
                if remote_entries.is_empty() {
                    return;
                }
                let remaining = config
                    .panel
                    .ip_intel_max_entries
                    .saturating_sub(self.entries.len());
                remote_entries.truncate(remaining);
                self.entries.extend(remote_entries);
                self.entries
                    .sort_by_key(|entry| std::cmp::Reverse(entry.prefix));
            }
            Err(err) => {
                debug!(error = %err, "remote IP intelligence lookup failed");
            }
        }
    }

    fn lookup(&self, ip: IpAddr) -> Option<&IpIntelEntry> {
        self.entries
            .iter()
            .find(|entry| ip_in_cidr(ip, entry.network, entry.prefix))
    }
}

#[derive(Debug)]
struct IpIntelEntry {
    network: IpAddr,
    prefix: u8,
    country: String,
    asn: String,
    organization: String,
}

fn query_cymru_ip_intel(
    config: &SentinelConfig,
    ips: &[IpAddr],
) -> SentinelResult<Vec<IpIntelEntry>> {
    let timeout = Duration::from_millis(config.panel.ip_intel_remote_timeout_ms);
    let endpoint = config.panel.ip_intel_remote_endpoint.trim();
    let mut addrs = endpoint
        .to_socket_addrs()
        .map_err(|err| SentinelError::Command(format!("resolve {endpoint}: {err}")))?;
    let addr = addrs
        .next()
        .ok_or_else(|| SentinelError::Command(format!("resolve {endpoint}: no address")))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|err| SentinelError::Command(format!("connect {endpoint}: {err}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| SentinelError::Command(format!("set read timeout: {err}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| SentinelError::Command(format!("set write timeout: {err}")))?;
    let mut request = String::from("begin\nverbose\n");
    for ip in ips {
        request.push_str(&ip.to_string());
        request.push('\n');
    }
    request.push_str("end\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|err| SentinelError::Command(format!("write whois request: {err}")))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| SentinelError::Command(format!("read whois response: {err}")))?;
    Ok(response
        .lines()
        .filter_map(parse_cymru_ip_intel_line)
        .collect())
}

fn parse_cymru_ip_intel_line(line: &str) -> Option<IpIntelEntry> {
    let fields = line.split('|').map(str::trim).collect::<Vec<_>>();
    if fields.len() < 7 || fields[0].eq_ignore_ascii_case("as") {
        return None;
    }
    let asn = clean_cymru_asn(fields[0]);
    let country = clean_ip_intel_field(fields[3]);
    let organization = clean_ip_intel_field(fields[6]);
    let (network, prefix) = parse_cidr(fields[2]).or_else(|| {
        fields[1]
            .parse::<IpAddr>()
            .ok()
            .map(|ip| (ip, if ip.is_ipv4() { 32 } else { 128 }))
    })?;
    Some(IpIntelEntry {
        network,
        prefix,
        country,
        asn,
        organization,
    })
}

fn clean_cymru_asn(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("na") {
        return "unknown".to_string();
    }
    if value.to_ascii_uppercase().starts_with("AS") {
        clean_ip_intel_field(value)
    } else {
        format!("AS{}", clean_ip_intel_field(value))
    }
}

fn parse_ip_intel_line(line: &str) -> Option<IpIntelEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let fields = split_csv_line(line);
    if fields.len() < 4 || fields[0].eq_ignore_ascii_case("cidr") {
        return None;
    }
    let (network, prefix) = parse_cidr(fields.first()?)?;
    Some(IpIntelEntry {
        network,
        prefix,
        country: clean_ip_intel_field(fields.get(1)?),
        asn: clean_ip_intel_field(fields.get(2)?),
        organization: clean_ip_intel_field(fields.get(3)?),
    })
}

fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (network, prefix) = value.trim().split_once('/')?;
    let network = network.trim().parse::<IpAddr>().ok()?;
    let prefix = prefix.trim().parse::<u8>().ok()?;
    let max_prefix = match network {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    (prefix <= max_prefix).then_some((network, prefix))
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

fn clean_ip_intel_field(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "unknown".to_string()
    } else {
        truncate_panel_value(&remove_ips_in_text(value))
    }
}

fn network_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(value) => ipv4_network_prefix(value),
        IpAddr::V6(value) => ipv6_network_prefix(value),
    }
}

fn ipv4_network_prefix(value: Ipv4Addr) -> String {
    let octets = value.octets();
    format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
}

fn ipv6_network_prefix(value: Ipv6Addr) -> String {
    let segments = value.segments();
    format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
}

fn finding_source_ip(finding: &Finding) -> Option<IpAddr> {
    for key in [
        "source_ip",
        "ip",
        "remote_ip",
        "remote_addr",
        "active_response_ip",
    ] {
        let Some(value) = evidence_value(&finding.evidence, key) else {
            continue;
        };
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    finding.subject.parse::<IpAddr>().ok()
}

fn probe_source_reason(finding: &Finding) -> String {
    let family = evidence_value(&finding.evidence, "probe_family");
    let response = evidence_value(&finding.evidence, "response_profile");
    let failures = evidence_value(&finding.evidence, "failure_count");
    if let Some(family) = family {
        return format!(
            "web_probe family={} response={} count={}",
            family,
            response.unwrap_or("unknown"),
            evidence_value(&finding.evidence, "request_count").unwrap_or("1")
        );
    }
    if let Some(failures) = failures {
        return format!("ssh_bruteforce failure_count={failures}");
    }
    if let Some(id) = evidence_value(&finding.evidence, "attack_fingerprint_id") {
        return format!("attack_fingerprint id={id}");
    }
    finding.rule_id.clone()
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

fn panel_incident(config: &SentinelConfig, incident: &Incident) -> PanelIncident {
    PanelIncident {
        id: incident.id.clone(),
        title: redact_text(config, &incident.title),
        severity: incident.severity,
        score: incident.score,
        first_seen: incident.first_seen,
        last_seen: incident.last_seen,
        summary: redact_text(config, &incident.summary),
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
                category: finding.category.clone(),
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
        category: finding.category.to_string(),
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
        category: event.field("category").unwrap_or("system").to_string(),
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
        if payload.probe_sources.len() > 1 {
            payload
                .probe_sources
                .truncate(payload.probe_sources.len() / 2);
            continue;
        }
        validate_payload_size(config, &payload)?;
    }
}

fn validate_payload_size(config: &SentinelConfig, payload: &PanelEnvelope) -> SentinelResult<()> {
    let size = panel_transport_body_len(payload)?;
    if size > config.panel.max_payload_bytes {
        return Err(SentinelError::Notify(format!(
            "panel payload is too large: {size} > {} bytes",
            config.panel.max_payload_bytes
        )));
    }
    Ok(())
}

fn panel_transport_body(payload: &PanelEnvelope) -> SentinelResult<Vec<u8>> {
    let raw = serde_json::to_vec(payload).map_err(|err| SentinelError::Notify(err.to_string()))?;
    let body = PanelTransportBody {
        encoding: PANEL_TRANSPORT_ENCODING,
        payload: BASE64_STANDARD.encode(raw),
    };
    serde_json::to_vec(&body).map_err(|err| SentinelError::Notify(err.to_string()))
}

fn panel_transport_body_len(payload: &PanelEnvelope) -> SentinelResult<usize> {
    panel_transport_body(payload).map(|body| body.len())
}

fn sanitize_panel_envelope(config: &SentinelConfig, mut payload: PanelEnvelope) -> PanelEnvelope {
    let node_name = panel_node_name(config);
    payload.schema_version = PANEL_SCHEMA_VERSION;
    payload.node.node_id = node_name.clone();
    payload.node.node_name = node_name;
    payload.node.host_id.clear();
    payload.node.hostname.clear();
    payload.node.agent_version = env!("CARGO_PKG_VERSION").to_string();
    payload.node.privacy_mode = config.panel.privacy_mode.clone();
    payload.node.enabled_features = enabled_features(config);
    if let Some(metrics) = payload.node.metrics.as_mut() {
        apply_configured_node_location(config, metrics);
    }

    for finding in &mut payload.findings {
        sanitize_panel_finding(config, finding);
    }
    for incident in &mut payload.incidents {
        sanitize_panel_incident(config, incident);
    }
    for drift in &mut payload.baseline_drifts {
        sanitize_panel_baseline_drift(config, drift);
    }
    for block in &mut payload.active_blocks {
        sanitize_panel_active_block(config, block);
    }
    for source in &mut payload.probe_sources {
        sanitize_panel_probe_source(config, source);
    }

    payload
}

fn sanitize_panel_finding(config: &SentinelConfig, finding: &mut PanelFinding) {
    finding.title = redact_text(config, &finding.title);
    finding.subject = redact_subject(config, &finding.subject);
    finding.dedup_key = redact_text(config, &finding.dedup_key);
    finding.evidence = panel_evidence(config, &finding.evidence);
    finding.impact = finding
        .impact
        .iter()
        .map(|item| redact_text(config, item))
        .collect();
    finding.recommendations = finding
        .recommendations
        .iter()
        .map(|item| redact_text(config, item))
        .collect();
}

fn sanitize_panel_incident(config: &SentinelConfig, incident: &mut PanelIncident) {
    incident.title = redact_text(config, &incident.title);
    incident.summary = redact_text(config, &incident.summary);
}

fn sanitize_panel_baseline_drift(config: &SentinelConfig, drift: &mut PanelBaselineDrift) {
    drift.subject = redact_subject(config, &drift.subject);
    drift.review_action = redact_text(config, &drift.review_action);
    drift.reasons = drift
        .reasons
        .iter()
        .map(|item| redact_text(config, item))
        .collect();
}

fn sanitize_panel_active_block(config: &SentinelConfig, block: &mut PanelActiveBlock) {
    block.reason = redact_text(config, &block.reason);
    block.backend = redact_text(config, &block.backend);
}

fn sanitize_panel_probe_source(config: &SentinelConfig, source: &mut PanelProbeSource) {
    source.latest_reason = redact_text(config, &source.latest_reason);
    source.block_reason = redact_text(config, &source.block_reason);
    source.organization = truncate_panel_value(&redact_text(config, &source.organization));
}

fn panel_node_name(config: &SentinelConfig) -> String {
    for candidate in [
        config.panel.node_name.trim(),
        config.agent.display_name.trim(),
        config.fleet.node_name.trim(),
    ] {
        if let Some(name) = safe_node_name(candidate) {
            return name;
        }
    }
    "unnamed-node".to_string()
}

fn safe_node_name(value: &str) -> Option<String> {
    let sanitized = remove_ips_in_text(value).trim().to_string();
    if sanitized.is_empty() || sanitized == "redacted" || sanitized.contains("redacted") {
        return None;
    }
    Some(truncate_node_name(&sanitized))
}

fn truncate_node_name(value: &str) -> String {
    const MAX_NODE_NAME_BYTES: usize = 96;
    if value.len() <= MAX_NODE_NAME_BYTES {
        return value.to_string();
    }
    let mut end = MAX_NODE_NAME_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn apply_configured_node_location(config: &SentinelConfig, metrics: &mut NodeMetrics) {
    let location = &config.panel.location;
    metrics.country_code = normalize_country_code(&location.country_code);
    metrics.country = safe_location_value(&location.country);
    metrics.region = safe_location_value(&location.region);
    metrics.city = safe_location_value(&location.city);
}

fn normalize_country_code(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() == 2 && trimmed.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Some(trimmed.to_ascii_uppercase());
    }
    None
}

fn safe_location_value(value: &str) -> Option<String> {
    let cleaned = remove_ips_in_text(value).trim().to_string();
    if cleaned.is_empty() || cleaned == "redacted" || cleaned.contains("redacted") {
        return None;
    }
    Some(truncate_location_value(&cleaned))
}

fn truncate_location_value(value: &str) -> String {
    const MAX_LOCATION_BYTES: usize = 96;
    if value.len() <= MAX_LOCATION_BYTES {
        return value.to_string();
    }
    let mut end = MAX_LOCATION_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
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
    redact_text(config, value)
}

fn redact_text(_config: &SentinelConfig, value: &str) -> String {
    remove_ips_in_text(value)
}

fn redact_evidence_value(config: &SentinelConfig, key: &str, value: &str) -> String {
    let normalized_key = key.to_ascii_lowercase();
    let mut redacted = if normalized_key.contains("ip") || normalized_key.contains("addr") {
        remove_ip(value)
    } else {
        remove_ips_in_text(value)
    };
    if config.panel.privacy_mode == "strict"
        && (normalized_key.contains("command") || normalized_key == "cmdline")
    {
        redacted = mask_command_args(&redacted);
    }
    redacted
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
        enqueue_payload, panel_envelope, panel_transport_body, sanitize_panel_envelope,
        sign_request, summary_from_state, PanelActiveBlock, PanelBaselineDrift, PanelEnvelopeParts,
        PanelFinding, PanelIncident, PanelOutboxState, PanelScanSummary, PANEL_TRANSPORT_ENCODING,
    };
    use crate::active_response::BlockEntry;
    use crate::storage::SqliteStore;
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use chrono::{Duration as ChronoDuration, Utc};
    use sentinel_core::panel_auth::{panel_signature_hex, PANEL_INGEST_METHOD, PANEL_INGEST_PATH};
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};
    use std::collections::BTreeMap;
    use std::net::IpAddr;

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
    fn panel_transport_body_hides_attack_text_until_decoded(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.panel.node_name = "node-a".to_string();
        let payload = panel_envelope(
            &config,
            &store,
            PanelEnvelopeParts {
                scan: PanelScanSummary {
                    finished_at: Utc::now(),
                    raw_events: 0,
                    diff_events: 0,
                    findings: 1,
                    incidents: 0,
                    suppressed_duplicates: 0,
                    maintenance_suppressed: 0,
                    active_response_applied: 0,
                    active_response_failed: 0,
                    collector_errors: 0,
                    event_count_by_source: BTreeMap::new(),
                },
                findings: vec![PanelFinding {
                    id: "finding-1".to_string(),
                    rule_id: "WEB-001".to_string(),
                    title: "command_injection probe".to_string(),
                    severity: Severity::High,
                    confidence: "high".to_string(),
                    category: "web".to_string(),
                    subject: "redacted".to_string(),
                    timestamp: Utc::now(),
                    dedup_key: "dedup".to_string(),
                    evidence: Vec::new(),
                    impact: Vec::new(),
                    recommendations: Vec::new(),
                }],
                incidents: Vec::new(),
                baseline_drifts: Vec::new(),
                active_blocks: Vec::new(),
                probe_sources: Vec::new(),
            },
        )?;

        let body = panel_transport_body(&payload)?;
        let text = String::from_utf8(body)?;
        assert!(!text.contains("command_injection"));
        let wrapper: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(wrapper["encoding"], PANEL_TRANSPORT_ENCODING);
        let decoded = BASE64_STANDARD.decode(wrapper["payload"].as_str().unwrap())?;
        let decoded_payload: serde_json::Value = serde_json::from_slice(&decoded)?;
        assert_eq!(
            decoded_payload["findings"][0]["title"],
            "command_injection probe"
        );
        Ok(())
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
            PanelEnvelopeParts {
                scan,
                findings: Vec::new(),
                incidents: Vec::new(),
                baseline_drifts: Vec::new(),
                active_blocks: Vec::new(),
                probe_sources: Vec::new(),
            },
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

        assert_eq!(panel.subject, "root@redacted");
        assert_eq!(panel.evidence[0].value, "redacted");
        assert_eq!(panel.evidence[1].value, "/bin/bash [args masked]");
    }

    #[test]
    fn strict_panel_identity_is_privacy_safe() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.panel.privacy_mode = "strict".to_string();
        config.agent.hostname = "203.0.113.10".to_string();
        config.agent.host_id = String::new();
        config.agent.display_name = String::new();
        config.panel.node_id = String::new();
        config.panel.node_name = String::new();
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
            PanelEnvelopeParts {
                scan,
                findings: Vec::new(),
                incidents: Vec::new(),
                baseline_drifts: Vec::new(),
                active_blocks: Vec::new(),
                probe_sources: Vec::new(),
            },
        )?;
        let json = serde_json::to_string(&payload.node)?;

        assert_eq!(payload.schema_version, 2);
        assert_eq!(payload.node.node_name, "unnamed-node");
        assert_eq!(payload.node.node_id, "unnamed-node");
        assert!(payload.node.host_id.is_empty());
        assert!(payload.node.hostname.is_empty());
        assert!(!json.contains("203.0.113"));
        assert!(!json.contains("node_id"));
        assert!(!json.contains("host_id"));
        assert!(!json.contains("hostname"));
        Ok(())
    }

    #[test]
    fn panel_node_location_uses_explicit_non_sensitive_config(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.panel.node_name = "apernet-sg".to_string();
        config.panel.location.country_code = "sg".to_string();
        config.panel.location.country = "Singapore".to_string();
        config.panel.location.city = "Singapore".to_string();

        let payload = panel_envelope(
            &config,
            &store,
            PanelEnvelopeParts {
                scan: PanelScanSummary {
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
                },
                findings: Vec::new(),
                incidents: Vec::new(),
                baseline_drifts: Vec::new(),
                active_blocks: Vec::new(),
                probe_sources: Vec::new(),
            },
        )?;
        let metrics = payload.node.metrics.as_ref().expect("node metrics");
        assert_eq!(metrics.country_code.as_deref(), Some("SG"));
        assert_eq!(metrics.country.as_deref(), Some("Singapore"));
        assert_eq!(metrics.city.as_deref(), Some("Singapore"));

        let mut tampered = payload.clone();
        let metrics = tampered.node.metrics.as_mut().expect("node metrics");
        metrics.country_code = Some("US".to_string());
        metrics.country = Some("203.0.113.10".to_string());
        let sanitized = sanitize_panel_envelope(&config, tampered);
        let metrics = sanitized.node.metrics.as_ref().expect("node metrics");
        assert_eq!(metrics.country_code.as_deref(), Some("SG"));
        assert_eq!(metrics.country.as_deref(), Some("Singapore"));
        Ok(())
    }

    #[test]
    fn legacy_panel_outbox_payload_is_sanitized() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.panel.privacy_mode = "strict".to_string();
        config.agent.hostname = "203.0.113.20".to_string();
        config.agent.host_id = String::new();
        config.agent.display_name = String::new();
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
        let mut payload = panel_envelope(
            &config,
            &store,
            PanelEnvelopeParts {
                scan,
                findings: Vec::new(),
                incidents: Vec::new(),
                baseline_drifts: Vec::new(),
                active_blocks: Vec::new(),
                probe_sources: Vec::new(),
            },
        )?;
        payload.node.node_id = "203.0.113.20".to_string();
        payload.node.node_name = "203.0.113.20".to_string();
        payload.node.host_id = "203.0.113.20".to_string();
        payload.node.hostname = "203.0.113.20".to_string();
        payload.findings.push(PanelFinding {
            id: "finding-1".to_string(),
            rule_id: "SSH-001".to_string(),
            title: "source 198.51.100.8 attempted login".to_string(),
            severity: Severity::High,
            confidence: "high".to_string(),
            category: "ssh".to_string(),
            subject: "root@198.51.100.8".to_string(),
            timestamp: Utc::now(),
            dedup_key: "ssh:198.51.100.8".to_string(),
            evidence: vec![
                Evidence::new("source_ip", "198.51.100.8"),
                Evidence::new("command_line", "/bin/bash -c curl 198.51.100.8"),
            ],
            impact: vec!["remote 198.51.100.8 may be probing SSH".to_string()],
            recommendations: vec!["review traffic from 198.51.100.8".to_string()],
        });
        payload.incidents.push(PanelIncident {
            id: "incident-1".to_string(),
            title: "incident from 198.51.100.8".to_string(),
            severity: Severity::High,
            score: 90,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            summary: "198.51.100.8 correlated across events".to_string(),
        });
        payload.baseline_drifts.push(PanelBaselineDrift {
            finding_id: "finding-2".to_string(),
            rule_id: "SERVICE-001".to_string(),
            category: "network".to_string(),
            severity: Severity::Medium,
            subject: "0.0.0.0:24409/udp".to_string(),
            timestamp: Utc::now(),
            tier: "suspicious".to_string(),
            score: Some(67),
            review_action: "review 198.51.100.8 before refresh".to_string(),
            reasons: vec!["public listener on 0.0.0.0".to_string()],
        });
        payload.active_blocks.push(PanelActiveBlock {
            ip: "198.51.100.8".to_string(),
            rule_id: "SSH-001".to_string(),
            finding_id: "finding-1".to_string(),
            reason: "blocked 198.51.100.8".to_string(),
            backend: "nftables".to_string(),
            blocked_at: Utc::now(),
            expires_at: None,
            expired: false,
            firewall_present: Some(true),
        });

        let sanitized = sanitize_panel_envelope(&config, payload);
        let json = serde_json::to_string(&sanitized)?;

        assert_eq!(sanitized.schema_version, 2);
        assert_eq!(sanitized.node.node_name, "unnamed-node");
        assert_eq!(sanitized.node.node_id, "unnamed-node");
        assert!(sanitized.node.host_id.is_empty());
        assert!(sanitized.node.hostname.is_empty());
        assert!(!json.contains("203.0.113"));
        assert!(!json.contains("0.0.0.0"));
        assert!(!json.contains("node_id"));
        assert!(!json.contains("host_id"));
        assert!(!json.contains("hostname"));
        assert!(!json.contains("/bin/bash -c"));
        assert!(json.contains(r#""ip":"198.51.100.8""#));
        assert!(json.contains("/bin/bash [args masked]"));
        Ok(())
    }

    #[test]
    fn panel_active_blocks_keep_admin_source_ip() {
        let mut config = SentinelConfig::default();
        config.panel.privacy_mode = "strict".to_string();
        let block = BlockEntry {
            ip: "203.0.113.44".to_string(),
            rule_id: "SSH-001".to_string(),
            finding_id: "finding-1".to_string(),
            reason: "blocked 203.0.113.44 after brute-force evidence".to_string(),
            backend: "nftables".to_string(),
            blocked_at: Utc::now(),
            expires_at: None,
            expired: false,
            firewall_present: Some(true),
        };

        let panel = super::panel_active_block(&config, block);
        let json = serde_json::to_string(&panel).expect("panel block json");

        assert!(json.contains("203.0.113.44"));
        assert!(json.contains("\"ip\""));
        assert!(json.contains("redacted"));
    }

    #[test]
    fn panel_probe_sources_aggregate_public_sources() {
        let mut config = SentinelConfig::default();
        let temp = tempfile::tempdir().expect("temp dir");
        let intel_path = temp.path().join("ip-intel.csv");
        std::fs::write(
            &intel_path,
            "cidr,country,asn,organization\n47.242.23.0/24,JP,AS45102,Example Cloud\n47.0.0.0/8,ZZ,AS0,Broad Match\n",
        )
        .expect("write ip intel");
        config.panel.ip_intel_paths = vec![intel_path];
        let now = Utc::now();
        let findings = vec![
            Finding::new(
                "host",
                "web",
                "47.242.23.111",
                Severity::Medium,
                Category::Web,
                "WEB-001",
                "web probe",
            )
            .with_evidence(vec![
                Evidence::new("ip", "47.242.23.111"),
                Evidence::new("probe_family", "env_file"),
                Evidence::new("response_profile", "missing_or_rejected"),
                Evidence::new("request_count", "3"),
            ]),
            Finding::new(
                "host",
                "ssh",
                "47.242.23.111",
                Severity::High,
                Category::Ssh,
                "SSH-003",
                "ssh brute force",
            )
            .with_evidence(vec![
                Evidence::new("source_ip", "47.242.23.111"),
                Evidence::new("failure_count", "8"),
            ]),
            Finding::new(
                "host",
                "ssh",
                "10.0.0.5",
                Severity::High,
                Category::Ssh,
                "SSH-003",
                "private ssh brute force",
            )
            .with_evidence(vec![
                Evidence::new("source_ip", "10.0.0.5"),
                Evidence::new("failure_count", "8"),
            ]),
        ];
        let blocks = vec![BlockEntry {
            ip: "47.242.23.111".to_string(),
            rule_id: "SSH-003".to_string(),
            finding_id: "finding-ssh".to_string(),
            reason: "ssh brute force failure_count=8".to_string(),
            backend: "nftables".to_string(),
            blocked_at: now,
            expires_at: Some(now + ChronoDuration::hours(1)),
            expired: false,
            firewall_present: Some(true),
        }];

        let sources = super::panel_probe_sources(&config, &findings, &blocks);

        assert_eq!(sources.len(), 1);
        let source = &sources[0];
        assert_eq!(source.source_ip, "47.242.23.111");
        assert_eq!(source.network_prefix, "47.242.23.0/24");
        assert_eq!(source.country, "JP");
        assert_eq!(source.asn, "AS45102");
        assert_eq!(source.organization, "Example Cloud");
        assert_eq!(source.seen_count, 4);
        assert_eq!(source.block_status, "blocked");
        assert!(source.rule_ids.contains(&"WEB-001".to_string()));
        assert!(source.rule_ids.contains(&"SSH-003".to_string()));
        assert!(source.latest_reason.contains("ssh_bruteforce"));
        assert!(source.block_reason.contains("failure_count=8"));
    }

    #[test]
    fn parse_cymru_ip_intel_line_builds_cidr_entry() {
        let entry = super::parse_cymru_ip_intel_line(
            "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE, US",
        )
        .expect("cymru line");

        assert_eq!(entry.network, "8.8.8.0".parse::<IpAddr>().expect("ip"));
        assert_eq!(entry.prefix, 24);
        assert_eq!(entry.country, "US");
        assert_eq!(entry.asn, "AS15169");
        assert_eq!(entry.organization, "GOOGLE, US");
    }
}
