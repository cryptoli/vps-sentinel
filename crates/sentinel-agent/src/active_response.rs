use crate::attack_fingerprint::{
    ACTION_HINT_KEY, FINGERPRINT_ID_KEY, VERDICT_BENIGN, VERDICT_MALICIOUS,
};
use crate::detectors::field_is_allowlisted;
use crate::detectors::web_rules::{probe_family_blocks_on_single_attempt, probe_family_is_exploit};
use crate::risk_score::{confidence_percent, unified_score};
use crate::storage::SqliteStore;
use crate::utils::command::command_output;
use crate::utils::ip::is_public_remote_ip;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sentinel_core::{Finding, SentinelConfig, SentinelError, SentinelResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;
use tracing::warn;

const STATE_RULE_ID: &str = "active_response_blocks";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveResponseReport {
    pub planned_blocks: usize,
    pub applied_blocks: usize,
    pub permanent_blocks: usize,
    pub skipped_existing_blocks: usize,
    pub stale_blocks: usize,
    pub failed_blocks: usize,
    pub expired_blocks: usize,
    pub failed_expirations: usize,
    pub failed_state_checks: usize,
    pub block_actions: Vec<BlockAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAction {
    pub finding_id: String,
    pub ip: IpAddr,
    pub status: BlockActionStatus,
    pub reason: String,
    pub backend: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockActionStatus {
    Observed,
    Blocked,
    PermanentlyBlocked,
    AlreadyBlocked,
    AlreadyPermanentlyBlocked,
    Failed,
    SkippedLimit,
}

impl BlockActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Blocked => "blocked",
            Self::PermanentlyBlocked => "permanently_blocked",
            Self::AlreadyBlocked => "already_blocked",
            Self::AlreadyPermanentlyBlocked => "already_permanently_blocked",
            Self::Failed => "failed",
            Self::SkippedLimit => "skipped_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockEntry {
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockMaintenanceReport {
    pub expired_blocks: usize,
    pub stale_blocks: usize,
    pub failed_expirations: usize,
    pub failed_state_checks: usize,
    pub legacy_port_guards_removed: usize,
    pub failed_legacy_port_guard_cleanups: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnblockReport {
    pub requested_blocks: usize,
    pub state_removed: usize,
    pub firewall_removed: usize,
    pub failed_blocks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockCandidate {
    kind: BlockCandidateKind,
    ip: IpAddr,
    rule_id: String,
    finding_id: String,
    reason: String,
    action: ResponseAction,
    ttl_seconds: Option<u64>,
    permanent_after: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockCandidateKind {
    WebProbe,
    WebError,
    WebAggregate,
    SshBruteforce,
    AttackFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseAction {
    Observe,
    Block,
    PermanentBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BlockState {
    blocks: BTreeMap<String, BlockRecord>,
    #[serde(default)]
    trigger_history: BTreeMap<String, TriggerRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockRecord {
    ip: String,
    rule_id: String,
    finding_id: String,
    reason: String,
    backend: String,
    blocked_at: DateTime<Utc>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TriggerRecord {
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    count: usize,
}

trait IpBlocker {
    fn backend_name(&self) -> &'static str;
    fn block_ip(&self, ip: IpAddr, ttl: Option<Duration>) -> SentinelResult<()>;
    fn unblock_ip(&self, ip: IpAddr) -> SentinelResult<bool>;
    fn is_blocked(&self, ip: IpAddr) -> SentinelResult<bool>;
}

pub fn apply_active_response(
    findings: &[Finding],
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<ActiveResponseReport> {
    if !config.active_response.enabled {
        return Ok(ActiveResponseReport::default());
    }
    if active_response_strategy(config) == ActiveResponseStrategy::Observe {
        let candidates = block_candidates(findings, config);
        return Ok(ActiveResponseReport {
            planned_blocks: candidates.len(),
            block_actions: candidates
                .into_iter()
                .map(|candidate| BlockAction {
                    finding_id: candidate.finding_id,
                    ip: candidate.ip,
                    status: BlockActionStatus::Observed,
                    reason: candidate.reason,
                    backend: None,
                    expires_at: None,
                    detail: Some("active_response.strategy=observe".to_string()),
                })
                .collect(),
            ..ActiveResponseReport::default()
        });
    }
    let Some(blocker) = SystemIpBlocker::from_config(config) else {
        let candidates = block_candidates(findings, config);
        let failed_blocks = candidates.len();
        return Ok(ActiveResponseReport {
            failed_blocks,
            block_actions: candidates
                .into_iter()
                .map(|candidate| BlockAction {
                    finding_id: candidate.finding_id,
                    ip: candidate.ip,
                    status: BlockActionStatus::Failed,
                    reason: candidate.reason,
                    backend: None,
                    expires_at: None,
                    detail: Some("firewall backend unavailable".to_string()),
                })
                .collect(),
            ..ActiveResponseReport::default()
        });
    };
    apply_with_blocker(findings, config, store, &blocker)
}

fn apply_with_blocker(
    findings: &[Finding],
    config: &SentinelConfig,
    store: &SqliteStore,
    blocker: &dyn IpBlocker,
) -> SentinelResult<ActiveResponseReport> {
    let now = Utc::now();
    let mut state = store
        .load_rule_state::<BlockState>(STATE_RULE_ID)?
        .unwrap_or_default();
    let maintenance = synchronize_block_state(&mut state, config, now);
    let mut report = ActiveResponseReport {
        expired_blocks: maintenance.expired_blocks,
        stale_blocks: maintenance.stale_blocks,
        failed_expirations: maintenance.failed_expirations,
        failed_state_checks: maintenance.failed_state_checks,
        ..ActiveResponseReport::default()
    };
    let default_ttl = Duration::from_secs(config.active_response.block_ttl_seconds);

    let candidates = block_candidates(findings, config);
    report.planned_blocks = candidates.len();
    let permanent_decisions = permanent_block_decisions(&mut state, &candidates, config, now);
    let mut firewall_write_count = 0usize;
    for candidate in candidates {
        if candidate.action == ResponseAction::Observe {
            report.block_actions.push(BlockAction {
                finding_id: candidate.finding_id,
                ip: candidate.ip,
                status: BlockActionStatus::Observed,
                reason: candidate.reason,
                backend: None,
                expires_at: None,
                detail: Some("response_policy.action=observe".to_string()),
            });
            continue;
        }
        let key = candidate.ip.to_string();
        let permanent_trigger_count = permanent_decisions.get(&key).copied();
        let should_permanent_block =
            candidate.action == ResponseAction::PermanentBlock || permanent_trigger_count.is_some();
        if let Some(existing) = state.blocks.get(&key).cloned() {
            if should_permanent_block && existing.expires_at.is_some() {
                if firewall_write_count >= config.active_response.max_blocks_per_scan {
                    report.block_actions.push(BlockAction {
                        finding_id: candidate.finding_id,
                        ip: candidate.ip,
                        status: BlockActionStatus::SkippedLimit,
                        reason: candidate.reason,
                        backend: Some(existing.backend),
                        expires_at: existing.expires_at,
                        detail: Some("max blocks per scan reached".to_string()),
                    });
                    continue;
                }
                firewall_write_count += 1;
                match promote_ip_to_permanent(blocker, candidate.ip) {
                    Ok(()) => {
                        report.applied_blocks += 1;
                        report.permanent_blocks += 1;
                        report.block_actions.push(BlockAction {
                            finding_id: candidate.finding_id.clone(),
                            ip: candidate.ip,
                            status: BlockActionStatus::PermanentlyBlocked,
                            reason: candidate.reason.clone(),
                            backend: Some(blocker.backend_name().to_string()),
                            expires_at: None,
                            detail: Some(permanent_escalation_detail(
                                permanent_trigger_count.unwrap_or_default(),
                                config,
                            )),
                        });
                        state.blocks.insert(
                            key.clone(),
                            BlockRecord {
                                ip: key.clone(),
                                rule_id: candidate.rule_id,
                                finding_id: candidate.finding_id,
                                reason: candidate.reason,
                                backend: blocker.backend_name().to_string(),
                                blocked_at: existing.blocked_at,
                                expires_at: None,
                            },
                        );
                        state.trigger_history.remove(&key);
                    }
                    Err(err) => {
                        report.failed_blocks += 1;
                        warn!(ip = %candidate.ip, error = %err, "active response permanent block promotion failed");
                        report.block_actions.push(BlockAction {
                            finding_id: candidate.finding_id,
                            ip: candidate.ip,
                            status: BlockActionStatus::Failed,
                            reason: candidate.reason,
                            backend: Some(blocker.backend_name().to_string()),
                            expires_at: existing.expires_at,
                            detail: Some(err.to_string()),
                        });
                    }
                }
                continue;
            }
            report.skipped_existing_blocks += 1;
            if should_permanent_block && existing.expires_at.is_none() {
                state.trigger_history.remove(&key);
            }
            let status = if existing.expires_at.is_none() {
                BlockActionStatus::AlreadyPermanentlyBlocked
            } else {
                BlockActionStatus::AlreadyBlocked
            };
            report.block_actions.push(BlockAction {
                finding_id: candidate.finding_id,
                ip: candidate.ip,
                status,
                reason: candidate.reason,
                backend: Some(existing.backend.clone()),
                expires_at: existing.expires_at,
                detail: None,
            });
            continue;
        }
        if firewall_write_count >= config.active_response.max_blocks_per_scan {
            report.block_actions.push(BlockAction {
                finding_id: candidate.finding_id,
                ip: candidate.ip,
                status: BlockActionStatus::SkippedLimit,
                reason: candidate.reason,
                backend: None,
                expires_at: None,
                detail: Some("max blocks per scan reached".to_string()),
            });
            continue;
        }
        firewall_write_count += 1;
        let ttl = Duration::from_secs(candidate.ttl_seconds.unwrap_or(default_ttl.as_secs()));
        let temporary_expires_at = now + ChronoDuration::seconds(duration_seconds(ttl.as_secs()));
        let block_ttl = if should_permanent_block {
            None
        } else {
            Some(ttl)
        };
        match blocker.block_ip(candidate.ip, block_ttl) {
            Ok(()) => {
                report.applied_blocks += 1;
                if should_permanent_block {
                    report.permanent_blocks += 1;
                }
                let expires_at = if should_permanent_block {
                    None
                } else {
                    Some(temporary_expires_at)
                };
                report.block_actions.push(BlockAction {
                    finding_id: candidate.finding_id.clone(),
                    ip: candidate.ip,
                    status: if should_permanent_block {
                        BlockActionStatus::PermanentlyBlocked
                    } else {
                        BlockActionStatus::Blocked
                    },
                    reason: candidate.reason.clone(),
                    backend: Some(blocker.backend_name().to_string()),
                    expires_at,
                    detail: permanent_trigger_count
                        .map(|count| permanent_escalation_detail(count, config)),
                });
                state.blocks.insert(
                    key.clone(),
                    BlockRecord {
                        ip: key.clone(),
                        rule_id: candidate.rule_id,
                        finding_id: candidate.finding_id,
                        reason: candidate.reason,
                        backend: blocker.backend_name().to_string(),
                        blocked_at: now,
                        expires_at,
                    },
                );
                if should_permanent_block {
                    state.trigger_history.remove(&key);
                }
            }
            Err(err) => {
                report.failed_blocks += 1;
                warn!(ip = %candidate.ip, error = %err, "active response block failed");
                report.block_actions.push(BlockAction {
                    finding_id: candidate.finding_id,
                    ip: candidate.ip,
                    status: BlockActionStatus::Failed,
                    reason: candidate.reason,
                    backend: Some(blocker.backend_name().to_string()),
                    expires_at: None,
                    detail: Some(err.to_string()),
                });
            }
        }
    }
    store.save_rule_state(STATE_RULE_ID, &state)?;
    Ok(report)
}

fn promote_ip_to_permanent(blocker: &dyn IpBlocker, ip: IpAddr) -> SentinelResult<()> {
    let _ = blocker.unblock_ip(ip)?;
    blocker.block_ip(ip, None)
}

fn permanent_block_decisions(
    state: &mut BlockState,
    candidates: &[BlockCandidate],
    config: &SentinelConfig,
    now: DateTime<Utc>,
) -> BTreeMap<String, usize> {
    prune_trigger_history(state, config, now);
    let mut decisions = BTreeMap::new();
    if !config.active_response.permanent_block_enabled {
        return decisions;
    }
    let window = permanent_block_window(config);
    for candidate in candidates {
        if candidate.action == ResponseAction::Observe {
            continue;
        }
        let key = candidate.ip.to_string();
        let threshold = candidate
            .permanent_after
            .unwrap_or(config.active_response.permanent_block_threshold);
        let record = state
            .trigger_history
            .entry(key.clone())
            .or_insert_with(|| TriggerRecord {
                first_seen_at: now,
                last_seen_at: now,
                count: 0,
            });
        let age = now.signed_duration_since(record.first_seen_at);
        if age < ChronoDuration::zero() || age > window {
            record.first_seen_at = now;
            record.count = 0;
        }
        record.last_seen_at = now;
        record.count = record.count.saturating_add(1);
        if record.count >= threshold {
            decisions.insert(key, record.count);
        }
    }
    decisions
}

fn prune_trigger_history(state: &mut BlockState, config: &SentinelConfig, now: DateTime<Utc>) {
    let retention = ChronoDuration::seconds(duration_seconds(
        config
            .active_response
            .permanent_block_window_seconds
            .saturating_mul(2),
    ));
    state.trigger_history.retain(|_, record| {
        let age = now.signed_duration_since(record.last_seen_at);
        age >= ChronoDuration::zero() && age <= retention
    });
}

fn permanent_block_window(config: &SentinelConfig) -> ChronoDuration {
    ChronoDuration::seconds(duration_seconds(
        config.active_response.permanent_block_window_seconds,
    ))
}

fn permanent_escalation_detail(trigger_count: usize, config: &SentinelConfig) -> String {
    format!(
        "permanent_escalation trigger_count={trigger_count} window_seconds={}",
        config.active_response.permanent_block_window_seconds
    )
}

pub fn list_active_blocks(
    config: &SentinelConfig,
    store: &SqliteStore,
    verify_firewall: bool,
) -> SentinelResult<Vec<BlockEntry>> {
    let now = Utc::now();
    let state = store
        .load_rule_state::<BlockState>(STATE_RULE_ID)?
        .unwrap_or_default();
    let mut entries = state
        .blocks
        .values()
        .map(|record| {
            let firewall_present = if verify_firewall {
                record_firewall_present(config, record)
            } else {
                None
            };
            BlockEntry {
                ip: record.ip.clone(),
                rule_id: record.rule_id.clone(),
                finding_id: record.finding_id.clone(),
                reason: record.reason.clone(),
                backend: record.backend.clone(),
                blocked_at: record.blocked_at,
                expires_at: record.expires_at,
                expired: record
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= now),
                firewall_present,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.ip.cmp(&right.ip));
    Ok(entries)
}

pub fn cleanup_active_blocks(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<BlockMaintenanceReport> {
    let mut state = store
        .load_rule_state::<BlockState>(STATE_RULE_ID)?
        .unwrap_or_default();
    let report = synchronize_block_state(&mut state, config, Utc::now());
    store.save_rule_state(STATE_RULE_ID, &state)?;
    Ok(report)
}

pub fn unblock_active_ip(
    config: &SentinelConfig,
    store: &SqliteStore,
    ip: IpAddr,
) -> SentinelResult<UnblockReport> {
    let mut state = store
        .load_rule_state::<BlockState>(STATE_RULE_ID)?
        .unwrap_or_default();
    let mut report = UnblockReport {
        requested_blocks: 1,
        ..UnblockReport::default()
    };
    report.firewall_removed += unblock_ip_from_available_backends(config, ip)?;
    if state.blocks.remove(&ip.to_string()).is_some() {
        report.state_removed += 1;
    }
    state.trigger_history.remove(&ip.to_string());
    store.save_rule_state(STATE_RULE_ID, &state)?;
    Ok(report)
}

pub fn unblock_all_active_blocks(
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<UnblockReport> {
    let mut state = store
        .load_rule_state::<BlockState>(STATE_RULE_ID)?
        .unwrap_or_default();
    let ips = state
        .blocks
        .keys()
        .filter_map(|ip| ip.parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    let mut report = UnblockReport {
        requested_blocks: ips.len(),
        ..UnblockReport::default()
    };
    for ip in ips {
        match unblock_ip_from_available_backends(config, ip) {
            Ok(removed) => {
                report.firewall_removed += removed;
                if state.blocks.remove(&ip.to_string()).is_some() {
                    report.state_removed += 1;
                }
                state.trigger_history.remove(&ip.to_string());
            }
            Err(err) => {
                report.failed_blocks += 1;
                warn!(ip = %ip, error = %err, "active response manual unblock failed");
            }
        }
    }
    store.save_rule_state(STATE_RULE_ID, &state)?;
    Ok(report)
}

fn synchronize_block_state(
    state: &mut BlockState,
    config: &SentinelConfig,
    now: DateTime<Utc>,
) -> BlockMaintenanceReport {
    let mut report = BlockMaintenanceReport::default();
    if config.active_response.cleanup_legacy_port_guards {
        let legacy = cleanup_legacy_port_guards(config);
        report.legacy_port_guards_removed = legacy.removed;
        report.failed_legacy_port_guard_cleanups = legacy.failed;
    }
    let expired = state
        .blocks
        .iter()
        .filter(|(_, record)| {
            record
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
        })
        .filter_map(|(ip, record)| {
            let parsed = record.ip.parse::<IpAddr>().ok()?;
            Some((ip.clone(), parsed, record.backend.clone()))
        })
        .collect::<Vec<_>>();

    for (key, ip, backend) in expired {
        let Some(blocker) = SystemIpBlocker::from_backend_name(config, &backend) else {
            report.failed_expirations += 1;
            warn!(ip = %ip, backend = backend, "active response unblock skipped because backend is unavailable");
            continue;
        };
        match blocker.unblock_ip(ip) {
            Ok(_) => {
                report.expired_blocks += 1;
                state.blocks.remove(&key);
            }
            Err(err) => {
                report.failed_expirations += 1;
                warn!(ip = %ip, error = %err, "active response unblock failed");
            }
        }
    }

    let current = state
        .blocks
        .iter()
        .filter_map(|(key, record)| {
            let parsed = record.ip.parse::<IpAddr>().ok()?;
            Some((key.clone(), parsed, record.backend.clone()))
        })
        .collect::<Vec<_>>();

    for (key, ip, backend) in current {
        let Some(blocker) = SystemIpBlocker::from_backend_name(config, &backend) else {
            report.failed_state_checks += 1;
            continue;
        };
        match blocker.is_blocked(ip) {
            Ok(true) => {}
            Ok(false) => {
                report.stale_blocks += 1;
                state.blocks.remove(&key);
            }
            Err(err) => {
                report.failed_state_checks += 1;
                warn!(ip = %ip, backend = backend, error = %err, "active response state check failed");
            }
        }
    }
    report
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LegacyPortGuardCleanupReport {
    removed: usize,
    failed: usize,
}

fn cleanup_legacy_port_guards(config: &SentinelConfig) -> LegacyPortGuardCleanupReport {
    let timeout = Duration::from_secs(config.active_response.command_timeout_seconds);
    let mut report = LegacyPortGuardCleanupReport::default();
    let nft = cleanup_legacy_nft_port_guard(timeout);
    report.removed += nft.removed;
    report.failed += nft.failed;
    for program in ["iptables", "ip6tables"] {
        let cleaned = cleanup_legacy_iptables_port_guards(program, timeout);
        report.removed += cleaned.removed;
        report.failed += cleaned.failed;
    }
    report
}

fn cleanup_legacy_nft_port_guard(timeout: Duration) -> LegacyPortGuardCleanupReport {
    let mut report = LegacyPortGuardCleanupReport::default();
    if !command_available("nft", timeout) {
        return report;
    }
    let Some(output) = command_output(
        "nft",
        &["list", "table", "inet", "vps_sentinel_exposure_guard"],
        timeout,
    ) else {
        report.failed += 1;
        return report;
    };
    if !output.status_success {
        return report;
    }
    match run_command_status_owned(
        "nft",
        &[
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            "vps_sentinel_exposure_guard".to_string(),
        ],
        timeout,
    ) {
        Ok(true) => {
            report.removed += 1;
            warn!("removed legacy vps-sentinel port guard nftables table");
        }
        Ok(false) => report.failed += 1,
        Err(err) => {
            report.failed += 1;
            warn!(error = %err, "failed to remove legacy vps-sentinel port guard nftables table");
        }
    }
    report
}

fn cleanup_legacy_iptables_port_guards(
    program: &str,
    timeout: Duration,
) -> LegacyPortGuardCleanupReport {
    let mut report = LegacyPortGuardCleanupReport::default();
    if !command_available(program, timeout) {
        return report;
    }
    let Some(output) = command_output(program, &["-S"], timeout) else {
        report.failed += 1;
        return report;
    };
    if !output.status_success {
        return report;
    }
    for line in output
        .stdout
        .lines()
        .filter(|line| is_legacy_port_guard_rule(line) && line.trim_start().starts_with("-A "))
    {
        let mut args = split_iptables_rule(line);
        if args.first().map(String::as_str) != Some("-A") || args.len() < 3 {
            continue;
        }
        args[0] = "-D".to_string();
        match run_command_status_owned(program, &args, timeout) {
            Ok(true) => {
                report.removed += 1;
                warn!(
                    backend = program,
                    "removed legacy vps-sentinel port guard iptables rule"
                );
            }
            Ok(false) => report.failed += 1,
            Err(err) => {
                report.failed += 1;
                warn!(backend = program, error = %err, "failed to remove legacy vps-sentinel port guard iptables rule");
            }
        }
    }
    report
}

fn is_legacy_port_guard_rule(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    lowered.contains("vps-sentinel exposure guard")
        && lowered.contains(" -p tcp ")
        && (lowered.contains(" --dport ") || lowered.contains(" --dports "))
        && (lowered.contains(" -j drop") || lowered.contains(" -j reject"))
}

fn split_iptables_rule(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(quote_ch) = quote {
            if ch == quote_ch {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

fn block_candidates(findings: &[Finding], config: &SentinelConfig) -> Vec<BlockCandidate> {
    let mut candidates = BTreeMap::<IpAddr, BlockCandidate>::new();
    for finding in findings {
        let Some(candidate) = block_candidate(finding, config) else {
            continue;
        };
        candidates.entry(candidate.ip).or_insert(candidate);
    }
    for candidate in aggregate_web_probe_candidates(findings, config) {
        candidates.entry(candidate.ip).or_insert(candidate);
    }
    candidates.into_values().collect()
}

fn block_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    if evidence_value(finding, "attack_fingerprint_verdict") == Some(VERDICT_BENIGN) {
        return None;
    }
    let candidate = match finding.rule_id.as_str() {
        "WEB-001" if config.active_response.web_enabled => web_probe_candidate(finding, config),
        "WEB-002" if config.active_response.web_enabled => web_error_candidate(finding, config),
        "SSH-003" | "SSH-007" if config.active_response.ssh_enabled => {
            ssh_bruteforce_candidate(finding, config)
        }
        _ => None,
    }
    .or_else(|| attack_fingerprint_candidate(finding, config))?;
    let candidate = apply_response_layer(candidate, finding, config);
    let candidate = apply_response_policy(candidate, finding, config)?;
    filter_block_candidate(candidate, config)
}

fn filter_block_candidate(
    candidate: BlockCandidate,
    config: &SentinelConfig,
) -> Option<BlockCandidate> {
    if field_is_allowlisted(&candidate.ip.to_string(), &config.allowlist.ips) {
        return None;
    }
    if !is_public_remote_ip(candidate.ip) {
        return None;
    }
    Some(candidate)
}

fn web_probe_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    if proxy_source_unresolved(finding) {
        return None;
    }
    let ip = evidence_ip(finding, "ip")?;
    let family = evidence_value(finding, "probe_family")?;
    let response = evidence_value(finding, "response_profile")?;
    let request_count = evidence_usize(finding, "request_count")?;
    let threshold = web_probe_threshold(family, response, config);
    if request_count < threshold {
        return None;
    }
    Some(BlockCandidate {
        kind: BlockCandidateKind::WebProbe,
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!(
            "web probe family={family} response={response} request_count={request_count}"
        ),
        action: ResponseAction::Block,
        ttl_seconds: None,
        permanent_after: None,
    })
}

fn web_error_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    if proxy_source_unresolved(finding) {
        return None;
    }
    let ip = evidence_ip(finding, "ip")?;
    let error_count = evidence_usize(finding, "error_count")?;
    let threshold = match active_response_strategy(config) {
        ActiveResponseStrategy::Strict => config
            .active_response
            .web_probe_block_threshold
            .saturating_mul(2),
        ActiveResponseStrategy::Observe | ActiveResponseStrategy::Balanced => {
            config.active_response.web_probe_block_threshold
        }
    };
    if error_count < threshold {
        return None;
    }
    Some(BlockCandidate {
        kind: BlockCandidateKind::WebError,
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!("web error burst error_count={error_count}"),
        action: ResponseAction::Block,
        ttl_seconds: None,
        permanent_after: None,
    })
}

#[derive(Debug, Clone)]
struct WebProbeAggregate<'a> {
    finding: &'a Finding,
    total_requests: usize,
    families: BTreeSet<String>,
    responses: BTreeSet<String>,
}

fn aggregate_web_probe_candidates(
    findings: &[Finding],
    config: &SentinelConfig,
) -> Vec<BlockCandidate> {
    if !config.active_response.web_enabled {
        return Vec::new();
    }
    let mut groups = BTreeMap::<IpAddr, WebProbeAggregate>::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.rule_id == "WEB-001")
    {
        let Some(ip) = evidence_ip(finding, "ip") else {
            continue;
        };
        let Some(family) = evidence_value(finding, "probe_family") else {
            continue;
        };
        let Some(response) = evidence_value(finding, "response_profile") else {
            continue;
        };
        let Some(request_count) = evidence_usize(finding, "request_count") else {
            continue;
        };
        let group = groups.entry(ip).or_insert_with(|| WebProbeAggregate {
            finding,
            total_requests: 0,
            families: BTreeSet::new(),
            responses: BTreeSet::new(),
        });
        group.total_requests = group.total_requests.saturating_add(request_count);
        for family in
            split_evidence_list(evidence_value(finding, "probe_families").unwrap_or(family))
        {
            group.families.insert(family);
        }
        for response in
            split_evidence_list(evidence_value(finding, "response_profiles").unwrap_or(response))
        {
            group.responses.insert(response);
        }
    }
    groups
        .into_iter()
        .filter_map(|(ip, group)| {
            let candidate = aggregate_web_candidate(ip, &group, config)?;
            let candidate = apply_response_layer(candidate, group.finding, config);
            let candidate = apply_response_policy(candidate, group.finding, config)?;
            filter_block_candidate(candidate, config)
        })
        .collect()
}

fn proxy_source_unresolved(finding: &Finding) -> bool {
    evidence_value(finding, "proxy_source_unresolved") == Some("true")
}

fn split_evidence_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn aggregate_web_candidate(
    ip: IpAddr,
    group: &WebProbeAggregate<'_>,
    config: &SentinelConfig,
) -> Option<BlockCandidate> {
    let family_count = group.families.len();
    let broad_scan =
        family_count >= 3 && group.total_requests >= multi_family_web_probe_threshold(config);
    let high_volume_scan = family_count >= 2
        && group.total_requests
            >= config
                .active_response
                .web_probe_block_threshold
                .saturating_mul(2);
    if !broad_scan && !high_volume_scan {
        return None;
    }
    Some(BlockCandidate {
        kind: BlockCandidateKind::WebAggregate,
        ip,
        rule_id: "WEB-001".to_string(),
        finding_id: group.finding.id.clone(),
        reason: format!(
            "web aggregate families={} responses={} request_count={}",
            join_sorted(&group.families),
            join_sorted(&group.responses),
            group.total_requests
        ),
        action: ResponseAction::Block,
        ttl_seconds: None,
        permanent_after: None,
    })
}

fn multi_family_web_probe_threshold(config: &SentinelConfig) -> usize {
    let threshold = config
        .active_response
        .web_probe_block_threshold
        .saturating_mul(4)
        .saturating_add(4)
        / 5;
    threshold.max(3)
}

fn join_sorted(values: &BTreeSet<String>) -> String {
    let mut joined = String::new();
    for value in values {
        if !joined.is_empty() {
            joined.push(',');
        }
        joined.push_str(value);
    }
    joined
}

fn ssh_bruteforce_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    let ip = evidence_ip(finding, "source_ip")?;
    let failure_count = evidence_usize(finding, "failure_count")?;
    let threshold = match active_response_strategy(config) {
        ActiveResponseStrategy::Strict => config
            .active_response
            .ssh_failed_login_block_threshold
            .max(config.ssh.failed_login_threshold.saturating_mul(2)),
        ActiveResponseStrategy::Observe | ActiveResponseStrategy::Balanced => {
            config.active_response.ssh_failed_login_block_threshold
        }
    };
    if failure_count < threshold {
        return None;
    }
    Some(BlockCandidate {
        kind: BlockCandidateKind::SshBruteforce,
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!("ssh brute force failure_count={failure_count}"),
        action: ResponseAction::Block,
        ttl_seconds: None,
        permanent_after: None,
    })
}

fn attack_fingerprint_candidate(
    finding: &Finding,
    config: &SentinelConfig,
) -> Option<BlockCandidate> {
    if !config.attack_fingerprints.active_response_enabled {
        return None;
    }
    if evidence_value(finding, ACTION_HINT_KEY) != Some("block") || proxy_source_unresolved(finding)
    {
        return None;
    }
    let ip = evidence_any_ip(finding, &["source_ip", "ip", "remote_ip", "remote_addr"])?;
    let fingerprint_id = evidence_value(finding, FINGERPRINT_ID_KEY).unwrap_or("unknown");
    let fingerprint_kind = evidence_value(finding, "attack_fingerprint_kind").unwrap_or("unknown");
    let score = evidence_value(finding, "attack_fingerprint_score").unwrap_or("unknown");
    Some(BlockCandidate {
        kind: BlockCandidateKind::AttackFingerprint,
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!(
            "attack fingerprint id={fingerprint_id} kind={fingerprint_kind} score={score}"
        ),
        action: ResponseAction::Block,
        ttl_seconds: None,
        permanent_after: None,
    })
}

#[derive(Debug, Clone, Copy)]
struct ResponseLayer {
    name: &'static str,
    ttl_multiplier: u64,
    permanent_after: Option<usize>,
    action: Option<ResponseAction>,
}

fn apply_response_layer(
    mut candidate: BlockCandidate,
    finding: &Finding,
    config: &SentinelConfig,
) -> BlockCandidate {
    let Some(layer) = response_layer(&candidate, finding, config) else {
        return candidate;
    };
    candidate.reason = format!("{} layer={}", candidate.reason, layer.name);
    if candidate.ttl_seconds.is_none() && layer.ttl_multiplier > 1 {
        candidate.ttl_seconds = Some(layered_ttl_seconds(config, layer.ttl_multiplier));
    }
    if candidate.permanent_after.is_none() {
        candidate.permanent_after = layer.permanent_after;
    }
    if let Some(action) = layer.action {
        candidate.action = action;
    }
    candidate
}

fn response_layer(
    candidate: &BlockCandidate,
    finding: &Finding,
    config: &SentinelConfig,
) -> Option<ResponseLayer> {
    if evidence_value(finding, "attack_fingerprint_verdict") == Some(VERDICT_MALICIOUS) {
        return Some(ResponseLayer {
            name: "confirmed_malicious_fingerprint",
            ttl_multiplier: 4,
            permanent_after: Some(layered_permanent_after(config, 1)),
            action: Some(ResponseAction::PermanentBlock),
        });
    }
    if evidence_value(finding, ACTION_HINT_KEY) == Some("block") {
        return Some(ResponseLayer {
            name: "repeated_attack_fingerprint",
            ttl_multiplier: 2,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        });
    }
    match finding.rule_id.as_str() {
        "SSH-007" => Some(ResponseLayer {
            name: "ssh_success_after_bruteforce",
            ttl_multiplier: 4,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        }),
        "SSH-003" if high_volume_ssh_bruteforce(finding, config) => Some(ResponseLayer {
            name: "high_volume_ssh_bruteforce",
            ttl_multiplier: 2,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        }),
        "WEB-001" if candidate.kind == BlockCandidateKind::WebAggregate => Some(ResponseLayer {
            name: "multi_family_web_scan",
            ttl_multiplier: 2,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        }),
        "WEB-001" => web_probe_response_layer(finding, config),
        "WEB-002" => Some(ResponseLayer {
            name: "web_error_burst",
            ttl_multiplier: 2,
            permanent_after: Some(layered_permanent_after(config, 3)),
            action: None,
        }),
        _ => None,
    }
}

fn web_probe_response_layer(finding: &Finding, config: &SentinelConfig) -> Option<ResponseLayer> {
    let family = evidence_value(finding, "probe_family")?;
    let response = evidence_value(finding, "response_profile")?;
    if response == "successful_response" {
        return Some(ResponseLayer {
            name: "confirmed_web_exposure",
            ttl_multiplier: 4,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        });
    }
    if probe_family_blocks_on_single_attempt(family) {
        return Some(ResponseLayer {
            name: "high_confidence_web_exploit",
            ttl_multiplier: 3,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        });
    }
    if probe_family_is_exploit(family) {
        return Some(ResponseLayer {
            name: "repeated_web_exploit",
            ttl_multiplier: 2,
            permanent_after: Some(layered_permanent_after(config, 2)),
            action: None,
        });
    }
    None
}

fn high_volume_ssh_bruteforce(finding: &Finding, config: &SentinelConfig) -> bool {
    let Some(failure_count) = evidence_usize(finding, "failure_count") else {
        return false;
    };
    failure_count
        >= config
            .active_response
            .ssh_failed_login_block_threshold
            .saturating_mul(2)
}

fn layered_ttl_seconds(config: &SentinelConfig, multiplier: u64) -> u64 {
    const MAX_LAYERED_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
    config
        .active_response
        .block_ttl_seconds
        .saturating_mul(multiplier)
        .min(MAX_LAYERED_TTL_SECONDS)
}

fn layered_permanent_after(config: &SentinelConfig, target: usize) -> usize {
    config
        .active_response
        .permanent_block_threshold
        .max(1)
        .min(target.max(1))
}

fn apply_response_policy(
    mut candidate: BlockCandidate,
    finding: &Finding,
    config: &SentinelConfig,
) -> Option<BlockCandidate> {
    if !config.response_policy.enabled {
        return Some(candidate);
    }
    let Some((name, policy)) = config.response_policy.policies.iter().find(|(_, policy)| {
        policy.enabled
            && (policy.rule_ids.iter().any(|rule| rule == &finding.rule_id)
                || policy
                    .categories
                    .iter()
                    .any(|category| category.eq_ignore_ascii_case(&finding.category.to_string())))
    }) else {
        return Some(candidate);
    };
    if !finding.severity.meets(policy.min_severity) {
        return None;
    }
    if confidence_percent(finding) < policy.min_confidence {
        return None;
    }
    if unified_score(finding) < policy.min_unified_score {
        return None;
    }
    candidate.action = match policy.action.as_str() {
        "observe" => ResponseAction::Observe,
        "permanent_block" => ResponseAction::PermanentBlock,
        _ => ResponseAction::Block,
    };
    if let Some(ttl_seconds) = policy.ttl_seconds {
        candidate.ttl_seconds = Some(ttl_seconds);
    }
    if let Some(permanent_after) = policy.permanent_after {
        candidate.permanent_after = Some(permanent_after);
    }
    candidate.reason = format!("{} policy={name}", candidate.reason);
    Some(candidate)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveResponseStrategy {
    Observe,
    Balanced,
    Strict,
}

fn active_response_strategy(config: &SentinelConfig) -> ActiveResponseStrategy {
    match config.active_response.strategy.as_str() {
        "observe" => ActiveResponseStrategy::Observe,
        "strict" => ActiveResponseStrategy::Strict,
        _ => ActiveResponseStrategy::Balanced,
    }
}

fn web_probe_threshold(family: &str, response: &str, config: &SentinelConfig) -> usize {
    match active_response_strategy(config) {
        ActiveResponseStrategy::Observe | ActiveResponseStrategy::Balanced => {
            if response == "successful_response" || probe_family_blocks_on_single_attempt(family) {
                1
            } else if probe_family_is_exploit(family) {
                config.active_response.web_exploit_block_threshold
            } else {
                config.active_response.web_probe_block_threshold
            }
        }
        ActiveResponseStrategy::Strict => {
            if response == "successful_response" {
                1
            } else if probe_family_is_exploit(family) {
                config.active_response.web_exploit_block_threshold
            } else {
                config
                    .active_response
                    .web_probe_block_threshold
                    .saturating_mul(2)
            }
        }
    }
}

fn evidence_ip(finding: &Finding, key: &str) -> Option<IpAddr> {
    evidence_value(finding, key)?.parse().ok()
}

fn evidence_any_ip(finding: &Finding, keys: &[&str]) -> Option<IpAddr> {
    keys.iter().find_map(|key| evidence_ip(finding, key))
}

fn evidence_usize(finding: &Finding, key: &str) -> Option<usize> {
    evidence_value(finding, key)?.parse().ok()
}

fn evidence_value<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    sentinel_core::evidence_value(&finding.evidence, key)
}

fn record_firewall_present(config: &SentinelConfig, record: &BlockRecord) -> Option<bool> {
    let ip = record.ip.parse::<IpAddr>().ok()?;
    let blocker = SystemIpBlocker::from_backend_name(config, &record.backend)?;
    blocker.is_blocked(ip).ok()
}

fn unblock_ip_from_available_backends(
    config: &SentinelConfig,
    ip: IpAddr,
) -> SentinelResult<usize> {
    let blockers = SystemIpBlocker::available_for_unblock(config);
    if blockers.is_empty() {
        return Err(SentinelError::Command(
            "no supported firewall backend is available".to_string(),
        ));
    }
    let mut removed = 0usize;
    let mut failures = 0usize;
    for blocker in blockers {
        match blocker.unblock_ip(ip) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(err) => {
                failures += 1;
                warn!(
                    ip = %ip,
                    backend = blocker.backend_name(),
                    error = %err,
                    "active response manual unblock backend failed"
                );
            }
        }
    }
    if failures > 0 && removed == 0 {
        return Err(SentinelError::Command(format!(
            "failed to unblock {ip} from all available firewall backends"
        )));
    }
    Ok(removed)
}

#[derive(Debug)]
struct SystemIpBlocker {
    backend: FirewallBackend,
    timeout: Duration,
}

impl SystemIpBlocker {
    fn from_config(config: &SentinelConfig) -> Option<Self> {
        let timeout = Duration::from_secs(config.active_response.command_timeout_seconds);
        let backend = match config.active_response.firewall_backend.as_str() {
            "nftables" => FirewallBackend::Nftables,
            "iptables" => FirewallBackend::Iptables,
            _ if command_available("nft", timeout) => FirewallBackend::Nftables,
            _ if command_available("iptables", timeout) => FirewallBackend::Iptables,
            _ => return None,
        };
        Some(Self { backend, timeout })
    }

    fn from_backend_name(config: &SentinelConfig, backend: &str) -> Option<Self> {
        let timeout = Duration::from_secs(config.active_response.command_timeout_seconds);
        let backend = FirewallBackend::from_name(backend)?;
        if backend.available(timeout) {
            return Some(Self { backend, timeout });
        }
        None
    }

    fn available_for_unblock(config: &SentinelConfig) -> Vec<Self> {
        let timeout = Duration::from_secs(config.active_response.command_timeout_seconds);
        let backends = match config.active_response.firewall_backend.as_str() {
            "nftables" => vec![FirewallBackend::Nftables],
            "iptables" => vec![FirewallBackend::Iptables],
            _ => vec![FirewallBackend::Nftables, FirewallBackend::Iptables],
        };
        backends
            .into_iter()
            .filter(|backend| backend.available(timeout))
            .map(|backend| Self { backend, timeout })
            .collect()
    }
}

impl IpBlocker for SystemIpBlocker {
    fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    fn block_ip(&self, ip: IpAddr, ttl: Option<Duration>) -> SentinelResult<()> {
        self.backend.block_ip(ip, ttl, self.timeout)
    }

    fn unblock_ip(&self, ip: IpAddr) -> SentinelResult<bool> {
        self.backend.unblock_ip(ip, self.timeout)
    }

    fn is_blocked(&self, ip: IpAddr) -> SentinelResult<bool> {
        self.backend.is_blocked(ip, self.timeout)
    }
}

#[derive(Debug, Clone, Copy)]
enum FirewallBackend {
    Nftables,
    Iptables,
}

impl FirewallBackend {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "nftables" => Some(Self::Nftables),
            "iptables" => Some(Self::Iptables),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        }
    }

    fn available(self, timeout: Duration) -> bool {
        match self {
            Self::Nftables => command_available("nft", timeout),
            Self::Iptables => {
                command_available("iptables", timeout) || command_available("ip6tables", timeout)
            }
        }
    }

    fn block_ip(self, ip: IpAddr, ttl: Option<Duration>, timeout: Duration) -> SentinelResult<()> {
        match self {
            Self::Nftables => nft_block_ip(ip, ttl, timeout),
            Self::Iptables => iptables_block_ip(ip, ttl, timeout),
        }
    }

    fn unblock_ip(self, ip: IpAddr, timeout: Duration) -> SentinelResult<bool> {
        match self {
            Self::Nftables => nft_unblock_ip(ip, timeout),
            Self::Iptables => iptables_unblock_ip(ip, timeout),
        }
    }

    fn is_blocked(self, ip: IpAddr, timeout: Duration) -> SentinelResult<bool> {
        match self {
            Self::Nftables => nft_is_blocked(ip, timeout),
            Self::Iptables => iptables_is_blocked(ip, timeout),
        }
    }
}

fn nft_block_ip(ip: IpAddr, ttl: Option<Duration>, timeout: Duration) -> SentinelResult<()> {
    ensure_nftables_base(ip, timeout)?;
    if nft_is_blocked(ip, timeout)? {
        return Ok(());
    }
    let set_name = nft_set_name(ip);
    let mut args = vec![
        "add".to_string(),
        "element".to_string(),
        "inet".to_string(),
        "vps_sentinel".to_string(),
        set_name.to_string(),
        "{".to_string(),
        ip.to_string(),
    ];
    if let Some(ttl) = ttl {
        args.push("timeout".to_string());
        args.push(format!("{}s", ttl.as_secs()));
    }
    args.push("}".to_string());
    run_command_required("nft", &args, timeout)
}

fn nft_unblock_ip(ip: IpAddr, timeout: Duration) -> SentinelResult<bool> {
    if !nft_is_blocked(ip, timeout)? {
        return Ok(false);
    }
    let removed = run_command_status_owned(
        "nft",
        &[
            "delete".to_string(),
            "element".to_string(),
            "inet".to_string(),
            "vps_sentinel".to_string(),
            nft_set_name(ip).to_string(),
            "{".to_string(),
            ip.to_string(),
            "}".to_string(),
        ],
        timeout,
    )?;
    Ok(removed)
}

fn nft_is_blocked(ip: IpAddr, timeout: Duration) -> SentinelResult<bool> {
    let output = command_output(
        "nft",
        &["list", "set", "inet", "vps_sentinel", nft_set_name(ip)],
        timeout,
    )
    .ok_or_else(|| {
        SentinelError::Command(format!(
            "nft list set inet vps_sentinel {} timed out or could not start",
            nft_set_name(ip)
        ))
    })?;
    if !output.status_success {
        return Ok(false);
    }
    let needle = ip.to_string();
    Ok(output
        .stdout
        .split_whitespace()
        .map(|token| token.trim_matches(|ch| matches!(ch, '{' | '}' | ',' | ';')))
        .any(|token| token == needle))
}

fn ensure_nftables_base(ip: IpAddr, timeout: Duration) -> SentinelResult<()> {
    run_command_best_effort("nft", &["add", "table", "inet", "vps_sentinel"], timeout);
    let set_name = nft_set_name(ip);
    let address_type = if ip.is_ipv4() {
        "ipv4_addr"
    } else {
        "ipv6_addr"
    };
    run_command_best_effort(
        "nft",
        &[
            "add",
            "set",
            "inet",
            "vps_sentinel",
            set_name,
            "{",
            "type",
            address_type,
            ";",
            "flags",
            "timeout",
            ";",
            "}",
        ],
        timeout,
    );
    run_command_best_effort(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "vps_sentinel",
            "input",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-10",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
        timeout,
    );
    let chain = command_output(
        "nft",
        &["list", "chain", "inet", "vps_sentinel", "input"],
        timeout,
    )
    .filter(|output| output.status_success)
    .map(|output| output.stdout)
    .ok_or_else(|| {
        SentinelError::Command("nft list chain inet vps_sentinel input failed".to_string())
    })?;
    if !chain.contains(&format!("@{set_name}")) {
        let family = if ip.is_ipv4() { "ip" } else { "ip6" };
        let set_ref = format!("@{set_name}");
        run_command_required(
            "nft",
            &[
                "add".to_string(),
                "rule".to_string(),
                "inet".to_string(),
                "vps_sentinel".to_string(),
                "input".to_string(),
                family.to_string(),
                "saddr".to_string(),
                set_ref,
                "drop".to_string(),
            ],
            timeout,
        )?;
    }
    Ok(())
}

fn nft_set_name(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "blocked_ipv4"
    } else {
        "blocked_ipv6"
    }
}

fn iptables_block_ip(ip: IpAddr, _ttl: Option<Duration>, timeout: Duration) -> SentinelResult<()> {
    if iptables_is_blocked(ip, timeout)? {
        return Ok(());
    }
    run_command_required(iptables_program(ip), &iptables_rule_args("-I", ip), timeout)
}

fn iptables_unblock_ip(ip: IpAddr, timeout: Duration) -> SentinelResult<bool> {
    let mut removed = false;
    for _ in 0..16 {
        if !iptables_is_blocked(ip, timeout)? {
            return Ok(removed);
        }
        let deleted =
            run_command_status_owned(iptables_program(ip), &iptables_rule_args("-D", ip), timeout)?;
        if !deleted {
            return Ok(removed);
        }
        removed = true;
    }
    Ok(removed)
}

fn iptables_is_blocked(ip: IpAddr, timeout: Duration) -> SentinelResult<bool> {
    run_command_status_owned(iptables_program(ip), &iptables_rule_args("-C", ip), timeout)
}

fn iptables_rule_args(action: &str, ip: IpAddr) -> Vec<String> {
    vec![
        action.to_string(),
        "INPUT".to_string(),
        "-s".to_string(),
        ip.to_string(),
        "-j".to_string(),
        "DROP".to_string(),
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        "vps-sentinel".to_string(),
    ]
}

fn iptables_program(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() {
        "iptables"
    } else {
        "ip6tables"
    }
}

fn command_available(program: &str, timeout: Duration) -> bool {
    command_output(program, &["--version"], timeout)
        .map(|output| output.status_success)
        .unwrap_or(false)
}

fn run_command_required(program: &str, args: &[String], timeout: Duration) -> SentinelResult<()> {
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    match command_output(program, &arg_refs, timeout) {
        Some(output) if output.status_success => Ok(()),
        Some(_) => Err(SentinelError::Command(format!(
            "{program} {} failed",
            args.join(" ")
        ))),
        None => Err(SentinelError::Command(format!(
            "{program} {} timed out or could not start",
            args.join(" ")
        ))),
    }
}

fn run_command_status_owned(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> SentinelResult<bool> {
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    command_output(program, &arg_refs, timeout)
        .map(|output| output.status_success)
        .ok_or_else(|| {
            SentinelError::Command(format!(
                "{program} {} timed out or could not start",
                args.join(" ")
            ))
        })
}

fn run_command_best_effort(program: &str, args: &[&str], timeout: Duration) {
    let _ = command_output(program, args, timeout);
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
        apply_with_blocker, block_candidates, is_public_remote_ip, list_active_blocks,
        BlockActionStatus, BlockRecord, BlockState, IpBlocker, ResponseAction, SentinelResult,
        STATE_RULE_ID,
    };
    use crate::attack_fingerprint::{VERDICT_BENIGN, VERDICT_MALICIOUS};
    use crate::storage::SqliteStore;
    use chrono::{Duration as ChronoDuration, Utc};
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};
    use std::collections::BTreeMap;

    #[test]
    fn web_probe_blocks_only_after_strict_thresholds() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        config.active_response.web_exploit_block_threshold = 5;
        let low_noise = web_finding("8.8.8.8", "env_file", "missing_or_rejected", 3);
        let high_volume = web_finding("8.8.4.4", "env_file", "missing_or_rejected", 25);
        let exploit = web_finding("1.1.1.1", "command_injection", "missing_or_rejected", 1);
        let repeated_sql = web_finding("1.0.0.1", "sql_injection", "missing_or_rejected", 5);
        let successful = web_finding("9.9.9.9", "env_file", "successful_response", 1);

        let candidates = block_candidates(
            &[low_noise, high_volume, exploit, repeated_sql, successful],
            &config,
        );

        assert_eq!(candidates.len(), 4);
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "8.8.4.4"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "1.1.1.1"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "1.0.0.1"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "9.9.9.9"));
    }

    #[test]
    fn multi_family_web_probe_aggregate_blocks_low_and_slow_scan() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        let findings = vec![
            web_finding("54.197.205.159", "env_file", "missing_or_rejected", 11),
            web_finding("54.197.205.159", "git_exposure", "missing_or_rejected", 7),
            web_finding("54.197.205.159", "actuator", "missing_or_rejected", 2),
            web_finding("34.139.235.74", "env_file", "missing_or_rejected", 9),
            web_finding("34.139.235.74", "git_exposure", "missing_or_rejected", 4),
        ];

        let candidates = block_candidates(&findings, &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "54.197.205.159");
        assert!(candidates[0].reason.contains("web aggregate"));
        assert!(candidates[0].reason.contains("request_count=20"));
    }

    #[test]
    fn grouped_web_probe_family_list_can_trigger_aggregate_block() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        let mut finding = web_finding("54.197.205.160", "env_file", "missing_or_rejected", 20);
        finding.evidence.push(Evidence::new(
            "probe_families",
            "actuator, env_file, git_exposure",
        ));
        finding
            .evidence
            .push(Evidence::new("response_profiles", "missing_or_rejected"));

        let candidates = block_candidates(&[finding], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "54.197.205.160");
        assert!(candidates[0].reason.contains("web aggregate"));
    }

    #[test]
    fn unresolved_trusted_proxy_web_findings_are_not_block_candidates() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        let mut finding = web_finding("172.70.12.9", "env_file", "successful_response", 1);
        finding
            .evidence
            .push(Evidence::new("source_is_trusted_proxy", "true"));
        finding
            .evidence
            .push(Evidence::new("proxy_source_unresolved", "true"));

        let candidates = block_candidates(&[finding], &config);

        assert!(candidates.is_empty());
    }

    #[test]
    fn multi_family_web_probe_aggregate_honors_policy_and_ip_safety() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        config.allowlist.ips.push("54.197.205.159".to_string());
        config
            .response_policy
            .policies
            .get_mut("web_attack")
            .expect("web response policy")
            .action = "observe".to_string();
        let findings = vec![
            web_finding("54.197.205.159", "env_file", "missing_or_rejected", 8),
            web_finding("54.197.205.159", "git_exposure", "missing_or_rejected", 8),
            web_finding("54.197.205.159", "actuator", "missing_or_rejected", 8),
            web_finding("10.0.0.5", "env_file", "missing_or_rejected", 8),
            web_finding("10.0.0.5", "git_exposure", "missing_or_rejected", 8),
            web_finding("10.0.0.5", "actuator", "missing_or_rejected", 8),
            web_finding("9.9.9.9", "env_file", "missing_or_rejected", 8),
            web_finding("9.9.9.9", "git_exposure", "missing_or_rejected", 8),
            web_finding("9.9.9.9", "actuator", "missing_or_rejected", 8),
        ];

        let candidates = block_candidates(&findings, &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "9.9.9.9");
        assert_eq!(candidates[0].action, ResponseAction::Observe);
        assert!(candidates[0].reason.contains("policy=web_attack"));
    }

    #[test]
    fn ssh_bruteforce_blocks_only_at_block_threshold() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 15;
        let below = ssh_finding("8.8.8.8", 14);
        let above = ssh_finding("1.1.1.1", 15);

        let candidates = block_candidates(&[below, above], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "1.1.1.1");
    }

    #[test]
    fn ssh_success_after_bruteforce_uses_same_response_policy() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 6;
        let mut finding = ssh_finding("8.8.4.4", 6);
        finding.rule_id = "SSH-007".to_string();
        finding.title = "SSH brute force followed by success".to_string();

        let candidates = block_candidates(&[finding], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "8.8.4.4");
        assert_eq!(candidates[0].rule_id, "SSH-007");
        assert!(candidates[0].reason.contains("policy=ssh_bruteforce"));
    }

    #[test]
    fn fingerprint_action_hint_can_block_below_rule_threshold() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        let mut finding = web_finding("8.8.8.8", "env_file", "missing_or_rejected", 1);
        finding.evidence.push(Evidence::new(
            crate::attack_fingerprint::FINGERPRINT_ID_KEY,
            "WEB-FP-test",
        ));
        finding.evidence.push(Evidence::new(
            crate::attack_fingerprint::ACTION_HINT_KEY,
            "block",
        ));
        finding
            .evidence
            .push(Evidence::new("attack_fingerprint_kind", "web_probe"));
        finding
            .evidence
            .push(Evidence::new("attack_fingerprint_score", "90"));

        let candidates = block_candidates(&[finding], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "8.8.8.8");
        assert!(candidates[0].reason.contains("WEB-FP-test"));
    }

    #[test]
    fn benign_fingerprint_feedback_suppresses_active_response() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 1;
        let mut finding = web_finding("8.8.8.8", "env_file", "successful_response", 10);
        finding
            .evidence
            .push(Evidence::new("attack_fingerprint_verdict", VERDICT_BENIGN));

        let candidates = block_candidates(&[finding], &config);

        assert!(candidates.is_empty());
    }

    #[test]
    fn fingerprint_action_hint_does_not_block_unresolved_proxy_source() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        let mut finding = web_finding("172.70.12.9", "env_file", "missing_or_rejected", 1);
        finding.evidence.push(Evidence::new(
            crate::attack_fingerprint::ACTION_HINT_KEY,
            "block",
        ));
        finding
            .evidence
            .push(Evidence::new("proxy_source_unresolved", "true"));

        let candidates = block_candidates(&[finding], &config);

        assert!(candidates.is_empty());
    }

    #[test]
    fn observe_strategy_reports_candidates_without_firewall_backend(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.strategy = "observe".to_string();
        config.active_response.ssh_failed_login_block_threshold = 15;

        let report = super::apply_active_response(&[ssh_finding("8.8.8.8", 16)], &config, &store)?;

        assert_eq!(report.planned_blocks, 1);
        assert_eq!(report.applied_blocks, 0);
        assert_eq!(report.block_actions[0].status, BlockActionStatus::Observed);
        assert_eq!(report.block_actions[0].ip.to_string(), "8.8.8.8");
        Ok(())
    }

    #[test]
    fn high_confidence_web_exploit_blocks_on_single_attempt() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_exploit_block_threshold = 5;
        let cgi_shell = web_finding("4.4.4.4", "cgi_shell_traversal", "missing_or_rejected", 1);
        let phpunit = web_finding("4.4.8.8", "phpunit_eval_stdin", "missing_or_rejected", 1);
        let php_config = web_finding("4.4.9.9", "php_config_injection", "missing_or_rejected", 1);
        let lfi = web_finding("4.4.10.10", "lfi_file_read", "missing_or_rejected", 1);
        let ssrf = web_finding("4.4.11.11", "ssrf_metadata", "missing_or_rejected", 1);
        let template_below_threshold =
            web_finding("4.4.12.12", "template_injection", "missing_or_rejected", 1);
        let sql_below_threshold = web_finding("8.8.4.4", "sql_injection", "missing_or_rejected", 1);

        let candidates = block_candidates(
            &[
                cgi_shell,
                phpunit,
                php_config,
                lfi,
                ssrf,
                template_below_threshold,
                sql_below_threshold,
            ],
            &config,
        );

        assert_eq!(candidates.len(), 5);
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.4.4"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.8.8"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.9.9"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.10.10"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.11.11"));
    }

    #[test]
    fn strict_strategy_requires_repeated_rejected_exploit_probes() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.strategy = "strict".to_string();
        config.active_response.web_exploit_block_threshold = 5;
        let single_rejected =
            web_finding("4.4.4.4", "cgi_shell_traversal", "missing_or_rejected", 1);
        let repeated_rejected =
            web_finding("4.4.4.5", "cgi_shell_traversal", "missing_or_rejected", 5);
        let successful = web_finding("4.4.4.6", "env_file", "successful_response", 1);

        let candidates =
            block_candidates(&[single_rejected, repeated_rejected, successful], &config);

        assert_eq!(candidates.len(), 2);
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.4.5"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.4.6"));
    }

    #[test]
    fn strong_web_signal_uses_layered_ttl_and_permanent_threshold() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.block_ttl_seconds = 60;
        config.active_response.permanent_block_threshold = 5;
        let finding = web_finding("9.9.9.9", "env_file", "successful_response", 1);

        let candidates = block_candidates(&[finding], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ttl_seconds, Some(240));
        assert_eq!(candidates[0].permanent_after, Some(2));
        assert!(candidates[0]
            .reason
            .contains("layer=confirmed_web_exposure"));
    }

    #[test]
    fn response_policy_explicit_ttl_and_permanent_threshold_override_layer() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.block_ttl_seconds = 60;
        let policy = config
            .response_policy
            .policies
            .get_mut("web_attack")
            .expect("web policy");
        policy.ttl_seconds = Some(30);
        policy.permanent_after = Some(4);
        let finding = web_finding("9.9.9.9", "env_file", "successful_response", 1);

        let candidates = block_candidates(&[finding], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ttl_seconds, Some(30));
        assert_eq!(candidates[0].permanent_after, Some(4));
        assert!(candidates[0].reason.contains("policy=web_attack"));
    }

    #[test]
    fn malicious_fingerprint_verdict_uses_permanent_response_layer() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        let mut finding = web_finding("8.8.8.8", "env_file", "missing_or_rejected", 1);
        finding.evidence.push(Evidence::new(
            crate::attack_fingerprint::FINGERPRINT_ID_KEY,
            "WEB-FP-test",
        ));
        finding.evidence.push(Evidence::new(
            crate::attack_fingerprint::ACTION_HINT_KEY,
            "block",
        ));
        finding.evidence.push(Evidence::new(
            "attack_fingerprint_verdict",
            VERDICT_MALICIOUS,
        ));
        finding
            .evidence
            .push(Evidence::new("attack_fingerprint_score", "95"));

        let candidates = block_candidates(&[finding], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].action, ResponseAction::Block);
        assert_eq!(candidates[0].permanent_after, Some(1));
        assert!(candidates[0]
            .reason
            .contains("layer=confirmed_malicious_fingerprint"));
    }

    #[test]
    fn block_report_tracks_per_finding_actions() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 15;
        let mut finding = ssh_finding("8.8.8.8", 16);
        finding.id = "finding-1".to_string();
        let blocker = MemoryBlocker;

        let report = apply_with_blocker(&[finding], &config, &store, &blocker)?;

        assert_eq!(report.applied_blocks, 1);
        assert_eq!(report.block_actions.len(), 1);
        assert_eq!(report.block_actions[0].finding_id, "finding-1");
        assert_eq!(report.block_actions[0].status, BlockActionStatus::Blocked);
        assert_eq!(report.block_actions[0].backend.as_deref(), Some("memory"));
        assert_eq!(report.block_actions[0].ip.to_string(), "8.8.8.8");
        Ok(())
    }

    #[test]
    fn repeated_candidates_escalate_existing_block_to_permanent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 15;
        config.active_response.permanent_block_threshold = 2;
        config.active_response.permanent_block_window_seconds = 3600;
        let blocker = MemoryBlocker;

        let first = apply_with_blocker(&[ssh_finding("8.8.8.8", 16)], &config, &store, &blocker)?;
        assert_eq!(first.applied_blocks, 1);
        assert_eq!(first.permanent_blocks, 0);
        assert_eq!(first.block_actions[0].status, BlockActionStatus::Blocked);
        assert!(first.block_actions[0].expires_at.is_some());

        let second = apply_with_blocker(&[ssh_finding("8.8.8.8", 17)], &config, &store, &blocker)?;
        assert_eq!(second.applied_blocks, 1);
        assert_eq!(second.permanent_blocks, 1);
        assert_eq!(
            second.block_actions[0].status,
            BlockActionStatus::PermanentlyBlocked
        );
        assert!(second.block_actions[0].expires_at.is_none());
        assert!(second.block_actions[0]
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("trigger_count=2")));

        let entries = list_active_blocks(&config, &store, false)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "8.8.8.8");
        assert!(entries[0].expires_at.is_none());
        assert!(!entries[0].expired);
        Ok(())
    }

    #[test]
    fn disabled_permanent_block_keeps_temporary_block() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 15;
        config.active_response.permanent_block_enabled = false;
        config.active_response.permanent_block_threshold = 1;
        let blocker = MemoryBlocker;

        let report = apply_with_blocker(&[ssh_finding("8.8.4.4", 16)], &config, &store, &blocker)?;

        assert_eq!(report.applied_blocks, 1);
        assert_eq!(report.permanent_blocks, 0);
        assert_eq!(report.block_actions[0].status, BlockActionStatus::Blocked);
        assert!(report.block_actions[0].expires_at.is_some());
        Ok(())
    }

    #[test]
    fn observed_candidates_do_not_increment_permanent_block_history(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 15;
        config.active_response.permanent_block_threshold = 1;
        config
            .response_policy
            .policies
            .get_mut("ssh_bruteforce")
            .expect("ssh response policy")
            .action = "observe".to_string();
        let blocker = MemoryBlocker;

        let report = apply_with_blocker(&[ssh_finding("8.8.8.8", 16)], &config, &store, &blocker)?;

        assert_eq!(report.applied_blocks, 0);
        assert_eq!(report.block_actions[0].status, BlockActionStatus::Observed);
        let state = store
            .load_rule_state::<BlockState>(STATE_RULE_ID)?
            .unwrap_or_default();
        assert!(state.trigger_history.is_empty());
        assert!(state.blocks.is_empty());
        Ok(())
    }

    #[test]
    fn existing_permanent_block_is_reported_explicitly() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 15;
        config.active_response.permanent_block_threshold = 1;
        let blocker = MemoryBlocker;

        let first = apply_with_blocker(&[ssh_finding("8.8.4.5", 16)], &config, &store, &blocker)?;
        assert_eq!(
            first.block_actions[0].status,
            BlockActionStatus::PermanentlyBlocked
        );

        let second = apply_with_blocker(&[ssh_finding("8.8.4.5", 17)], &config, &store, &blocker)?;

        assert_eq!(second.applied_blocks, 0);
        assert_eq!(second.permanent_blocks, 0);
        assert_eq!(
            second.block_actions[0].status,
            BlockActionStatus::AlreadyPermanentlyBlocked
        );
        assert!(second.block_actions[0].expires_at.is_none());
        Ok(())
    }

    #[test]
    fn allowlisted_and_non_public_ips_are_never_blocked() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.allowlist.ips.push("8.8.8.8".to_string());
        let allowlisted = ssh_finding("8.8.8.8", 30);
        let private = ssh_finding("10.0.0.5", 30);
        let documentation = ssh_finding("203.0.113.5", 30);

        let candidates = block_candidates(&[allowlisted, private, documentation], &config);

        assert!(candidates.is_empty());
    }

    #[test]
    fn public_ip_classifier_rejects_non_routable_ranges() {
        assert!(is_public_remote_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_remote_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("172.16.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("0.1.2.3".parse().unwrap()));
        assert!(!is_public_remote_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("192.0.0.9".parse().unwrap()));
        assert!(!is_public_remote_ip("192.0.2.1".parse().unwrap()));
        assert!(!is_public_remote_ip("198.18.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("240.0.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("::1".parse().unwrap()));
        assert!(!is_public_remote_ip("fc00::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:db8::1".parse().unwrap()));
        assert!(!is_public_remote_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!is_public_remote_ip("100::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:2::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:10::1".parse().unwrap()));
        assert!(!is_public_remote_ip("64:ff9b:1::1".parse().unwrap()));
    }

    #[test]
    fn lists_active_block_state_without_firewall_verification(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let now = Utc::now();
        let mut blocks = BTreeMap::new();
        blocks.insert(
            "8.8.8.8".to_string(),
            BlockRecord {
                ip: "8.8.8.8".to_string(),
                rule_id: "WEB-001".to_string(),
                finding_id: "finding-1".to_string(),
                reason: "web probe".to_string(),
                backend: "iptables".to_string(),
                blocked_at: now,
                expires_at: Some(now + ChronoDuration::minutes(5)),
            },
        );
        store.save_rule_state(
            STATE_RULE_ID,
            &BlockState {
                blocks,
                ..BlockState::default()
            },
        )?;

        let entries = list_active_blocks(&SentinelConfig::default(), &store, false)?;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "8.8.8.8");
        assert_eq!(entries[0].firewall_present, None);
        assert!(!entries[0].expired);
        Ok(())
    }

    #[test]
    fn legacy_port_guard_rule_detection_is_narrow() {
        assert!(super::is_legacy_port_guard_rule(
            r#"-A INPUT -p tcp -m multiport --dports 3306,6379 -m comment --comment "vps-sentinel exposure guard" -j DROP"#
        ));
        assert!(!super::is_legacy_port_guard_rule(
            "-A INPUT -s 8.8.8.8/32 -m comment --comment vps-sentinel -j DROP"
        ));
        assert!(!super::is_legacy_port_guard_rule(
            r#"-A INPUT -p tcp --dport 6379 -m comment --comment "custom exposure guard" -j DROP"#
        ));
    }

    #[test]
    fn split_iptables_rule_preserves_quoted_comment() {
        let args = super::split_iptables_rule(
            r#"-A INPUT -p tcp --dport 6379 -m comment --comment "vps-sentinel exposure guard" -j DROP"#,
        );

        assert_eq!(args[0], "-A");
        assert_eq!(args[1], "INPUT");
        assert!(args.contains(&"6379".to_string()));
        assert!(args.contains(&"vps-sentinel exposure guard".to_string()));
    }

    fn web_finding(
        ip: &str,
        family: &str,
        response_profile: &str,
        request_count: usize,
    ) -> Finding {
        Finding::new(
            "host",
            "Web vulnerability probing detected",
            "probe",
            Severity::Low,
            Category::Web,
            "WEB-001",
            ip,
        )
        .with_evidence(vec![
            Evidence::new("ip", ip),
            Evidence::new("probe_family", family),
            Evidence::new("response_profile", response_profile),
            Evidence::new("request_count", request_count.to_string()),
        ])
    }

    fn ssh_finding(ip: &str, failure_count: usize) -> Finding {
        Finding::new(
            "host",
            "SSH brute force pattern detected",
            "bruteforce",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            ip,
        )
        .with_evidence(vec![
            Evidence::new("source_ip", ip),
            Evidence::new("failure_count", failure_count.to_string()),
        ])
    }

    #[derive(Default)]
    struct MemoryBlocker;

    impl IpBlocker for MemoryBlocker {
        fn backend_name(&self) -> &'static str {
            "memory"
        }

        fn block_ip(
            &self,
            _ip: std::net::IpAddr,
            _ttl: Option<std::time::Duration>,
        ) -> SentinelResult<()> {
            Ok(())
        }

        fn unblock_ip(&self, _ip: std::net::IpAddr) -> SentinelResult<bool> {
            Ok(true)
        }

        fn is_blocked(&self, _ip: std::net::IpAddr) -> SentinelResult<bool> {
            Ok(true)
        }
    }
}
