use crate::detectors::field_is_allowlisted;
use crate::storage::SqliteStore;
use crate::utils::command::command_output;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sentinel_core::{Finding, SentinelConfig, SentinelError, SentinelResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tracing::warn;

const STATE_RULE_ID: &str = "active_response_blocks";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveResponseReport {
    pub planned_blocks: usize,
    pub applied_blocks: usize,
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
    Blocked,
    AlreadyBlocked,
    Failed,
    SkippedLimit,
}

impl BlockActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::AlreadyBlocked => "already_blocked",
            Self::Failed => "failed",
            Self::SkippedLimit => "skipped_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    pub ip: String,
    pub rule_id: String,
    pub finding_id: String,
    pub reason: String,
    pub backend: String,
    pub blocked_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub expired: bool,
    pub firewall_present: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockMaintenanceReport {
    pub expired_blocks: usize,
    pub stale_blocks: usize,
    pub failed_expirations: usize,
    pub failed_state_checks: usize,
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
    ip: IpAddr,
    rule_id: String,
    finding_id: String,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BlockState {
    blocks: BTreeMap<String, BlockRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockRecord {
    ip: String,
    rule_id: String,
    finding_id: String,
    reason: String,
    backend: String,
    blocked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

trait IpBlocker {
    fn backend_name(&self) -> &'static str;
    fn block_ip(&self, ip: IpAddr, ttl: Duration) -> SentinelResult<()>;
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
    let ttl = Duration::from_secs(config.active_response.block_ttl_seconds);
    let expires_at = now + ChronoDuration::seconds(duration_seconds(ttl.as_secs()));

    let candidates = block_candidates(findings, config);
    report.planned_blocks = candidates.len();
    let mut attempted_new_blocks = 0usize;
    for candidate in candidates {
        if let Some(existing) = state.blocks.get(&candidate.ip.to_string()) {
            report.skipped_existing_blocks += 1;
            report.block_actions.push(BlockAction {
                finding_id: candidate.finding_id,
                ip: candidate.ip,
                status: BlockActionStatus::AlreadyBlocked,
                reason: candidate.reason,
                backend: Some(existing.backend.clone()),
                expires_at: Some(existing.expires_at),
                detail: None,
            });
            continue;
        }
        if attempted_new_blocks >= config.active_response.max_blocks_per_scan {
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
        attempted_new_blocks += 1;
        match blocker.block_ip(candidate.ip, ttl) {
            Ok(()) => {
                report.applied_blocks += 1;
                report.block_actions.push(BlockAction {
                    finding_id: candidate.finding_id.clone(),
                    ip: candidate.ip,
                    status: BlockActionStatus::Blocked,
                    reason: candidate.reason.clone(),
                    backend: Some(blocker.backend_name().to_string()),
                    expires_at: Some(expires_at),
                    detail: None,
                });
                state.blocks.insert(
                    candidate.ip.to_string(),
                    BlockRecord {
                        ip: candidate.ip.to_string(),
                        rule_id: candidate.rule_id,
                        finding_id: candidate.finding_id,
                        reason: candidate.reason,
                        backend: blocker.backend_name().to_string(),
                        blocked_at: now,
                        expires_at,
                    },
                );
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
                expired: record.expires_at <= now,
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
    let expired = state
        .blocks
        .iter()
        .filter(|(_, record)| record.expires_at <= now)
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

fn block_candidates(findings: &[Finding], config: &SentinelConfig) -> Vec<BlockCandidate> {
    let mut candidates = BTreeMap::<IpAddr, BlockCandidate>::new();
    for finding in findings {
        let Some(candidate) = block_candidate(finding, config) else {
            continue;
        };
        candidates.entry(candidate.ip).or_insert(candidate);
    }
    candidates.into_values().collect()
}

fn block_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    let candidate = match finding.rule_id.as_str() {
        "WEB-001" if config.active_response.web_enabled => web_probe_candidate(finding, config),
        "WEB-002" if config.active_response.web_enabled => web_error_candidate(finding, config),
        "SSH-003" if config.active_response.ssh_enabled => {
            ssh_bruteforce_candidate(finding, config)
        }
        _ => None,
    }?;
    if field_is_allowlisted(&candidate.ip.to_string(), &config.allowlist.ips) {
        return None;
    }
    if !is_public_remote_ip(candidate.ip) {
        return None;
    }
    Some(candidate)
}

fn web_probe_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    let ip = evidence_ip(finding, "ip")?;
    let family = evidence_value(finding, "probe_family")?;
    let response = evidence_value(finding, "response_profile")?;
    let request_count = evidence_usize(finding, "request_count")?;
    let threshold =
        if response == "successful_response" || is_single_attempt_web_exploit_family(family) {
            1
        } else if is_exploit_probe_family(family) {
            config.active_response.web_exploit_block_threshold
        } else {
            config.active_response.web_probe_block_threshold
        };
    if request_count < threshold {
        return None;
    }
    Some(BlockCandidate {
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!(
            "web probe family={family} response={response} request_count={request_count}"
        ),
    })
}

fn web_error_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    let ip = evidence_ip(finding, "ip")?;
    let error_count = evidence_usize(finding, "error_count")?;
    if error_count < config.active_response.web_probe_block_threshold {
        return None;
    }
    Some(BlockCandidate {
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!("web error burst error_count={error_count}"),
    })
}

fn ssh_bruteforce_candidate(finding: &Finding, config: &SentinelConfig) -> Option<BlockCandidate> {
    let ip = evidence_ip(finding, "source_ip")?;
    let failure_count = evidence_usize(finding, "failure_count")?;
    if failure_count < config.active_response.ssh_failed_login_block_threshold {
        return None;
    }
    Some(BlockCandidate {
        ip,
        rule_id: finding.rule_id.clone(),
        finding_id: finding.id.clone(),
        reason: format!("ssh brute force failure_count={failure_count}"),
    })
}

fn is_exploit_probe_family(family: &str) -> bool {
    matches!(
        family,
        "cgi_shell_traversal"
            | "command_injection"
            | "php_config_injection"
            | "sql_injection"
            | "phpunit_eval_stdin"
    )
}

fn is_single_attempt_web_exploit_family(family: &str) -> bool {
    matches!(
        family,
        "cgi_shell_traversal" | "command_injection" | "php_config_injection" | "phpunit_eval_stdin"
    )
}

fn evidence_ip(finding: &Finding, key: &str) -> Option<IpAddr> {
    evidence_value(finding, key)?.parse().ok()
}

fn evidence_usize(finding: &Finding, key: &str) -> Option<usize> {
    evidence_value(finding, key)?.parse().ok()
}

fn evidence_value<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding
        .evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.as_str())
}

fn is_public_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || is_this_network_ipv4(ip)
        || is_protocol_assignment_ipv4(ip)
        || is_documentation_ipv4(ip)
        || is_benchmark_ipv4(ip)
        || is_reserved_ipv4(ip)
        || is_shared_address_space_ipv4(ip))
}

fn is_this_network_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 0
}

fn is_protocol_assignment_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 192 && octets[1] == 0 && octets[2] == 0
}

fn is_documentation_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_benchmark_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && matches!(octets[1], 18 | 19)
}

fn is_shared_address_space_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
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

    fn block_ip(&self, ip: IpAddr, ttl: Duration) -> SentinelResult<()> {
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

    fn block_ip(self, ip: IpAddr, ttl: Duration, timeout: Duration) -> SentinelResult<()> {
        match self {
            Self::Nftables => nft_block_ip(ip, ttl, timeout),
            Self::Iptables => iptables_block_ip(ip, timeout),
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

fn nft_block_ip(ip: IpAddr, ttl: Duration, timeout: Duration) -> SentinelResult<()> {
    ensure_nftables_base(ip, timeout)?;
    if nft_is_blocked(ip, timeout)? {
        return Ok(());
    }
    let set_name = nft_set_name(ip);
    run_command_required(
        "nft",
        &[
            "add".to_string(),
            "element".to_string(),
            "inet".to_string(),
            "vps_sentinel".to_string(),
            set_name.to_string(),
            "{".to_string(),
            ip.to_string(),
            "timeout".to_string(),
            format!("{}s", ttl.as_secs()),
            "}".to_string(),
        ],
        timeout,
    )
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

fn iptables_block_ip(ip: IpAddr, timeout: Duration) -> SentinelResult<()> {
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
        BlockActionStatus, BlockRecord, BlockState, IpBlocker, SentinelResult, STATE_RULE_ID,
    };
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
    fn high_confidence_web_exploit_blocks_on_single_attempt() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_exploit_block_threshold = 5;
        let cgi_shell = web_finding("4.4.4.4", "cgi_shell_traversal", "missing_or_rejected", 1);
        let phpunit = web_finding("4.4.8.8", "phpunit_eval_stdin", "missing_or_rejected", 1);
        let php_config = web_finding("4.4.9.9", "php_config_injection", "missing_or_rejected", 1);
        let sql_below_threshold = web_finding("8.8.4.4", "sql_injection", "missing_or_rejected", 1);

        let candidates = block_candidates(
            &[cgi_shell, phpunit, php_config, sql_below_threshold],
            &config,
        );

        assert_eq!(candidates.len(), 3);
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.4.4"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.8.8"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "4.4.9.9"));
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
                expires_at: now + ChronoDuration::minutes(5),
            },
        );
        store.save_rule_state(STATE_RULE_ID, &BlockState { blocks })?;

        let entries = list_active_blocks(&SentinelConfig::default(), &store, false)?;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, "8.8.8.8");
        assert_eq!(entries[0].firewall_present, None);
        assert!(!entries[0].expired);
        Ok(())
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

        fn block_ip(&self, _ip: std::net::IpAddr, _ttl: std::time::Duration) -> SentinelResult<()> {
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
