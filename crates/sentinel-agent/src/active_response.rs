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
    pub failed_blocks: usize,
    pub expired_blocks: usize,
    pub failed_expirations: usize,
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
    fn unblock_ip(&self, ip: IpAddr) -> SentinelResult<()>;
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
        return Ok(ActiveResponseReport {
            failed_blocks: block_candidates(findings, config).len(),
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
    let mut report = expire_blocks(&mut state, blocker, now);
    let ttl = Duration::from_secs(config.active_response.block_ttl_seconds);
    let expires_at = now + ChronoDuration::seconds(duration_seconds(ttl.as_secs()));

    let candidates = block_candidates(findings, config);
    report.planned_blocks = candidates.len();
    let mut attempted_new_blocks = 0usize;
    for candidate in candidates {
        if state.blocks.contains_key(&candidate.ip.to_string()) {
            report.skipped_existing_blocks += 1;
            continue;
        }
        if attempted_new_blocks >= config.active_response.max_blocks_per_scan {
            break;
        }
        attempted_new_blocks += 1;
        match blocker.block_ip(candidate.ip, ttl) {
            Ok(()) => {
                report.applied_blocks += 1;
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
            }
        }
    }
    store.save_rule_state(STATE_RULE_ID, &state)?;
    Ok(report)
}

fn expire_blocks(
    state: &mut BlockState,
    blocker: &dyn IpBlocker,
    now: DateTime<Utc>,
) -> ActiveResponseReport {
    let mut report = ActiveResponseReport::default();
    let expired = state
        .blocks
        .iter()
        .filter(|(_, record)| record.expires_at <= now)
        .filter_map(|(ip, record)| {
            let parsed = record.ip.parse::<IpAddr>().ok()?;
            Some((ip.clone(), parsed))
        })
        .collect::<Vec<_>>();

    for (key, ip) in expired {
        match blocker.unblock_ip(ip) {
            Ok(()) => {
                report.expired_blocks += 1;
                state.blocks.remove(&key);
            }
            Err(err) => {
                report.failed_expirations += 1;
                warn!(ip = %ip, error = %err, "active response unblock failed");
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
    let threshold = if response == "successful_response" {
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
        "cgi_shell_traversal" | "command_injection" | "sql_injection" | "phpunit_eval_stdin"
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
        || is_documentation_ipv4(ip)
        || is_shared_address_space_ipv4(ip))
}

fn is_documentation_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_shared_address_space_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
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
}

impl IpBlocker for SystemIpBlocker {
    fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    fn block_ip(&self, ip: IpAddr, ttl: Duration) -> SentinelResult<()> {
        self.backend.block_ip(ip, ttl, self.timeout)
    }

    fn unblock_ip(&self, ip: IpAddr) -> SentinelResult<()> {
        self.backend.unblock_ip(ip, self.timeout)
    }
}

#[derive(Debug, Clone, Copy)]
enum FirewallBackend {
    Nftables,
    Iptables,
}

impl FirewallBackend {
    fn name(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        }
    }

    fn block_ip(self, ip: IpAddr, ttl: Duration, timeout: Duration) -> SentinelResult<()> {
        match self {
            Self::Nftables => nft_block_ip(ip, ttl, timeout),
            Self::Iptables => iptables_block_ip(ip, timeout),
        }
    }

    fn unblock_ip(self, ip: IpAddr, timeout: Duration) -> SentinelResult<()> {
        match self {
            Self::Nftables => nft_unblock_ip(ip, timeout),
            Self::Iptables => iptables_unblock_ip(ip, timeout),
        }
    }
}

fn nft_block_ip(ip: IpAddr, ttl: Duration, timeout: Duration) -> SentinelResult<()> {
    ensure_nftables_base(ip, timeout)?;
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

fn nft_unblock_ip(ip: IpAddr, timeout: Duration) -> SentinelResult<()> {
    run_command_best_effort_owned(
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
    );
    Ok(())
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
    run_command_required(
        iptables_program(ip),
        &[
            "-I".to_string(),
            "INPUT".to_string(),
            "-s".to_string(),
            ip.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            "vps-sentinel".to_string(),
        ],
        timeout,
    )
}

fn iptables_unblock_ip(ip: IpAddr, timeout: Duration) -> SentinelResult<()> {
    run_command_best_effort_owned(
        iptables_program(ip),
        &[
            "-D".to_string(),
            "INPUT".to_string(),
            "-s".to_string(),
            ip.to_string(),
            "-j".to_string(),
            "DROP".to_string(),
            "-m".to_string(),
            "comment".to_string(),
            "--comment".to_string(),
            "vps-sentinel".to_string(),
        ],
        timeout,
    );
    Ok(())
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

fn run_command_best_effort(program: &str, args: &[&str], timeout: Duration) {
    let _ = command_output(program, args, timeout);
}

fn run_command_best_effort_owned(program: &str, args: &[String], timeout: Duration) {
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let _ = command_output(program, &arg_refs, timeout);
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
    use super::{block_candidates, is_public_remote_ip};
    use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

    #[test]
    fn web_probe_blocks_only_after_strict_thresholds() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.web_probe_block_threshold = 25;
        config.active_response.web_exploit_block_threshold = 5;
        let low_noise = web_finding("8.8.8.8", "phpunit_eval_stdin", "missing_or_rejected", 3);
        let high_volume = web_finding("8.8.4.4", "phpunit_eval_stdin", "missing_or_rejected", 25);
        let exploit = web_finding("1.1.1.1", "command_injection", "missing_or_rejected", 5);
        let successful = web_finding("9.9.9.9", "env_file", "successful_response", 1);

        let candidates = block_candidates(&[low_noise, high_volume, exploit, successful], &config);

        assert_eq!(candidates.len(), 3);
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "8.8.4.4"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "1.1.1.1"));
        assert!(candidates
            .iter()
            .any(|item| item.ip.to_string() == "9.9.9.9"));
    }

    #[test]
    fn ssh_bruteforce_blocks_only_at_block_threshold() {
        let mut config = SentinelConfig::default();
        config.active_response.enabled = true;
        config.active_response.ssh_failed_login_block_threshold = 20;
        let below = ssh_finding("8.8.8.8", 19);
        let above = ssh_finding("1.1.1.1", 20);

        let candidates = block_candidates(&[below, above], &config);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ip.to_string(), "1.1.1.1");
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
        assert!(!is_public_remote_ip("192.0.2.1".parse().unwrap()));
        assert!(!is_public_remote_ip("::1".parse().unwrap()));
        assert!(!is_public_remote_ip("fc00::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:db8::1".parse().unwrap()));
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
}
