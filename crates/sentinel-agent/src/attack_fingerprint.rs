use crate::storage::SqliteStore;
use chrono::{DateTime, Utc};
use sentinel_core::{Category, Evidence, Finding, SentinelConfig, SentinelResult, Severity};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

pub const ACTION_HINT_KEY: &str = "attack_fingerprint_action_hint";
pub const FINGERPRINT_ID_KEY: &str = "attack_fingerprint_id";

pub const VERDICT_UNKNOWN: &str = "unknown";
pub const VERDICT_BENIGN: &str = "benign";
pub const VERDICT_MALICIOUS: &str = "malicious";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttackFingerprintReport {
    pub observations: usize,
    pub created: usize,
    pub matched_exact: usize,
    pub matched_similar: usize,
    pub action_hints: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackFingerprint {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub exact_hash: String,
    pub simhash: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub seen_count: usize,
    pub source_ips: Vec<String>,
    pub hosts: Vec<String>,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub score: u16,
    pub confidence: u16,
    pub verdict: String,
    pub summary: String,
    pub features: Vec<FingerprintFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackObservation {
    pub id: String,
    pub fingerprint_id: String,
    pub finding_id: String,
    pub host_id: String,
    pub source_ip: String,
    pub rule_id: String,
    pub observed_at: DateTime<Utc>,
    pub features: Vec<FingerprintFeature>,
    pub evidence_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FingerprintFeature {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintExplanation {
    pub fingerprint_id: String,
    pub kind: String,
    pub verdict: String,
    pub risk_tier: String,
    pub recommended_action: String,
    pub score: u16,
    pub confidence: u16,
    pub seen_count: usize,
    pub source_ip_count: usize,
    pub host_count: usize,
    pub rule_count: usize,
    pub signals: Vec<String>,
    pub limitations: Vec<String>,
    pub top_features: Vec<FingerprintFeature>,
    pub recent_observations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    New,
    Exact,
    Similar,
}

#[derive(Debug, Clone)]
struct FingerprintCandidate {
    kind: String,
    title: String,
    source_ip: String,
    exact_hash: String,
    simhash: u64,
    score: u16,
    confidence: u16,
    summary: String,
    features: Vec<FingerprintFeature>,
}

#[derive(Debug, Clone)]
struct MatchedFingerprint {
    fingerprint: AttackFingerprint,
    kind: MatchKind,
}

pub fn enrich_and_persist_findings(
    findings: &mut [Finding],
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<AttackFingerprintReport> {
    if !config.attack_fingerprints.enabled {
        return Ok(AttackFingerprintReport::default());
    }

    let mut report = AttackFingerprintReport::default();
    for finding in findings {
        let Some(candidate) = fingerprint_candidate(finding) else {
            continue;
        };
        report.observations += 1;
        let matched = match_fingerprint(store, &candidate, config)?;
        let match_kind = matched.kind;
        let mut fingerprint = merge_fingerprint(matched, &candidate, finding, config);
        let action_hint = should_hint_active_response(&fingerprint, &candidate, finding, config);
        if action_hint {
            report.action_hints += 1;
        }
        enrich_finding(finding, &fingerprint, action_hint);
        let observation = observation_from_candidate(&candidate, &fingerprint, finding, config);
        match match_kind {
            MatchKind::New => report.created += 1,
            MatchKind::Exact => report.matched_exact += 1,
            MatchKind::Similar => report.matched_similar += 1,
        }
        fingerprint
            .features
            .truncate(config.attack_fingerprints.max_features_per_fingerprint);
        store.save_attack_fingerprint(&fingerprint)?;
        store.save_attack_observation(
            &observation,
            config.attack_fingerprints.max_observations_per_fingerprint,
        )?;
    }
    Ok(report)
}

fn match_fingerprint(
    store: &SqliteStore,
    candidate: &FingerprintCandidate,
    config: &SentinelConfig,
) -> SentinelResult<MatchedFingerprint> {
    if let Some(fingerprint) =
        store.find_attack_fingerprint_by_exact_hash(&candidate.kind, &candidate.exact_hash)?
    {
        return Ok(MatchedFingerprint {
            fingerprint,
            kind: MatchKind::Exact,
        });
    }
    if !config.attack_fingerprints.similarity_enabled {
        return Ok(MatchedFingerprint {
            fingerprint: new_fingerprint(candidate),
            kind: MatchKind::New,
        });
    }
    let similar = store
        .list_attack_fingerprints_by_kind(
            &candidate.kind,
            config.attack_fingerprints.max_match_candidates,
        )?
        .into_iter()
        .filter_map(|fingerprint| {
            let simhash = parse_simhash(&fingerprint.simhash)?;
            let distance = hamming_distance(candidate.simhash, simhash);
            (distance <= config.attack_fingerprints.similarity_hamming_distance)
                .then_some((distance, fingerprint))
        })
        .min_by_key(|(distance, fingerprint)| (*distance, Reverse(fingerprint.last_seen_at)));
    if let Some((_, fingerprint)) = similar {
        return Ok(MatchedFingerprint {
            fingerprint,
            kind: MatchKind::Similar,
        });
    }
    Ok(MatchedFingerprint {
        fingerprint: new_fingerprint(candidate),
        kind: MatchKind::New,
    })
}

fn merge_fingerprint(
    matched: MatchedFingerprint,
    candidate: &FingerprintCandidate,
    finding: &Finding,
    config: &SentinelConfig,
) -> AttackFingerprint {
    let now = finding.timestamp;
    let mut fingerprint = matched.fingerprint;
    match matched.kind {
        MatchKind::New => {
            fingerprint.first_seen_at = now;
            fingerprint.last_seen_at = now;
        }
        MatchKind::Exact | MatchKind::Similar => {
            fingerprint.last_seen_at = fingerprint.last_seen_at.max(now);
            fingerprint.first_seen_at = fingerprint.first_seen_at.min(now);
            fingerprint.seen_count = fingerprint.seen_count.saturating_add(1);
            fingerprint.score = fingerprint.score.max(candidate.score);
            fingerprint.confidence = fingerprint.confidence.max(candidate.confidence);
            fingerprint.summary = candidate.summary.clone();
        }
    }
    merge_sorted_unique(
        &mut fingerprint.source_ips,
        &stored_source_ip(config, &candidate.source_ip),
        64,
    );
    merge_sorted_unique(&mut fingerprint.hosts, &finding.host_id, 32);
    merge_sorted_unique(&mut fingerprint.rule_ids, &finding.rule_id, 32);
    merge_sorted_unique(
        &mut fingerprint.categories,
        &finding.category.to_string(),
        16,
    );
    merge_features(
        &mut fingerprint.features,
        &candidate.features,
        config.attack_fingerprints.max_features_per_fingerprint,
    );
    fingerprint.score = composite_score(&fingerprint, candidate);
    fingerprint.confidence = fingerprint.confidence.max(candidate.confidence).min(100);
    fingerprint
}

fn new_fingerprint(candidate: &FingerprintCandidate) -> AttackFingerprint {
    let now = Utc::now();
    AttackFingerprint {
        id: fingerprint_id(&candidate.kind, &candidate.exact_hash),
        kind: candidate.kind.clone(),
        title: candidate.title.clone(),
        exact_hash: candidate.exact_hash.clone(),
        simhash: format_simhash(candidate.simhash),
        first_seen_at: now,
        last_seen_at: now,
        seen_count: 1,
        source_ips: Vec::new(),
        hosts: Vec::new(),
        rule_ids: Vec::new(),
        categories: Vec::new(),
        score: candidate.score,
        confidence: candidate.confidence,
        verdict: VERDICT_UNKNOWN.to_string(),
        summary: candidate.summary.clone(),
        features: candidate.features.clone(),
    }
}

fn observation_from_candidate(
    candidate: &FingerprintCandidate,
    fingerprint: &AttackFingerprint,
    finding: &Finding,
    config: &SentinelConfig,
) -> AttackObservation {
    AttackObservation {
        id: uuid::Uuid::new_v4().to_string(),
        fingerprint_id: fingerprint.id.clone(),
        finding_id: finding.id.clone(),
        host_id: finding.host_id.clone(),
        source_ip: stored_source_ip(config, &candidate.source_ip),
        rule_id: finding.rule_id.clone(),
        observed_at: finding.timestamp,
        features: candidate.features.clone(),
        evidence_summary: evidence_summary(finding),
    }
}

fn stored_source_ip(config: &SentinelConfig, source_ip: &str) -> String {
    let source_ip = source_ip.trim();
    if source_ip.is_empty() {
        return String::new();
    }
    if !config.privacy.mask_ip {
        return source_ip.to_string();
    }
    let hash = blake3::hash(source_ip.as_bytes()).to_hex().to_string();
    format!("ip-hash-{}", &hash[..12])
}

fn fingerprint_candidate(finding: &Finding) -> Option<FingerprintCandidate> {
    match finding.category {
        Category::Web => web_candidate(finding),
        Category::Ssh => ssh_candidate(finding),
        Category::Process | Category::Rootkit => host_behavior_candidate(finding, "host_process"),
        Category::Persistence | Category::FileIntegrity | Category::User | Category::Privilege => {
            host_behavior_candidate(finding, "host_persistence")
        }
        _ => None,
    }
}

fn web_candidate(finding: &Finding) -> Option<FingerprintCandidate> {
    if !matches!(finding.rule_id.as_str(), "WEB-001" | "WEB-002") {
        return None;
    }
    let mut features = FeatureBuilder::new("web_probe");
    features.add("rule", &finding.rule_id);
    features.add("category", finding.category.to_string());
    features.add_list("families", evidence_list(finding, "probe_families"));
    features.add(
        "family",
        evidence_value(finding, "probe_family").unwrap_or(""),
    );
    features.add_list("responses", evidence_list(finding, "response_profiles"));
    features.add(
        "response",
        evidence_value(finding, "response_profile").unwrap_or(""),
    );
    features.add_list("methods", evidence_list(finding, "methods"));
    features.add_list("statuses", evidence_list(finding, "statuses"));
    features.add_list(
        "path_shapes",
        evidence_list(finding, "sample_paths")
            .into_iter()
            .map(|path| normalize_web_path(&path))
            .collect(),
    );
    if let Some(count) =
        evidence_value(finding, "request_count").or_else(|| evidence_value(finding, "error_count"))
    {
        features.add("volume_bucket", volume_bucket(count));
    }
    let features = features.finish();
    if features.is_empty() {
        return None;
    }
    let score = finding_score(finding)
        .saturating_add(web_feature_bonus(finding))
        .min(100);
    Some(candidate_from_features(
        "web_probe",
        "Web attack fingerprint",
        source_ip(finding),
        score,
        confidence_percent(finding),
        web_summary(finding),
        features,
    ))
}

fn ssh_candidate(finding: &Finding) -> Option<FingerprintCandidate> {
    if !matches!(finding.rule_id.as_str(), "SSH-003" | "SSH-007") {
        return None;
    }
    let users = evidence_list(finding, "users")
        .into_iter()
        .chain(evidence_list(finding, "failed_users"))
        .map(|user| normalize_ssh_user(&user))
        .collect::<Vec<_>>();
    let mut features = FeatureBuilder::new("ssh_bruteforce");
    features.add("rule", &finding.rule_id);
    features.add("category", finding.category.to_string());
    features.add_list("users", users);
    if let Some(count) = evidence_value(finding, "failure_count") {
        features.add("failure_bucket", volume_bucket(count));
    }
    features.add_list(
        "success_users",
        evidence_list(finding, "success_users")
            .into_iter()
            .map(|user| normalize_ssh_user(&user))
            .collect(),
    );
    let features = features.finish();
    if features.is_empty() {
        return None;
    }
    let score = finding_score(finding)
        .saturating_add(ssh_feature_bonus(finding))
        .min(100);
    Some(candidate_from_features(
        "ssh_bruteforce",
        "SSH attack fingerprint",
        source_ip(finding),
        score,
        confidence_percent(finding),
        ssh_summary(finding),
        features,
    ))
}

fn host_behavior_candidate(finding: &Finding, kind: &str) -> Option<FingerprintCandidate> {
    let mut features = FeatureBuilder::new(kind);
    features.add("rule", &finding.rule_id);
    features.add("category", finding.category.to_string());
    if let Some(name) =
        evidence_value(finding, "process_name").or_else(|| evidence_value(finding, "name"))
    {
        features.add("process_name", name);
    }
    for key in [
        "exe_hash_blake3",
        "package_owner",
        "parent_name",
        "systemd_unit",
        "outbound_remote_ports",
        "gpu_process",
        "file_type",
        "entry_type",
    ] {
        features.add(key, evidence_value(finding, key).unwrap_or(""));
    }
    for key in ["exe_path", "path", "cmdline"] {
        if let Some(value) = evidence_value(finding, key) {
            features.add(key, normalize_host_value(key, value));
        }
    }
    let features = features.finish();
    if features.len() < 3 {
        return None;
    }
    Some(candidate_from_features(
        kind,
        "Host behavior fingerprint",
        source_ip(finding),
        finding_score(finding),
        confidence_percent(finding),
        format!("{} {}", finding.rule_id, finding.title),
        features,
    ))
}

fn candidate_from_features(
    kind: &str,
    title: &str,
    source_ip: String,
    score: u16,
    confidence: u16,
    summary: String,
    features: Vec<FingerprintFeature>,
) -> FingerprintCandidate {
    let exact_hash = exact_hash(kind, &features);
    let simhash = simhash(kind, &features);
    FingerprintCandidate {
        kind: kind.to_string(),
        title: title.to_string(),
        source_ip,
        exact_hash,
        simhash,
        score,
        confidence,
        summary,
        features,
    }
}

fn should_hint_active_response(
    fingerprint: &AttackFingerprint,
    candidate: &FingerprintCandidate,
    finding: &Finding,
    config: &SentinelConfig,
) -> bool {
    if !config.attack_fingerprints.active_response_enabled || candidate.source_ip.is_empty() {
        return false;
    }
    if fingerprint.verdict == VERDICT_BENIGN || proxy_source_unresolved(finding) {
        return false;
    }
    if fingerprint.verdict == VERDICT_MALICIOUS {
        return true;
    }
    fingerprint.score >= config.attack_fingerprints.active_response_min_score
        && fingerprint.seen_count >= config.attack_fingerprints.active_response_min_observations
        && fingerprint.source_ips.len()
            >= config.attack_fingerprints.active_response_min_distinct_ips
}

fn enrich_finding(finding: &mut Finding, fingerprint: &AttackFingerprint, action_hint: bool) {
    upsert_evidence(
        &mut finding.evidence,
        FINGERPRINT_ID_KEY,
        fingerprint.id.clone(),
    );
    upsert_evidence(
        &mut finding.evidence,
        "attack_fingerprint_kind",
        fingerprint.kind.clone(),
    );
    upsert_evidence(
        &mut finding.evidence,
        "attack_fingerprint_score",
        fingerprint.score.to_string(),
    );
    upsert_evidence(
        &mut finding.evidence,
        "attack_fingerprint_seen_count",
        fingerprint.seen_count.to_string(),
    );
    upsert_evidence(
        &mut finding.evidence,
        "attack_fingerprint_source_ip_count",
        fingerprint.source_ips.len().to_string(),
    );
    if fingerprint.verdict != VERDICT_UNKNOWN {
        upsert_evidence(
            &mut finding.evidence,
            "attack_fingerprint_verdict",
            fingerprint.verdict.clone(),
        );
    }
    if action_hint {
        upsert_evidence(&mut finding.evidence, ACTION_HINT_KEY, "block");
    }
}

fn composite_score(fingerprint: &AttackFingerprint, candidate: &FingerprintCandidate) -> u16 {
    let mut score = fingerprint.score.max(candidate.score);
    if fingerprint.seen_count >= 2 {
        score = score.saturating_add(5);
    }
    if fingerprint.source_ips.len() >= 2 {
        score = score.saturating_add(10);
    }
    if fingerprint.hosts.len() >= 2 {
        score = score.saturating_add(10);
    }
    if fingerprint.verdict == VERDICT_MALICIOUS {
        score = score.saturating_add(15);
    }
    score.min(100)
}

fn finding_score(finding: &Finding) -> u16 {
    evidence_value(finding, "unified_risk_score")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| severity_score(finding.severity))
        .min(100)
}

fn severity_score(severity: Severity) -> u16 {
    match severity {
        Severity::Info => 10,
        Severity::Low => 30,
        Severity::Medium => 55,
        Severity::High => 75,
        Severity::Critical => 90,
    }
}

fn confidence_percent(finding: &Finding) -> u16 {
    match finding.confidence {
        sentinel_core::Confidence::Low => 40,
        sentinel_core::Confidence::Medium => 65,
        sentinel_core::Confidence::High => 85,
    }
}

fn web_feature_bonus(finding: &Finding) -> u16 {
    let mut bonus: u16 = 0;
    if evidence_value(finding, "response_profile") == Some("successful_response") {
        bonus = bonus.saturating_add(20);
    }
    if evidence_value(finding, "probe_family").is_some_and(is_high_confidence_web_family) {
        bonus = bonus.saturating_add(15);
    }
    bonus
}

fn ssh_feature_bonus(finding: &Finding) -> u16 {
    let users = evidence_list(finding, "users")
        .len()
        .max(evidence_list(finding, "failed_users").len());
    if users >= 8 {
        10
    } else {
        0
    }
}

fn is_high_confidence_web_family(value: &str) -> bool {
    matches!(
        value,
        "command_injection"
            | "cgi_shell_traversal"
            | "php_config_injection"
            | "lfi_file_read"
            | "php_stream_wrapper"
            | "java_jndi_injection"
            | "ssrf_metadata"
            | "phpunit_eval_stdin"
    )
}

fn web_summary(finding: &Finding) -> String {
    let families = evidence_value(finding, "probe_families")
        .or_else(|| evidence_value(finding, "probe_family"))
        .unwrap_or("unknown");
    let responses = evidence_value(finding, "response_profiles")
        .or_else(|| evidence_value(finding, "response_profile"))
        .unwrap_or("unknown");
    format!(
        "{} families={families} responses={responses}",
        finding.rule_id
    )
}

fn ssh_summary(finding: &Finding) -> String {
    let users = evidence_value(finding, "users")
        .or_else(|| evidence_value(finding, "failed_users"))
        .unwrap_or("");
    let failures = evidence_value(finding, "failure_count").unwrap_or("0");
    format!("{} failures={failures} users={users}", finding.rule_id)
}

fn evidence_summary(finding: &Finding) -> String {
    finding
        .evidence
        .iter()
        .filter(|item| {
            matches!(
                item.key.as_str(),
                "probe_family"
                    | "probe_families"
                    | "response_profile"
                    | "request_count"
                    | "failure_count"
                    | "users"
                    | "exe_path"
                    | "process_name"
                    | "path"
            )
        })
        .take(8)
        .map(|item| format!("{}={}", item.key, item.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn exact_hash(kind: &str, features: &[FingerprintFeature]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    for feature in features {
        hasher.update(feature.key.as_bytes());
        hasher.update(b"=");
        hasher.update(feature.value.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()
}

fn fingerprint_id(kind: &str, exact_hash: &str) -> String {
    let prefix = match kind {
        "web_probe" => "WEB-FP",
        "ssh_bruteforce" => "SSH-FP",
        "host_process" => "PROC-FP",
        "host_persistence" => "PERSIST-FP",
        _ => "ATTACK-FP",
    };
    format!("{prefix}-{}", &exact_hash[..12])
}

fn simhash(kind: &str, features: &[FingerprintFeature]) -> u64 {
    let mut weights = [0i32; 64];
    for token in simhash_tokens(kind, features) {
        let hash = blake3::hash(token.as_bytes());
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.as_bytes()[..8]);
        let value = u64::from_le_bytes(bytes);
        let weight = token_weight(&token);
        for (bit, slot) in weights.iter_mut().enumerate() {
            if value & (1u64 << bit) == 0 {
                *slot -= weight;
            } else {
                *slot += weight;
            }
        }
    }
    weights
        .into_iter()
        .enumerate()
        .fold(0u64, |acc, (bit, weight)| {
            if weight >= 0 {
                acc | (1u64 << bit)
            } else {
                acc
            }
        })
}

fn simhash_tokens(kind: &str, features: &[FingerprintFeature]) -> Vec<String> {
    let mut tokens = vec![format!("kind:{kind}")];
    for feature in features {
        tokens.push(format!("{}={}", feature.key, feature.value));
        for value in split_values(&feature.value) {
            tokens.push(format!("{}:{value}", feature.key));
        }
    }
    tokens.sort();
    tokens.dedup();
    tokens
}

fn token_weight(token: &str) -> i32 {
    if token.contains("rule=") || token.contains("family") || token.contains("path_shapes") {
        3
    } else {
        1
    }
}

fn hamming_distance(left: u64, right: u64) -> u32 {
    (left ^ right).count_ones()
}

fn format_simhash(value: u64) -> String {
    format!("{value:016x}")
}

fn parse_simhash(value: &str) -> Option<u64> {
    u64::from_str_radix(value, 16).ok()
}

fn source_ip(finding: &Finding) -> String {
    for key in [
        "source_ip",
        "ip",
        "remote_ip",
        "remote_addr",
        "active_response_ip",
    ] {
        if let Some(value) = evidence_value(finding, key).filter(|value| !value.trim().is_empty()) {
            return value.trim().to_string();
        }
    }
    String::new()
}

fn proxy_source_unresolved(finding: &Finding) -> bool {
    evidence_value(finding, "proxy_source_unresolved") == Some("true")
}

fn evidence_value<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    sentinel_core::evidence_value(&finding.evidence, key)
}

fn evidence_list(finding: &Finding, key: &str) -> Vec<String> {
    sentinel_core::evidence_values(&finding.evidence, key)
}

fn split_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn volume_bucket(value: &str) -> &'static str {
    let count = value.parse::<usize>().unwrap_or(0);
    match count {
        0..=1 => "single",
        2..=5 => "low",
        6..=20 => "medium",
        21..=100 => "high",
        _ => "extreme",
    }
}

fn normalize_web_path(path: &str) -> String {
    let decoded = percent_decode_lossy(path).to_ascii_lowercase();
    let mut normalized = String::with_capacity(decoded.len());
    let mut chars = decoded.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                chars.next();
            }
            normalized.push_str("{num}");
        } else if ch.is_ascii_hexdigit() && next_hex_run_len(&chars) >= 7 {
            while chars.peek().is_some_and(|next| next.is_ascii_hexdigit()) {
                chars.next();
            }
            normalized.push_str("{hex}");
        } else {
            normalized.push(ch);
        }
    }
    normalized.split('&').take(8).collect::<Vec<_>>().join("&")
}

fn next_hex_run_len<I>(chars: &std::iter::Peekable<I>) -> usize
where
    I: Iterator<Item = char> + Clone,
{
    let mut len = 0usize;
    let mut cloned = chars.clone();
    while cloned.peek().is_some_and(|ch| ch.is_ascii_hexdigit()) {
        len += 1;
        cloned.next();
    }
    len
}

fn normalize_ssh_user(user: &str) -> String {
    let user = user.trim().to_ascii_lowercase();
    if user.chars().any(|ch| ch.is_ascii_digit()) {
        collapse_digit_runs(&user)
    } else {
        user
    }
}

fn normalize_host_value(key: &str, value: &str) -> String {
    let value = value.trim();
    if key == "cmdline" {
        return value
            .split_whitespace()
            .take(8)
            .map(collapse_digit_runs)
            .collect::<Vec<_>>()
            .join(" ");
    }
    collapse_digit_runs(value)
        .replace("/lib/systemd/system/", "/usr/lib/systemd/system/")
        .replace(" (deleted)", "")
}

fn collapse_digit_runs(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut in_digits = false;
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                normalized.push_str("{num}");
                in_digits = true;
            }
        } else {
            in_digits = false;
            normalized.push(ch);
        }
    }
    normalized
}

fn percent_decode_lossy(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn merge_sorted_unique(values: &mut Vec<String>, value: &str, limit: usize) {
    if value.trim().is_empty() {
        return;
    }
    values.push(value.trim().to_string());
    values.sort();
    values.dedup();
    values.truncate(limit);
}

fn merge_features(
    target: &mut Vec<FingerprintFeature>,
    source: &[FingerprintFeature],
    limit: usize,
) {
    target.extend(source.iter().cloned());
    target.sort();
    target.dedup();
    target.truncate(limit);
}

fn upsert_evidence(evidence: &mut Vec<Evidence>, key: &str, value: impl Into<String>) {
    sentinel_core::upsert_evidence(evidence, key, value);
}

struct FeatureBuilder {
    features: BTreeMap<String, BTreeSet<String>>,
}

impl FeatureBuilder {
    fn new(kind: &str) -> Self {
        let mut builder = Self {
            features: BTreeMap::new(),
        };
        builder.add("kind", kind);
        builder
    }

    fn add(&mut self, key: &str, value: impl AsRef<str>) {
        let value = value.as_ref().trim();
        if value.is_empty() {
            return;
        }
        self.features
            .entry(key.to_string())
            .or_default()
            .insert(value.to_string());
    }

    fn add_list(&mut self, key: &str, values: Vec<String>) {
        for value in values {
            self.add(key, value);
        }
    }

    fn finish(self) -> Vec<FingerprintFeature> {
        self.features
            .into_iter()
            .map(|(key, values)| FingerprintFeature {
                key,
                value: values.into_iter().collect::<Vec<_>>().join(","),
            })
            .collect()
    }
}

pub fn redact_fingerprint(fingerprint: &mut AttackFingerprint) {
    fingerprint.source_ips = if fingerprint.source_ips.is_empty() {
        Vec::new()
    } else {
        vec!["[redacted]".to_string()]
    };
}

pub fn redact_observation(observation: &mut AttackObservation) {
    if !observation.source_ip.is_empty() {
        observation.source_ip = "[redacted]".to_string();
    }
}

pub fn explain_fingerprint(
    fingerprint: &AttackFingerprint,
    observations: &[AttackObservation],
) -> FingerprintExplanation {
    FingerprintExplanation {
        fingerprint_id: fingerprint.id.clone(),
        kind: fingerprint.kind.clone(),
        verdict: fingerprint.verdict.clone(),
        risk_tier: fingerprint_risk_tier(fingerprint).to_string(),
        recommended_action: fingerprint_recommended_action(fingerprint).to_string(),
        score: fingerprint.score,
        confidence: fingerprint.confidence,
        seen_count: fingerprint.seen_count,
        source_ip_count: fingerprint.source_ips.len(),
        host_count: fingerprint.hosts.len(),
        rule_count: fingerprint.rule_ids.len(),
        signals: fingerprint_signals(fingerprint, observations),
        limitations: fingerprint_limitations(fingerprint, observations),
        top_features: top_explainable_features(&fingerprint.features, 10),
        recent_observations: observations
            .iter()
            .take(8)
            .map(observation_summary)
            .collect(),
    }
}

pub fn valid_verdict(value: &str) -> bool {
    matches!(value, VERDICT_UNKNOWN | VERDICT_BENIGN | VERDICT_MALICIOUS)
}

fn fingerprint_risk_tier(fingerprint: &AttackFingerprint) -> &'static str {
    if fingerprint.verdict == VERDICT_BENIGN {
        "benign"
    } else if fingerprint.verdict == VERDICT_MALICIOUS
        || fingerprint.score >= 90
        || (fingerprint.score >= 80 && fingerprint.source_ips.len() >= 2)
    {
        "high"
    } else if fingerprint.score >= 65 || fingerprint.seen_count >= 3 {
        "medium"
    } else {
        "low"
    }
}

fn fingerprint_recommended_action(fingerprint: &AttackFingerprint) -> &'static str {
    match fingerprint.verdict.as_str() {
        VERDICT_BENIGN => "keep as benign unless new evidence appears",
        VERDICT_MALICIOUS => "eligible for active response when source IP safety checks pass",
        _ if fingerprint.score >= 80 && fingerprint.seen_count >= 2 => {
            "review and consider marking malicious if the behavior is unwanted"
        }
        _ if fingerprint.score >= 65 => "monitor and review recent observations",
        _ => "keep observing; current evidence is weak",
    }
}

fn fingerprint_signals(
    fingerprint: &AttackFingerprint,
    observations: &[AttackObservation],
) -> Vec<String> {
    let mut signals = Vec::new();
    if fingerprint.score >= 80 {
        signals.push(format!("high composite score {}", fingerprint.score));
    }
    if fingerprint.confidence >= 80 {
        signals.push(format!("high confidence {}", fingerprint.confidence));
    }
    if fingerprint.seen_count >= 2 {
        signals.push(format!("seen {} times", fingerprint.seen_count));
    }
    if fingerprint.source_ips.len() >= 2 {
        signals.push(format!(
            "observed from {} distinct sources",
            fingerprint.source_ips.len()
        ));
    }
    if fingerprint.hosts.len() >= 2 {
        signals.push(format!("seen on {} hosts", fingerprint.hosts.len()));
    }
    if !fingerprint.rule_ids.is_empty() {
        signals.push(format!("rules {}", fingerprint.rule_ids.join(",")));
    }
    if observations
        .iter()
        .any(|observation| !observation.evidence_summary.trim().is_empty())
    {
        signals.push("recent observations include retained evidence summaries".to_string());
    }
    if signals.is_empty() {
        signals.push("single low-volume observation".to_string());
    }
    signals
}

fn fingerprint_limitations(
    fingerprint: &AttackFingerprint,
    observations: &[AttackObservation],
) -> Vec<String> {
    let mut limitations = Vec::new();
    if fingerprint.source_ips.len() <= 1 {
        limitations.push("only one source has been observed".to_string());
    }
    if fingerprint.seen_count <= 1 {
        limitations.push("not enough repeated observations yet".to_string());
    }
    if fingerprint.verdict == VERDICT_UNKNOWN {
        limitations.push("operator verdict is still unknown".to_string());
    }
    if observations.is_empty() {
        limitations.push("no recent observations were loaded for this explanation".to_string());
    }
    limitations
}

fn top_explainable_features(
    features: &[FingerprintFeature],
    limit: usize,
) -> Vec<FingerprintFeature> {
    let mut ranked = features.to_vec();
    ranked.sort_by_key(|feature| {
        (
            Reverse(feature_explainability_rank(&feature.key)),
            feature.key.clone(),
            feature.value.clone(),
        )
    });
    ranked.truncate(limit);
    ranked
}

fn feature_explainability_rank(key: &str) -> u8 {
    match key {
        "kind" | "rule" | "category" => 9,
        "families" | "family" | "path_shapes" | "users" | "success_users" => 8,
        "process_name" | "exe_path" | "exe_hash_blake3" | "cmdline" => 7,
        "responses" | "response" | "failure_bucket" | "volume_bucket" => 6,
        "systemd_unit" | "package_owner" | "parent_name" | "gpu_process" => 5,
        _ => 1,
    }
}

fn observation_summary(observation: &AttackObservation) -> String {
    let source = if observation.source_ip.is_empty() {
        "-"
    } else {
        observation.source_ip.as_str()
    };
    format!(
        "{} rule={} host={} source={} {}",
        observation.observed_at,
        observation.rule_id,
        observation.host_id,
        source,
        observation.evidence_summary
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;
    use sentinel_core::{Confidence, Severity};

    #[test]
    fn web_fingerprint_ignores_source_ip_but_keeps_source_as_observation() {
        let left = web_finding("8.8.8.8", "/.env?token=123");
        let right = web_finding("1.1.1.1", "/.env?token=999");

        let left = fingerprint_candidate(&left).expect("left fingerprint");
        let right = fingerprint_candidate(&right).expect("right fingerprint");

        assert_eq!(left.exact_hash, right.exact_hash);
        assert_ne!(left.source_ip, right.source_ip);
    }

    #[test]
    fn simhash_groups_small_path_shape_variants() {
        let left = web_finding("8.8.8.8", "/wp-admin/admin-ajax.php?id=123");
        let right = web_finding("1.1.1.1", "/wp-admin/admin-ajax.php?id=999");
        let left = fingerprint_candidate(&left).expect("left fingerprint");
        let right = fingerprint_candidate(&right).expect("right fingerprint");

        assert!(hamming_distance(left.simhash, right.simhash) <= 6);
    }

    #[test]
    fn ssh_fingerprint_uses_user_dictionary_not_ip() {
        let left = ssh_finding("8.8.8.8", "root,admin,test");
        let right = ssh_finding("1.1.1.1", "admin,root,test");
        let left = fingerprint_candidate(&left).expect("left fingerprint");
        let right = fingerprint_candidate(&right).expect("right fingerprint");

        assert_eq!(left.exact_hash, right.exact_hash);
    }

    #[test]
    fn action_hint_requires_repeated_unknown_fingerprint() {
        let mut config = SentinelConfig::default();
        config.attack_fingerprints.active_response_min_score = 70;
        config.attack_fingerprints.active_response_min_observations = 2;
        config.attack_fingerprints.active_response_min_distinct_ips = 2;
        let finding = web_finding("8.8.8.8", "/cgi-bin/.%2e/.%2e/bin/sh");
        let candidate = fingerprint_candidate(&finding).expect("fingerprint");
        let mut fingerprint = new_fingerprint(&candidate);
        merge_sorted_unique(&mut fingerprint.source_ips, "8.8.8.8", 64);
        assert!(!should_hint_active_response(
            &fingerprint,
            &candidate,
            &finding,
            &config
        ));

        fingerprint.seen_count = 2;
        fingerprint.score = 80;
        merge_sorted_unique(&mut fingerprint.source_ips, "1.1.1.1", 64);
        assert!(should_hint_active_response(
            &fingerprint,
            &candidate,
            &finding,
            &config
        ));
    }

    #[test]
    fn privacy_mask_ip_stores_stable_hash_not_raw_ip() {
        let mut config = SentinelConfig::default();
        config.privacy.mask_ip = true;

        let stored = stored_source_ip(&config, "8.8.8.8");

        assert!(stored.starts_with("ip-hash-"));
        assert!(!stored.contains("8.8.8.8"));
        assert_eq!(stored, stored_source_ip(&config, "8.8.8.8"));
    }

    #[test]
    fn similar_match_keeps_canonical_hash_stable() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::NamedTempFile::new()?;
        let store = SqliteStore::open(temp.path())?;
        let mut config = SentinelConfig::default();
        config.attack_fingerprints.similarity_hamming_distance = 0;

        let left = manual_candidate("aaaaaaaaaaaa0000", 0x1234);
        let stored = new_fingerprint(&left);
        let original_id = stored.id.clone();
        let original_exact_hash = stored.exact_hash.clone();
        let original_simhash = stored.simhash.clone();
        store.save_attack_fingerprint(&stored)?;

        let right = manual_candidate("bbbbbbbbbbbb0000", 0x1234);
        let matched = match_fingerprint(&store, &right, &config)?;
        assert_eq!(matched.kind, MatchKind::Similar);

        let merged = merge_fingerprint(matched, &right, &web_finding("1.1.1.1", "/admin"), &config);

        assert_eq!(merged.id, original_id);
        assert_eq!(merged.exact_hash, original_exact_hash);
        assert_eq!(merged.simhash, original_simhash);
        assert_ne!(merged.exact_hash, right.exact_hash);
        Ok(())
    }

    #[test]
    fn explanation_prioritizes_interpretable_cluster_signals() {
        let mut fingerprint = new_fingerprint(&manual_candidate("cccccccccccc0000", 0x4321));
        fingerprint.score = 88;
        fingerprint.confidence = 90;
        fingerprint.seen_count = 4;
        fingerprint.source_ips = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        fingerprint.hosts = vec!["host-a".to_string(), "host-b".to_string()];
        fingerprint.rule_ids = vec!["WEB-001".to_string()];
        fingerprint.features.push(FingerprintFeature {
            key: "path_shapes".to_string(),
            value: "/.env".to_string(),
        });
        let observations = vec![AttackObservation {
            id: "obs-1".to_string(),
            fingerprint_id: fingerprint.id.clone(),
            finding_id: "finding-1".to_string(),
            host_id: "host-a".to_string(),
            source_ip: "1.1.1.1".to_string(),
            rule_id: "WEB-001".to_string(),
            observed_at: Utc::now(),
            features: Vec::new(),
            evidence_summary: "probe_family=env_file; request_count=25".to_string(),
        }];

        let explanation = explain_fingerprint(&fingerprint, &observations);

        assert_eq!(explanation.risk_tier, "high");
        assert!(explanation
            .signals
            .iter()
            .any(|signal| signal.contains("distinct sources")));
        assert_eq!(explanation.top_features[0].key, "kind");
        assert!(explanation
            .top_features
            .iter()
            .any(|feature| feature.key == "path_shapes"));
        assert_eq!(explanation.recent_observations.len(), 1);
    }

    fn manual_candidate(exact_hash: &str, simhash: u64) -> FingerprintCandidate {
        FingerprintCandidate {
            kind: "web_probe".to_string(),
            title: "Web attack fingerprint".to_string(),
            source_ip: "8.8.8.8".to_string(),
            exact_hash: exact_hash.to_string(),
            simhash,
            score: 80,
            confidence: 85,
            summary: "manual candidate".to_string(),
            features: vec![
                FingerprintFeature {
                    key: "kind".to_string(),
                    value: "web_probe".to_string(),
                },
                FingerprintFeature {
                    key: "family".to_string(),
                    value: "env_file".to_string(),
                },
            ],
        }
    }

    fn web_finding(ip: &str, path: &str) -> Finding {
        Finding::new(
            "host",
            "web",
            "web",
            Severity::Medium,
            Category::Web,
            "WEB-001",
            ip,
        )
        .with_confidence(Confidence::High)
        .with_evidence(vec![
            Evidence::new("ip", ip),
            Evidence::new("probe_family", "env_file"),
            Evidence::new("probe_families", "env_file"),
            Evidence::new("response_profile", "missing_or_rejected"),
            Evidence::new("response_profiles", "missing_or_rejected"),
            Evidence::new("request_count", "1"),
            Evidence::new("methods", "GET"),
            Evidence::new("statuses", "404"),
            Evidence::new("sample_paths", path),
        ])
    }

    fn ssh_finding(ip: &str, users: &str) -> Finding {
        Finding::new(
            "host",
            "ssh",
            "ssh",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            ip,
        )
        .with_evidence(vec![
            Evidence::new("source_ip", ip),
            Evidence::new("failure_count", "12"),
            Evidence::new("users", users),
        ])
    }
}
