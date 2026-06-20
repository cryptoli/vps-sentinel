use crate::rules::system::{SERVICE_PROFILE_DRIFT_RULE_ID, SERVICE_PROFILE_NEW_RULE_ID};
use crate::storage::SqliteStore;
use crate::utils::ip::is_public_listener_addr;
use chrono::{DateTime, Utc};
use sentinel_core::{
    Category, Evidence, Finding, RawEvent, SentinelConfig, SentinelResult, Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const STATE_RULE_ID: &str = "service_profile";
const UNPRIVILEGED_PORT_START: u16 = 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceProfile {
    pub updated_at: Option<DateTime<Utc>>,
    pub services: BTreeMap<String, ServiceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub process_name: String,
    pub executable: String,
    pub cmdline: String,
    pub public_exposure: bool,
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
    let current = current_profile_with_config(events, config);
    if current.services.is_empty() {
        return Ok(Vec::new());
    }
    let previous = store.load_rule_state::<ServiceProfile>(STATE_RULE_ID)?;
    let mut findings = Vec::new();
    if let Some(previous) = previous {
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
    let services = events
        .iter()
        .filter(|event| event.kind == "listening_socket")
        .filter_map(service_record)
        .filter(|record| !ignored_service_profile_record(record, config))
        .map(|record| (service_key(&record, config), record))
        .collect::<BTreeMap<_, _>>();
    ServiceProfile {
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
            let udp_change =
                udp_profile_change(previous, &current.services, current_record, config);
            if matches!(udp_change, UdpProfileChange::PortChurn) {
                continue;
            }
            findings.push(new_service_finding(
                current_record,
                package_activity.as_deref(),
                config,
                matches!(udp_change, UdpProfileChange::IdentitySeen),
            ));
            continue;
        };
        if service_identity_changed(previous_record, current_record) {
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

fn new_service_finding(
    record: &ServiceRecord,
    package_activity: Option<&str>,
    config: &SentinelConfig,
    identity_seen_dynamic_udp: bool,
) -> Finding {
    let mut evidence = service_evidence(record);
    let dynamic_udp = is_dynamic_udp_service(record, config) || identity_seen_dynamic_udp;
    if dynamic_udp {
        evidence.push(Evidence::new("dynamic_udp_listener", "true"));
        evidence.push(Evidence::new(
            "service_profile_identity",
            dynamic_udp_identity(record),
        ));
        if identity_seen_dynamic_udp && !is_dynamic_udp_service(record, config) {
            evidence.push(Evidence::new(
                "dynamic_udp_reason",
                "same_service_identity_udp_port_change",
            ));
        }
    }
    if let Some(package_activity) = package_activity {
        evidence.push(Evidence::new("package_activity_recent", "true"));
        evidence.push(Evidence::new("package_activity_sources", package_activity));
    }
    Finding::new(
        config.host_id(),
        "New service profile entry detected",
        "A listening service was not present in the previous service profile baseline.",
        if record.public_exposure && !dynamic_udp {
            Severity::Medium
        } else {
            Severity::Low
        },
        Category::Network,
        SERVICE_PROFILE_NEW_RULE_ID,
        format!("{}:{}/{}", record.local_addr, record.local_port, record.protocol),
    )
    .with_evidence_deduped_by(evidence, &["local_addr", "local_port", "protocol"])
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
        format!("{}:{}/{}", current.local_addr, current.local_port, current.protocol),
    )
    .with_evidence_deduped_by(evidence, &["local_addr", "local_port", "protocol"])
    .with_impact(vec![
        "A service owner change can be normal after upgrades, but it can also indicate service hijacking.".to_string(),
    ])
    .with_recommendations(vec![
        "Compare the executable with package ownership and service manager metadata before refreshing the profile.".to_string(),
    ])
}

fn service_record(event: &RawEvent) -> Option<ServiceRecord> {
    let protocol = event.field("protocol")?.to_string();
    let local_addr = event.field("local_addr")?.to_string();
    let local_port = event.field("local_port")?.parse::<u16>().ok()?;
    Some(ServiceRecord {
        public_exposure: is_public_listener_addr(&local_addr),
        protocol,
        local_addr,
        local_port,
        process_name: event.field("process_name").unwrap_or("").to_string(),
        executable: event.field("executable").unwrap_or("").to_string(),
        cmdline: event.field("cmdline").unwrap_or("").to_string(),
    })
}

fn service_key(record: &ServiceRecord, config: &SentinelConfig) -> String {
    if is_dynamic_udp_service(record, config) {
        return format!(
            "{}:{}:dynamic:{}",
            record.protocol,
            record.local_addr,
            dynamic_udp_identity(record)
        );
    }
    format!(
        "{}:{}:{}",
        record.protocol, record.local_addr, record.local_port
    )
}

fn is_dynamic_udp_service(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    config.service_profile.dynamic_udp_enabled
        && record.public_exposure
        && is_udp_protocol(&record.protocol)
        && record.local_port >= config.service_profile.dynamic_udp_min_port
}

fn dynamic_udp_identity(record: &ServiceRecord) -> String {
    let identity = normalized_identity(record);
    if identity.trim_matches('|').is_empty() {
        "unknown-owner".to_string()
    } else {
        identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpProfileChange {
    None,
    IdentitySeen,
    PortChurn,
}

fn udp_profile_change(
    previous: &ServiceProfile,
    current: &BTreeMap<String, ServiceRecord>,
    record: &ServiceRecord,
    config: &SentinelConfig,
) -> UdpProfileChange {
    if !identity_stable_dynamic_udp_candidate(record, config) {
        return UdpProfileChange::None;
    }
    let previous_ports = same_udp_identity_ports(previous.services.values(), record);
    if previous_ports.is_empty() || previous_ports.contains(&record.local_port) {
        return UdpProfileChange::None;
    }
    let current_ports = same_udp_identity_ports(current.values(), record);
    if current_ports.is_empty() {
        return UdpProfileChange::None;
    }
    if current_ports.len() <= previous_ports.len()
        && current_ports
            .iter()
            .all(|port| *port >= UNPRIVILEGED_PORT_START)
        && previous_ports
            .iter()
            .all(|port| *port >= UNPRIVILEGED_PORT_START)
    {
        UdpProfileChange::PortChurn
    } else {
        UdpProfileChange::IdentitySeen
    }
}

fn identity_stable_dynamic_udp_candidate(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    config.service_profile.dynamic_udp_enabled
        && record.public_exposure
        && is_udp_protocol(&record.protocol)
        && record.local_port >= UNPRIVILEGED_PORT_START
        && stable_service_identity(record).is_some()
}

fn same_udp_identity_ports<'a>(
    records: impl Iterator<Item = &'a ServiceRecord>,
    target: &ServiceRecord,
) -> BTreeSet<u16> {
    let Some(target_identity) = stable_service_identity(target) else {
        return BTreeSet::new();
    };
    records
        .filter(|record| {
            record.public_exposure
                && is_udp_protocol(&record.protocol)
                && record.protocol.eq_ignore_ascii_case(&target.protocol)
                && record.local_addr == target.local_addr
                && stable_service_identity(record).as_deref() == Some(target_identity.as_str())
        })
        .map(|record| record.local_port)
        .collect()
}

fn stable_service_identity(record: &ServiceRecord) -> Option<String> {
    let identity = normalized_identity(record);
    (!identity.trim_matches('|').is_empty()).then_some(identity)
}

fn ignored_service_profile_record(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    ignored_dynamic_udp_process(record, config) || ignored_loopback_ssh_forwarding(record, config)
}

fn ignored_dynamic_udp_process(record: &ServiceRecord, config: &SentinelConfig) -> bool {
    if !is_udp_protocol(&record.protocol)
        || record.local_port < config.service_profile.dynamic_udp_min_port
    {
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

fn is_udp_protocol(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("udp") || protocol.eq_ignore_ascii_case("udp6")
}

fn is_loopback_listener(addr: &str) -> bool {
    matches!(addr.trim(), "127.0.0.1" | "::1" | "[::1]" | "localhost")
}

fn service_identity_changed(previous: &ServiceRecord, current: &ServiceRecord) -> bool {
    normalized_identity(previous) != normalized_identity(current)
}

fn normalized_identity(record: &ServiceRecord) -> String {
    let executable = record
        .executable
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| record.executable.trim());
    format!("{}|{}", record.process_name.trim(), executable)
}

fn service_evidence(record: &ServiceRecord) -> Vec<Evidence> {
    vec![
        Evidence::new("protocol", &record.protocol),
        Evidence::new("local_addr", &record.local_addr),
        Evidence::new("local_port", record.local_port.to_string()),
        Evidence::new("public_exposure", record.public_exposure.to_string()),
        Evidence::new("process_name", &record.process_name),
        Evidence::new("executable", &record.executable),
        Evidence::new("cmdline", &record.cmdline),
        Evidence::new("service_profile_identity", normalized_identity(record)),
    ]
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
    fn unprivileged_udp_extra_port_for_seen_identity_is_low_signal(
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

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, sentinel_core::Severity::Low);
        assert!(findings[0].evidence.iter().any(|item| {
            item.key == "dynamic_udp_reason"
                && item.value == "same_service_identity_udp_port_change"
        }));
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
