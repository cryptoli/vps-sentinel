use super::{
    annotate_active_response, duplicate_suppression_window_seconds, enrich_process_start_drift,
    quiet_hours_allowed_findings, redact_findings, save_process_start_state,
    suppress_in_scan_duplicates, suppress_recent_duplicates,
};
use crate::active_response::{ActiveResponseReport, BlockAction, BlockActionStatus};
use crate::storage::SqliteStore;
use chrono::{Duration, Utc};
use sentinel_core::{Category, Evidence, Finding, RawEvent, SentinelConfig, Severity};

#[test]
fn redacts_finding_subject_and_evidence() {
    let mut config = SentinelConfig::default();
    config.privacy.mask_ip = true;
    config.privacy.mask_command_args = true;

    let finding = Finding::new(
        "host",
        "Suspicious command",
        "Command line matched.",
        Severity::Critical,
        Category::Process,
        "PROC-003",
        "root@203.0.113.10",
    )
    .with_evidence(vec![
        Evidence::new("source_ip", "203.0.113.10"),
        Evidence::new("cmdline", "/bin/bash -c whoami"),
        Evidence::new("raw", "203.0.113.10 /bin/bash -c whoami"),
    ]);

    let redacted = redact_findings(vec![finding], &config);
    assert_eq!(redacted[0].subject, "root@203.0.x.x");
    assert_eq!(redacted[0].evidence[0].value, "203.0.x.x");
    assert_eq!(redacted[0].evidence[1].value, "/bin/bash [args masked]");
    assert_eq!(redacted[0].evidence[2].value, "[masked by privacy config]");
}

#[test]
fn active_response_annotation_adds_block_status_to_finding() {
    let mut config = SentinelConfig::default();
    config.notifications.time_zone = sentinel_core::NotificationTimeZone::Utc;
    let mut finding = Finding::new(
        "host",
        "SSH brute force pattern detected",
        "bruteforce",
        Severity::High,
        Category::Ssh,
        "SSH-003",
        "8.8.8.8",
    );
    finding.id = "finding-1".to_string();
    let mut findings = vec![finding];
    let report = ActiveResponseReport {
        block_actions: vec![BlockAction {
            finding_id: "finding-1".to_string(),
            ip: "8.8.8.8".parse().unwrap(),
            status: BlockActionStatus::Blocked,
            reason: "ssh brute force failure_count=16".to_string(),
            backend: Some("iptables".to_string()),
            expires_at: Some(Utc::now()),
            detail: None,
        }],
        ..ActiveResponseReport::default()
    };

    annotate_active_response(&mut findings, &report, &config);

    assert_eq!(
        evidence_value(&findings[0], "active_response_status"),
        Some("blocked")
    );
    assert_eq!(
        evidence_value(&findings[0], "active_response_ip"),
        Some("8.8.8.8")
    );
    assert_eq!(
        evidence_value(&findings[0], "active_response_backend"),
        Some("iptables")
    );
    assert!(evidence_value(&findings[0], "active_response_expires_at")
        .is_some_and(|value| value.ends_with("UTC")));
}

#[test]
fn suppresses_duplicate_findings_within_one_scan() {
    let finding = Finding::new(
        "host",
        "Root SSH login detected",
        "Root logged in through SSH.",
        Severity::High,
        Category::Ssh,
        "SSH-001",
        "root@203.0.113.10",
    )
    .with_evidence_deduped_by(
        vec![
            Evidence::new("user", "root"),
            Evidence::new("source_ip", "203.0.113.10"),
            Evidence::new("port", "42100"),
        ],
        &["user", "source_ip"],
    );
    let mut duplicate = finding.clone();
    duplicate.id = "another-id".to_string();

    let (retained, suppressed) = suppress_in_scan_duplicates(vec![finding, duplicate]);

    assert_eq!(retained.len(), 1);
    assert_eq!(suppressed, 1);
}

#[test]
fn state_findings_use_longer_reminder_window() {
    let mut config = SentinelConfig::default();
    config.noise_control.dedup_window_seconds = 3600;
    config.noise_control.state_reminder_interval_seconds = 86400;

    let state_finding = Finding::new(
        "host",
        "SSH password authentication enabled",
        "Password login is enabled.",
        Severity::Medium,
        Category::ConfigRisk,
        "CONFIG-001",
        "/etc/ssh/sshd_config",
    );
    let event_finding = Finding::new(
        "host",
        "Root SSH login detected",
        "Root logged in through SSH.",
        Severity::High,
        Category::Ssh,
        "SSH-001",
        "root@203.0.113.10",
    );
    let ssh_key_drift = Finding::new(
        "host",
        "authorized_keys modified",
        "authorized_keys changed.",
        Severity::High,
        Category::Ssh,
        "SSH-005",
        "/root/.ssh/authorized_keys",
    );

    assert_eq!(
        duplicate_suppression_window_seconds(&state_finding, &config),
        86400
    );
    assert_eq!(
        duplicate_suppression_window_seconds(&ssh_key_drift, &config),
        86400
    );
    assert_eq!(
        duplicate_suppression_window_seconds(&event_finding, &config),
        3600
    );
}

#[test]
fn state_duplicates_are_suppressed_after_event_window() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let mut config = SentinelConfig::default();
    config.noise_control.dedup_window_seconds = 3600;
    config.noise_control.state_reminder_interval_seconds = 86400;

    let mut previous_state = Finding::new(
        "host",
        "SSH password authentication enabled",
        "Password login is enabled.",
        Severity::Medium,
        Category::ConfigRisk,
        "CONFIG-001",
        "/etc/ssh/sshd_config",
    );
    previous_state.timestamp = Utc::now() - Duration::hours(2);
    store.save_findings(std::slice::from_ref(&previous_state))?;

    let mut next_state = previous_state.clone();
    next_state.id = "next-state-finding".to_string();
    next_state.timestamp = Utc::now();
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![next_state], &config)?;
    assert!(retained.is_empty());
    assert_eq!(suppressed, 1);

    let mut previous_event = Finding::new(
        "host",
        "Root SSH login detected",
        "Root logged in through SSH.",
        Severity::High,
        Category::Ssh,
        "SSH-001",
        "root@203.0.113.10",
    );
    previous_event.timestamp = Utc::now() - Duration::hours(2);
    store.save_findings(std::slice::from_ref(&previous_event))?;

    let mut next_event = previous_event.clone();
    next_event.id = "next-event-finding".to_string();
    next_event.timestamp = Utc::now();
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![next_event], &config)?;
    assert_eq!(retained.len(), 1);
    assert_eq!(suppressed, 0);

    Ok(())
}

#[test]
fn new_active_response_block_bypasses_recent_duplicate_suppression(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let previous = ssh_bruteforce_finding("47.242.23.111", "10");
    store.save_findings(std::slice::from_ref(&previous))?;

    let mut blocked = previous.clone();
    blocked.id = "blocked-finding".to_string();
    blocked.evidence.push(Evidence::new("failure_count", "16"));
    blocked
        .evidence
        .push(Evidence::new("active_response_status", "blocked"));
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![blocked], &config)?;

    assert_eq!(retained.len(), 1);
    assert_eq!(suppressed, 0);
    Ok(())
}

#[test]
fn existing_active_response_block_still_uses_recent_duplicate_suppression(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let previous = ssh_bruteforce_finding("47.242.23.111", "16");
    store.save_findings(std::slice::from_ref(&previous))?;

    let mut already_blocked = previous.clone();
    already_blocked.id = "already-blocked-finding".to_string();
    already_blocked
        .evidence
        .push(Evidence::new("active_response_status", "already_blocked"));
    let (retained, suppressed) =
        suppress_recent_duplicates(&store, vec![already_blocked], &config)?;

    assert!(retained.is_empty());
    assert_eq!(suppressed, 1);
    Ok(())
}

#[test]
fn quiet_hours_keep_high_value_findings_by_default() {
    let config = SentinelConfig::default();
    let findings = vec![
        Finding::new(
            "host",
            "SSH authorized_keys changed",
            "authorized_keys changed.",
            Severity::High,
            Category::Ssh,
            "SSH-005",
            "/root/.ssh/authorized_keys",
        ),
        Finding::new(
            "host",
            "Docker socket present",
            "Docker context.",
            Severity::Info,
            Category::Docker,
            "DOCKER-001",
            "/var/run/docker.sock",
        ),
    ];

    let filtered = quiet_hours_allowed_findings(&findings, &config);

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].rule_id, "SSH-005");
}

#[test]
fn process_start_state_marks_same_identity_start_drift() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let first = process_event("/usr/local/bin/.sysd", ".sysd", "100");

    save_process_start_state(std::slice::from_ref(&first), &store)?;

    let mut second = vec![process_event("/usr/local/bin/.sysd", ".sysd", "200")];
    enrich_process_start_drift(&mut second, &store)?;

    assert_eq!(second[0].field("process_start_changed"), Some("true"));
    assert_eq!(second[0].field("process_start_drift"), Some("changed"));
    assert_eq!(second[0].field("previous_process_start_ticks"), Some("100"));
    assert_eq!(second[0].field("current_process_start_ticks"), Some("200"));
    Ok(())
}

#[test]
fn process_start_state_ignores_missing_or_changed_identity(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let first = process_event("/usr/local/bin/worker", "worker", "100");

    save_process_start_state(std::slice::from_ref(&first), &store)?;

    let mut missing_start = vec![
        RawEvent::new("process", "process_snapshot")
            .with_field("exe_path", "/usr/local/bin/worker")
            .with_field("name", "worker"),
        process_event("/usr/local/bin/other", "worker", "200"),
    ];
    enrich_process_start_drift(&mut missing_start, &store)?;

    assert_eq!(missing_start[0].field("process_start_changed"), None);
    assert_eq!(missing_start[1].field("process_start_changed"), None);
    Ok(())
}

fn process_event(exe_path: &str, name: &str, start_ticks: &str) -> RawEvent {
    RawEvent::new("process", "process_snapshot")
        .with_field("exe_path", exe_path)
        .with_field("name", name)
        .with_field("process_start_ticks", start_ticks)
}

fn evidence_value<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
    finding
        .evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.as_str())
}

fn ssh_bruteforce_finding(source_ip: &str, failure_count: &str) -> Finding {
    Finding::new(
        "host",
        "SSH brute force pattern detected",
        "bruteforce",
        Severity::High,
        Category::Ssh,
        "SSH-003",
        source_ip,
    )
    .with_evidence_deduped_by(
        vec![
            Evidence::new("source_ip", source_ip),
            Evidence::new("failure_count", failure_count),
        ],
        &["source_ip"],
    )
}
