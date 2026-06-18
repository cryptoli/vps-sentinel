use super::{
    annotate_active_response, apply_active_response_notification_policy,
    duplicate_suppression_window_seconds, enrich_log_integrity_state, enrich_process_start_drift,
    quiet_hours_allowed_findings, redact_findings, save_log_integrity_state,
    save_process_start_state, suppress_in_scan_duplicates, suppress_recent_duplicates,
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
fn active_response_summary_replaces_many_block_details() {
    let mut config = SentinelConfig::default();
    config.active_response.notification_detail_limit = 3;
    let mut findings = (1..=4)
        .map(|index| {
            let mut finding = Finding::new(
                "host",
                "Web vulnerability probing detected",
                "probe",
                Severity::Medium,
                Category::Web,
                "WEB-001",
                format!("8.8.8.{index}"),
            );
            finding.id = format!("finding-{index}");
            finding
        })
        .collect::<Vec<_>>();
    let report = ActiveResponseReport {
        applied_blocks: 4,
        block_actions: (1..=4)
            .map(|index| BlockAction {
                finding_id: format!("finding-{index}"),
                ip: format!("8.8.8.{index}").parse().unwrap(),
                status: BlockActionStatus::Blocked,
                reason: format!("web probe request_count={index}"),
                backend: Some("nftables".to_string()),
                expires_at: Some(Utc::now()),
                detail: None,
            })
            .collect(),
        ..ActiveResponseReport::default()
    };

    apply_active_response_notification_policy(&mut findings, &report, &config);

    assert_eq!(findings.len(), 5);
    assert!(findings[..4]
        .iter()
        .all(|finding| evidence_value(finding, "active_response_status").is_none()));
    let summary = findings.last().unwrap();
    assert_eq!(summary.rule_id, "ACTIVE-001");
    assert_eq!(
        evidence_value(summary, "active_response_status"),
        Some("blocked_many")
    );
    assert_eq!(
        evidence_value(summary, "active_response_block_count"),
        Some("4")
    );
    assert_eq!(
        evidence_value(summary, "active_response_reason_summary"),
        Some("web_probe=4")
    );
}

#[test]
fn active_response_keeps_small_block_details() {
    let mut config = SentinelConfig::default();
    config.active_response.notification_detail_limit = 3;
    let mut finding = Finding::new(
        "host",
        "SSH brute force pattern detected",
        "bruteforce",
        Severity::High,
        Category::Ssh,
        "SSH-003",
        "8.8.4.4",
    );
    finding.id = "finding-1".to_string();
    let mut findings = vec![finding];
    let report = ActiveResponseReport {
        applied_blocks: 1,
        block_actions: vec![BlockAction {
            finding_id: "finding-1".to_string(),
            ip: "8.8.4.4".parse().unwrap(),
            status: BlockActionStatus::Blocked,
            reason: "ssh brute force failure_count=16".to_string(),
            backend: Some("iptables".to_string()),
            expires_at: Some(Utc::now()),
            detail: None,
        }],
        ..ActiveResponseReport::default()
    };

    apply_active_response_notification_policy(&mut findings, &report, &config);

    assert_eq!(findings.len(), 1);
    assert_eq!(
        evidence_value(&findings[0], "active_response_status"),
        Some("blocked")
    );
    assert_eq!(
        evidence_value(&findings[0], "active_response_ip"),
        Some("8.8.4.4")
    );
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
    let ssh_key_state = Finding::new(
        "host",
        "authorized_keys unsafe state",
        "authorized_keys unsafe state.",
        Severity::High,
        Category::Ssh,
        "SSH-006",
        "/root/.ssh/authorized_keys",
    );
    let tamper_state = Finding::new(
        "host",
        "Sensitive log was abruptly truncated",
        "log truncation",
        Severity::High,
        Category::System,
        "TAMPER-002",
        "/var/log/auth.log",
    );
    let tamper_missing_state = Finding::new(
        "host",
        "Sensitive log disappeared",
        "log missing",
        Severity::High,
        Category::System,
        "TAMPER-003",
        "/var/log/auth.log",
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
        duplicate_suppression_window_seconds(&ssh_key_state, &config),
        86400
    );
    assert_eq!(
        duplicate_suppression_window_seconds(&tamper_state, &config),
        86400
    );
    assert_eq!(
        duplicate_suppression_window_seconds(&tamper_missing_state, &config),
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

#[test]
fn log_integrity_state_marks_abrupt_truncation() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let first = log_event("/var/log/auth.log", 1_048_576);

    save_log_integrity_state(std::slice::from_ref(&first), &store)?;

    let mut second = vec![log_event("/var/log/auth.log", 512)];
    enrich_log_integrity_state(&mut second, &store, &config)?;

    assert_eq!(second[0].field("log_size_drop"), Some("true"));
    assert_eq!(second[0].field("previous_size"), Some("1048576"));
    assert_eq!(second[0].field("current_size"), Some("512"));
    assert_eq!(second[0].field("drop_percent"), Some("99"));
    Ok(())
}

#[test]
fn log_integrity_state_ignores_recent_rotation_context() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let first = log_event("/var/log/auth.log", 1_048_576);

    save_log_integrity_state(std::slice::from_ref(&first), &store)?;

    let mut second =
        vec![log_event("/var/log/auth.log", 0).with_field("recent_rotated_sibling", "true")];
    enrich_log_integrity_state(&mut second, &store, &config)?;

    assert_eq!(second[0].field("log_size_drop"), None);
    Ok(())
}

#[test]
fn log_integrity_state_marks_previously_seen_log_missing() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let first = log_event("/var/log/auth.log", 4096);

    save_log_integrity_state(std::slice::from_ref(&first), &store)?;

    let mut second = Vec::new();
    enrich_log_integrity_state(&mut second, &store, &config)?;

    assert_eq!(second.len(), 1);
    assert_eq!(second[0].field("log_file_missing"), Some("true"));
    assert_eq!(second[0].field("path"), Some("/var/log/auth.log"));
    assert_eq!(second[0].field("previous_size"), Some("4096"));
    Ok(())
}

#[test]
fn log_integrity_state_does_not_save_synthetic_missing_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let first = log_event("/var/log/auth.log", 4096);

    save_log_integrity_state(std::slice::from_ref(&first), &store)?;

    let mut missing = Vec::new();
    enrich_log_integrity_state(&mut missing, &store, &config)?;
    save_log_integrity_state(&missing, &store)?;

    let mut repeated_missing = Vec::new();
    enrich_log_integrity_state(&mut repeated_missing, &store, &config)?;

    assert_eq!(
        repeated_missing[0].field("previous_file_type"),
        Some("file")
    );
    assert_eq!(repeated_missing[0].field("previous_size"), Some("4096"));
    Ok(())
}

fn process_event(exe_path: &str, name: &str, start_ticks: &str) -> RawEvent {
    RawEvent::new("process", "process_snapshot")
        .with_field("exe_path", exe_path)
        .with_field("name", name)
        .with_field("process_start_ticks", start_ticks)
}

fn log_event(path: &str, size: u64) -> RawEvent {
    RawEvent::new("log_integrity", "log_file_snapshot")
        .with_field("path", path)
        .with_field("file_type", "file")
        .with_field("size", size.to_string())
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
