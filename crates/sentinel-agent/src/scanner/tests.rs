use super::{
    duplicate_suppression_window_seconds, quiet_hours_allowed_findings, redact_findings,
    suppress_in_scan_duplicates, suppress_recent_duplicates,
};
use crate::storage::SqliteStore;
use chrono::{Duration, Utc};
use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

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
