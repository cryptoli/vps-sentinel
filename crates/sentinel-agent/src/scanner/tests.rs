use super::{
    annotate_active_response, apply_active_response_notification_policy,
    compact_raw_event_for_storage, duplicate_suppression_window_seconds,
    enrich_log_integrity_state, enrich_process_start_drift, prepare_notification_findings,
    prepare_raw_events_for_storage, quiet_hours_allowed_findings, redact_findings,
    retain_incremental_file_events, save_log_integrity_state, save_process_start_state,
    suppress_in_scan_duplicates, suppress_recent_duplicates, truncate_utf8,
};
use crate::active_response::{ActiveResponseReport, BlockAction, BlockActionStatus};
use crate::storage::SqliteStore;
use chrono::{Duration, Utc};
use sentinel_core::{
    evidence_value as core_evidence_value, Category, Evidence, Finding, RawEvent, SentinelConfig,
    Severity,
};

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
    assert_eq!(
        core_evidence_value(&redacted[0].evidence, "source_ip"),
        Some("203.0.x.x")
    );
    assert_eq!(
        core_evidence_value(&redacted[0].evidence, "cmdline"),
        Some("/bin/bash [args masked]")
    );
    assert_eq!(
        core_evidence_value(&redacted[0].evidence, "raw"),
        Some("[masked by privacy config]")
    );
}

#[test]
fn storage_compaction_removes_duplicate_process_argv_and_raw_log_lines() {
    let mut config = SentinelConfig::default();
    config.performance.store_raw_log_lines = false;
    config.performance.max_stored_field_bytes = 16;
    let event = RawEvent::new("process", "process_snapshot")
        .with_field("cmdline", "/usr/bin/python app.py")
        .with_field("argv_json", r#"["/usr/bin/python","app.py"]"#)
        .with_field("raw", "raw log line")
        .with_field("long", "abcdefghijklmnopqrstuvwxyz");

    let compact = compact_raw_event_for_storage(&event, &config);

    assert!(compact.field("argv_json").is_none());
    assert!(compact.field("raw").is_none());
    assert!(compact
        .field("long")
        .is_some_and(|value| value.len() <= 16 && value.contains("truncated")));
}

#[test]
fn storage_preparation_keeps_only_relevant_web_events_by_default() {
    let config = SentinelConfig::default();
    let benign = RawEvent::new("web", "web_access")
        .with_field("ip", "8.8.8.8")
        .with_field("method", "GET")
        .with_field("path", "/assets/app.css")
        .with_field("status", "404");
    let probe = RawEvent::new("web", "web_access")
        .with_field("ip", "8.8.4.4")
        .with_field("method", "GET")
        .with_field("path", "/.env")
        .with_field("status", "404");
    let process = RawEvent::new("process", "process_snapshot")
        .with_field("name", "nginx")
        .with_field("exe_path", "/usr/sbin/nginx");

    let stored = prepare_raw_events_for_storage(&[benign, probe, process], &config);

    assert_eq!(stored.len(), 2);
    assert!(stored
        .iter()
        .any(|event| event.kind == "web_access" && event.field("path") == Some("/.env")));
    assert!(stored.iter().any(|event| event.kind == "process_snapshot"));
}

#[test]
fn storage_preparation_can_keep_all_web_events_when_configured() {
    let mut config = SentinelConfig::default();
    config.performance.store_all_web_access_events = true;
    let benign = RawEvent::new("web", "web_access")
        .with_field("ip", "8.8.8.8")
        .with_field("method", "GET")
        .with_field("path", "/assets/app.css")
        .with_field("status", "404");

    let stored = prepare_raw_events_for_storage(&[benign], &config);

    assert_eq!(stored.len(), 1);
}

#[test]
fn incremental_file_filter_retains_only_detection_relevant_snapshots() {
    let events = vec![
        RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/etc/passwd")
            .with_field("hash", "stable"),
        RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/root/.ssh/authorized_keys")
            .with_field("mode_octal", "0666"),
        RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/var/www/html/shell.php")
            .with_field("is_web_path", "true"),
        RawEvent::new("baseline", "file_modified")
            .with_field("path", "/etc/ssh/sshd_config")
            .with_field("change", "modified"),
        RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/etc/ssh/sshd_config")
            .with_field("hash", "changed"),
    ];
    let changed = super::changed_file_paths(&events);

    let retained = retain_incremental_file_events(events, &changed);

    assert!(retained
        .iter()
        .any(|event| event.field("path") == Some("/root/.ssh/authorized_keys")));
    assert!(retained
        .iter()
        .any(|event| event.field("path") == Some("/var/www/html/shell.php")));
    assert!(retained
        .iter()
        .any(|event| event.field("path") == Some("/etc/ssh/sshd_config")));
    assert!(!retained
        .iter()
        .any(|event| event.field("path") == Some("/etc/passwd")));
}

#[test]
fn incremental_file_filter_reduces_high_volume_stable_snapshots() {
    let mut events = (0..10_000)
        .map(|index| {
            RawEvent::new("file_integrity", "file_snapshot")
                .with_field("path", format!("/opt/app/cache/file-{index}.txt"))
                .with_field("hash", "stable")
        })
        .collect::<Vec<_>>();
    events.push(
        RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/var/www/html/upload.php")
            .with_field("is_web_path", "true"),
    );
    events.push(
        RawEvent::new("baseline", "file_modified")
            .with_field("path", "/etc/passwd")
            .with_field("change", "modified"),
    );
    events.push(
        RawEvent::new("file_integrity", "file_snapshot")
            .with_field("path", "/etc/passwd")
            .with_field("hash", "changed"),
    );
    let changed = super::changed_file_paths(&events);

    let retained = retain_incremental_file_events(events, &changed);

    assert_eq!(retained.len(), 3);
    assert!(retained
        .iter()
        .any(|event| event.field("path") == Some("/var/www/html/upload.php")));
    assert!(retained
        .iter()
        .any(|event| event.field("path") == Some("/etc/passwd")));
}

#[test]
fn truncation_preserves_utf8_boundaries() {
    let truncated = truncate_utf8("安全安全安全安全安全", 24);
    assert!(truncated.starts_with("安全"));
    assert!(truncated.contains("truncated"));
    assert!(truncated.len() <= 24);

    let tiny = truncate_utf8("安全安全", 5);
    assert_eq!(tiny, "安");
    assert!(tiny.len() <= 5);
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
fn active_response_annotation_applies_to_related_findings_by_source_ip() {
    let config = SentinelConfig::default();
    let mut first = web_finding("8.8.8.8", "env_file");
    first.id = "finding-1".to_string();
    let mut second = web_finding("8.8.8.8", "git_exposure");
    second.id = "finding-2".to_string();
    let mut findings = vec![first, second];
    let report = ActiveResponseReport {
        block_actions: vec![BlockAction {
            finding_id: "finding-1".to_string(),
            ip: "8.8.8.8".parse().unwrap(),
            status: BlockActionStatus::AlreadyPermanentlyBlocked,
            reason: "web probe already handled".to_string(),
            backend: Some("nftables".to_string()),
            expires_at: None,
            detail: None,
        }],
        ..ActiveResponseReport::default()
    };

    annotate_active_response(&mut findings, &report, &config);

    assert_eq!(
        evidence_value(&findings[1], "active_response_status"),
        Some("already_permanently_blocked")
    );
    assert_eq!(
        evidence_value(&findings[1], "active_response_ip"),
        Some("8.8.8.8")
    );
}

#[test]
fn notification_policy_suppresses_already_handled_active_response_findings() {
    let mut handled = web_finding("8.8.8.8", "env_file");
    handled.evidence.push(Evidence::new(
        "active_response_status",
        "already_permanently_blocked",
    ));
    let fresh = web_finding("1.1.1.1", "git_exposure");

    let (retained, suppressed) = prepare_notification_findings(vec![handled, fresh]);

    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].subject, "1.1.1.1");
    assert_eq!(suppressed, 1);
}

#[test]
fn notification_policy_groups_same_source_web_findings() {
    let mut low = web_finding("8.8.8.8", "env_file");
    low.severity = Severity::Low;
    let mut blocked = web_finding("8.8.8.8", "git_exposure");
    blocked
        .evidence
        .push(Evidence::new("active_response_status", "blocked"));
    let other = web_finding("1.1.1.1", "actuator");

    let (retained, suppressed) = prepare_notification_findings(vec![low, blocked, other]);

    assert_eq!(retained.len(), 2);
    assert_eq!(suppressed, 1);
    let grouped = retained
        .iter()
        .find(|finding| finding.subject == "8.8.8.8")
        .expect("grouped web finding");
    assert_eq!(
        evidence_value(grouped, "notification_grouped_findings"),
        Some("2")
    );
    assert_eq!(
        evidence_value(grouped, "notification_grouped_probe_families"),
        Some("env_file, git_exposure")
    );
    assert_eq!(
        evidence_value(grouped, "active_response_status"),
        Some("blocked")
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
fn ssh_login_duplicate_suppression_ignores_volatile_port_after_enrichment(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let mut config = SentinelConfig::default();
    config.noise_control.dedup_window_seconds = 3600;

    let mut previous = root_ssh_login_finding("42100");
    crate::risk_score::enrich_findings(std::slice::from_mut(&mut previous));
    previous.normalize_evidence();
    store.save_findings(std::slice::from_ref(&previous))?;

    let mut next = root_ssh_login_finding("58812");
    crate::risk_score::enrich_findings(std::slice::from_mut(&mut next));
    next.normalize_evidence();

    assert_eq!(previous.dedup_key, next.dedup_key);
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![next], &config)?;

    assert!(retained.is_empty());
    assert_eq!(suppressed, 1);
    Ok(())
}

#[test]
fn state_duplicate_suppression_uses_identity_when_dedup_key_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();

    let previous = Finding::new(
        "host",
        "Critical system file changed",
        "critical file changed",
        Severity::High,
        Category::FileIntegrity,
        "FILE-001",
        "/etc/passwd",
    )
    .with_evidence(vec![
        Evidence::new("path", "/etc/passwd"),
        Evidence::new("change", "file_modified"),
        Evidence::new("previous_hash", "old"),
        Evidence::new("current_hash", "new"),
        Evidence::new("package_activity_recent", "true"),
    ]);
    store.save_findings(std::slice::from_ref(&previous))?;

    let next = Finding::new(
        "host",
        "Critical system file changed",
        "critical file changed",
        Severity::High,
        Category::FileIntegrity,
        "FILE-001",
        "/etc/passwd",
    )
    .with_evidence_deduped_by(
        vec![
            Evidence::new("path", "/etc/passwd"),
            Evidence::new("change", "file_modified"),
            Evidence::new("current_hash", "new"),
        ],
        &["path", "change", "current_hash"],
    );

    assert_ne!(previous.dedup_key, next.dedup_key);
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![next], &config)?;

    assert!(retained.is_empty());
    assert_eq!(suppressed, 1);
    Ok(())
}

#[test]
fn new_active_response_block_is_retained_when_not_recently_seen(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();

    let mut blocked = ssh_bruteforce_finding("47.242.23.111", "16");
    blocked.id = "blocked-finding".to_string();
    blocked
        .evidence
        .push(Evidence::new("active_response_status", "blocked"));
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![blocked], &config)?;

    assert_eq!(retained.len(), 1);
    assert_eq!(suppressed, 0);
    Ok(())
}

#[test]
fn permanent_active_response_upgrade_uses_recent_duplicate_suppression(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
    let config = SentinelConfig::default();
    let previous = ssh_bruteforce_finding("47.242.23.111", "16");
    store.save_findings(std::slice::from_ref(&previous))?;

    let mut permanent = previous.clone();
    permanent.id = "permanent-block-finding".to_string();
    permanent.evidence.push(Evidence::new(
        "active_response_status",
        "permanently_blocked",
    ));
    let (retained, suppressed) = suppress_recent_duplicates(&store, vec![permanent], &config)?;

    assert!(retained.is_empty());
    assert_eq!(suppressed, 1);
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

fn root_ssh_login_finding(port: &str) -> Finding {
    Finding::new(
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
            Evidence::new("port", port),
            Evidence::new("method", "publickey"),
        ],
        &["user", "source_ip", "method"],
    )
}

fn web_finding(ip: &str, family: &str) -> Finding {
    Finding::new(
        "host",
        "Web vulnerability probing detected",
        "probe",
        Severity::Medium,
        Category::Web,
        "WEB-001",
        ip,
    )
    .with_evidence(vec![
        Evidence::new("ip", ip),
        Evidence::new("probe_family", family),
        Evidence::new("response_profile", "missing_or_rejected"),
        Evidence::new("request_count", "1"),
    ])
}
