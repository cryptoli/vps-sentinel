use crate::active_response::apply_active_response;
use crate::attack_fingerprint::{enrich_and_persist_findings, VERDICT_BENIGN, VERDICT_MALICIOUS};
use crate::baseline::{diff_snapshots, BaselineSnapshot};
use crate::detectors::default_detectors;
use crate::detectors::ssh_rules::SshDetector;
use crate::detectors::web_rules::WebDetector;
use crate::detectors::{DetectContext, Detector, EventIndex};
use crate::risk_score;
use crate::storage::SqliteStore;
use sentinel_core::{evidence_value, RawEvent, SentinelConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

struct ReplayScenario {
    name: &'static str,
    config: SentinelConfig,
    events: Vec<RawEvent>,
    expected_rules: Vec<&'static str>,
    forbidden_rules: Vec<&'static str>,
}

impl ReplayScenario {
    fn run(&self) -> Vec<sentinel_core::Finding> {
        let ctx = DetectContext::new(Arc::new(self.config.clone()));
        let index = EventIndex::new(&self.events);
        let mut findings = Vec::new();
        for detector in default_detectors() {
            findings.extend(detector.detect_indexed(&self.events, &index, &ctx));
        }
        for finding in &mut findings {
            finding.normalize_evidence();
        }
        findings
    }

    fn assert_expected(&self) {
        let findings = self.run();
        let rule_ids = findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        for expected in &self.expected_rules {
            assert!(
                rule_ids.contains(expected),
                "scenario {} expected rule {}, got {:?}",
                self.name,
                expected,
                rule_ids
            );
        }
        for forbidden in &self.forbidden_rules {
            assert!(
                !rule_ids.contains(forbidden),
                "scenario {} forbids rule {}, got {:?}",
                self.name,
                forbidden,
                rule_ids
            );
        }
    }
}

#[test]
fn scenario_web_rotating_ip_clusters_by_method_not_ip() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::NamedTempFile::new()?;
    let store = SqliteStore::open(temp.path())?;
    let config = SentinelConfig::default();
    let mut first = web_probe_findings("8.8.8.8", "/.env?token=123", &config);
    let mut second = web_probe_findings("1.1.1.1", "/.env?token=999", &config);

    risk_score::enrich_findings(&mut first);
    risk_score::enrich_findings(&mut second);
    enrich_and_persist_findings(&mut first, &config, &store)?;
    enrich_and_persist_findings(&mut second, &config, &store)?;

    let fingerprints = store.list_attack_fingerprints(10)?;

    assert_eq!(fingerprints.len(), 1);
    assert_eq!(fingerprints[0].kind, "web_probe");
    assert_eq!(fingerprints[0].source_ips.len(), 2);
    Ok(())
}

#[test]
fn scenario_benign_fingerprint_feedback_prevents_block() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::NamedTempFile::new()?;
    let store = SqliteStore::open(temp.path())?;
    let mut config = SentinelConfig::default();
    config.active_response.enabled = true;
    config.active_response.web_probe_block_threshold = 1;

    let mut first = web_probe_findings("8.8.8.8", "/.git/config", &config);
    risk_score::enrich_findings(&mut first);
    enrich_and_persist_findings(&mut first, &config, &store)?;
    let fingerprint_id = store.list_attack_fingerprints(10)?[0].id.clone();
    assert!(store.set_attack_fingerprint_verdict(&fingerprint_id, VERDICT_BENIGN)?);

    let mut second = web_probe_findings("8.8.4.4", "/.git/config", &config);
    risk_score::enrich_findings(&mut second);
    enrich_and_persist_findings(&mut second, &config, &store)?;
    assert_eq!(
        evidence_value(&second[0].evidence, "attack_fingerprint_verdict"),
        Some(VERDICT_BENIGN)
    );

    let report = apply_active_response(&second, &config, &store)?;

    assert_eq!(report.planned_blocks, 0);
    Ok(())
}

#[test]
fn scenario_malicious_fingerprint_still_respects_allowlist(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::NamedTempFile::new()?;
    let store = SqliteStore::open(temp.path())?;
    let mut config = SentinelConfig::default();
    config.active_response.enabled = true;
    config.active_response.web_probe_block_threshold = 99;

    let mut first = web_probe_findings("8.8.8.8", "/.git/config", &config);
    risk_score::enrich_findings(&mut first);
    enrich_and_persist_findings(&mut first, &config, &store)?;
    let fingerprint_id = store.list_attack_fingerprints(10)?[0].id.clone();
    assert!(store.set_attack_fingerprint_verdict(&fingerprint_id, VERDICT_MALICIOUS)?);

    let mut second = web_probe_findings("8.8.4.4", "/.git/config", &config);
    risk_score::enrich_findings(&mut second);
    enrich_and_persist_findings(&mut second, &config, &store)?;
    assert_eq!(
        evidence_value(&second[0].evidence, "attack_fingerprint_action_hint"),
        Some("block")
    );

    config.allowlist.ips.push("8.8.4.4".to_string());
    let report = apply_active_response(&second, &config, &store)?;

    assert_eq!(report.planned_blocks, 0);
    Ok(())
}

#[test]
fn scenario_trusted_admin_ssh_success_is_negative_case() {
    let mut config = SentinelConfig::default();
    config.ssh.alert_on_trusted_admin_login = false;
    config.ssh.trusted_admin_ips.push("8.8.8.8".to_string());
    let events = vec![RawEvent::new("ssh", "ssh_auth")
        .with_field("source_ip", "8.8.8.8")
        .with_field("user", "root")
        .with_field("method", "publickey")
        .with_field("outcome", "success")];
    let ctx = DetectContext::new(Arc::new(config));
    let index = EventIndex::new(&events);

    let findings = SshDetector.detect_indexed(&events, &index, &ctx);

    assert!(findings.is_empty());
}

#[test]
fn replay_suspicious_listener_on_expected_port_still_alerts() {
    ReplayScenario {
        name: "hidden listener behind 443",
        config: SentinelConfig::default(),
        events: vec![
            RawEvent::new("network", "listening_socket")
                .with_field("protocol", "tcp")
                .with_field("local_addr", "0.0.0.0")
                .with_field("local_port", "443")
                .with_field("pid", "42")
                .with_field("process_name", ".nginx")
                .with_field("executable", "/usr/local/bin/.nginx")
                .with_field("cmdline", "/usr/local/bin/.nginx --serve"),
            RawEvent::new("process", "process_snapshot")
                .with_field("pid", "42")
                .with_field("name", ".nginx")
                .with_field("exe_path", "/usr/local/bin/.nginx")
                .with_field("parent_name", "bash")
                .with_field("euid", "0"),
            RawEvent::new("network", "outbound_connection")
                .with_field("pid", "42")
                .with_field("remote_addr", "8.8.8.8")
                .with_field("remote_port", "443")
                .with_field("remote_public", "true"),
        ],
        expected_rules: vec!["NET-003", "PROC-005"],
        forbidden_rules: vec![],
    }
    .assert_expected();
}

#[test]
fn replay_plain_service_fanout_is_negative_case() {
    let mut events = vec![
        RawEvent::new("network", "listening_socket")
            .with_field("protocol", "tcp")
            .with_field("local_addr", "0.0.0.0")
            .with_field("local_port", "443")
            .with_field("pid", "42")
            .with_field("process_name", "api")
            .with_field("executable", "/usr/local/bin/api")
            .with_field("cmdline", "/usr/local/bin/api"),
        RawEvent::new("process", "process_snapshot")
            .with_field("pid", "42")
            .with_field("name", "api")
            .with_field("exe_path", "/usr/local/bin/api")
            .with_field("parent_name", "systemd")
            .with_field("euid", "0")
            .with_field("socket_fd_count", "64"),
    ];
    for index in 1..=14 {
        events.push(
            RawEvent::new("network", "outbound_connection")
                .with_field("pid", "42")
                .with_field("remote_addr", format!("8.8.4.{index}"))
                .with_field("remote_port", "443")
                .with_field("remote_public", "true"),
        );
    }
    ReplayScenario {
        name: "plain service with outbound fanout",
        config: SentinelConfig::default(),
        events,
        expected_rules: vec![],
        forbidden_rules: vec!["NET-003", "PROC-005"],
    }
    .assert_expected();
}

#[test]
fn replay_authorized_keys_semantic_drift_alerts() {
    let previous = BaselineSnapshot::from_events(&[RawEvent::new("file", "file_snapshot")
        .with_field("path", "/root/.ssh/authorized_keys")
        .with_field("hash", "old")
        .with_field("semantic_kind", "authorized_keys")
        .with_field("semantic_hash", "semantic-old")
        .with_field("semantic_summary", "keys=1")]);
    let current = BaselineSnapshot::from_events(&[RawEvent::new("file", "file_snapshot")
        .with_field("path", "/root/.ssh/authorized_keys")
        .with_field("hash", "new")
        .with_field("semantic_kind", "authorized_keys")
        .with_field("semantic_hash", "semantic-new")
        .with_field("semantic_summary", "keys=2 options=from")]);
    ReplayScenario {
        name: "authorized_keys semantic drift",
        config: SentinelConfig::default(),
        events: diff_snapshots(&previous, &current),
        expected_rules: vec!["SSH-005"],
        forbidden_rules: vec!["FILE-001"],
    }
    .assert_expected();
}

fn web_probe_findings(
    ip: &str,
    path: &str,
    config: &SentinelConfig,
) -> Vec<sentinel_core::Finding> {
    let events = vec![RawEvent::new("web", "web_access")
        .with_field("ip", ip)
        .with_field("method", "GET")
        .with_field("path", path)
        .with_field("status", "404")];
    let ctx = DetectContext::new(Arc::new(config.clone()));
    let index = EventIndex::new(&events);
    let mut findings = WebDetector.detect_indexed(&events, &index, &ctx);
    for finding in &mut findings {
        finding.normalize_evidence();
    }
    findings
}
