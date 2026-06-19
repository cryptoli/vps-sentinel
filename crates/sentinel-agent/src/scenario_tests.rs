use crate::active_response::apply_active_response;
use crate::attack_fingerprint::{enrich_and_persist_findings, VERDICT_BENIGN, VERDICT_MALICIOUS};
use crate::detectors::ssh_rules::SshDetector;
use crate::detectors::web_rules::WebDetector;
use crate::detectors::{DetectContext, Detector, EventIndex};
use crate::risk_score;
use crate::storage::SqliteStore;
use sentinel_core::{evidence_value, RawEvent, SentinelConfig};
use std::sync::Arc;

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
