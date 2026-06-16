use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::BTreeSet;

pub struct NetworkDetector;

impl Detector for NetworkDetector {
    fn name(&self) -> &'static str {
        "network_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "NET-001",
                "Public listening port detected",
                Category::Network,
                Severity::Medium,
                "A process is listening on a public address and the port is not allowlisted.",
            ),
            RuleMetadata::new(
                "CONFIG-003",
                "Public database or admin port exposed",
                Category::ConfigRisk,
                Severity::High,
                "A high-risk service port is listening on a public address.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let policy = PortPolicy::from_context(ctx);
        for event in events
            .iter()
            .filter(|event| event.kind == "listening_socket")
        {
            let port = event
                .field("local_port")
                .and_then(|value| value.parse::<u16>().ok());
            let Some(port) = port else {
                continue;
            };
            if !is_public_addr(event.field("local_addr").unwrap_or("")) {
                continue;
            }
            if policy.is_allowlisted(port) {
                continue;
            }
            if policy.is_high_risk(port) {
                findings.push(risky_port(event, ctx, policy.service_name(port)));
            } else if policy.is_expected_public(port) {
                continue;
            } else if event.source == "baseline" && ctx.config.network.alert_on_new_listening_port {
                findings.push(public_listen(event, ctx));
            }
        }
        findings
    }
}

fn public_listen(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Public listening port detected",
        "A new public listening port appeared after the stored baseline.",
        Severity::Medium,
        Category::Network,
        "NET-001",
        format!(
            "{}:{}",
            string_field(event, "local_addr"),
            string_field(event, "local_port")
        ),
    )
    .with_evidence(socket_evidence(event))
    .with_recommendations(vec![
        "Confirm the service is intended to be internet-facing.".to_string(),
        "Refresh the baseline after approved service changes.".to_string(),
        "Restrict access with firewall rules when public exposure is not required.".to_string(),
    ])
}

fn risky_port(event: &RawEvent, ctx: &DetectContext, service_name: &'static str) -> Finding {
    Finding::new(
        &ctx.host_id,
        "High-risk public service port exposed",
        "A database, management, container, metrics, or dashboard service is publicly listening.",
        Severity::High,
        Category::ConfigRisk,
        "CONFIG-003",
        format!("{}:{}", string_field(event, "local_addr"), string_field(event, "local_port")),
    )
    .with_evidence({
        let mut items = socket_evidence(event);
        items.push(evidence("service_profile", service_name));
        items
    })
    .with_impact(vec![
        "Public exposure of admin or database services can lead to compromise if authentication or patching is weak.".to_string(),
    ])
    .with_recommendations(vec![
        "Bind the service to localhost or VPN-only interfaces unless public access is required.".to_string(),
        "Verify authentication, TLS, and firewall policy.".to_string(),
    ])
}

fn socket_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("protocol", string_field(event, "protocol")),
        evidence("local_addr", string_field(event, "local_addr")),
        evidence("local_port", string_field(event, "local_port")),
    ]
}

fn is_public_addr(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "ipv6")
}

struct PortPolicy {
    allowlisted: BTreeSet<u16>,
    expected_public: BTreeSet<u16>,
    high_risk_public: BTreeSet<u16>,
}

impl PortPolicy {
    fn from_context(ctx: &DetectContext) -> Self {
        let allowlisted = ctx
            .config
            .allowlist
            .listening_ports
            .iter()
            .chain(ctx.config.network.public_listen_allowlist.iter())
            .copied()
            .collect();
        let expected_public = ctx
            .config
            .network
            .expected_public_ports
            .iter()
            .copied()
            .collect();
        let high_risk_public = ctx
            .config
            .network
            .high_risk_public_ports
            .iter()
            .copied()
            .collect();
        Self {
            allowlisted,
            expected_public,
            high_risk_public,
        }
    }

    fn is_allowlisted(&self, port: u16) -> bool {
        self.allowlisted.contains(&port)
    }

    fn is_expected_public(&self, port: u16) -> bool {
        self.expected_public.contains(&port)
    }

    fn is_high_risk(&self, port: u16) -> bool {
        self.high_risk_public.contains(&port)
    }

    fn service_name(&self, port: u16) -> &'static str {
        known_port_profile(port).unwrap_or("configured high-risk service")
    }
}

fn known_port_profile(port: u16) -> Option<&'static str> {
    match port {
        11211 => Some("Memcached"),
        2375 | 2376 => Some("Docker API"),
        2379 | 2380 => Some("etcd"),
        3000 => Some("development dashboard"),
        3306 => Some("MySQL or MariaDB"),
        3389 => Some("RDP"),
        5432 => Some("PostgreSQL"),
        5601 => Some("Kibana"),
        5672 | 15672 => Some("RabbitMQ"),
        5900 | 5901 => Some("VNC"),
        5984 => Some("CouchDB"),
        5985 | 5986 => Some("WinRM"),
        6379 => Some("Redis"),
        6443 => Some("Kubernetes API"),
        9090 => Some("Prometheus or admin dashboard"),
        9200 | 9300 => Some("Elasticsearch"),
        10250 | 10255 => Some("Kubelet API"),
        27017..=27019 => Some("MongoDB"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkDetector;
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn suppresses_expected_web_ports() {
        let findings = detect_with_default_config(vec![socket_event("network", 443)]);
        assert!(findings.is_empty());
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
}
