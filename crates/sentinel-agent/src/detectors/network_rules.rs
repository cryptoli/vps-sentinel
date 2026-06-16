use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

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
            if ctx.config.allowlist.listening_ports.contains(&port)
                || ctx.config.network.public_listen_allowlist.contains(&port)
            {
                continue;
            }
            if !is_public_addr(event.field("local_addr").unwrap_or("")) {
                continue;
            }
            if risky_public_port(port) {
                findings.push(risky_port(event, ctx));
            } else if ctx.config.network.alert_on_new_listening_port {
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
        "A port is listening on a public address and is not allowlisted.",
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
        "Restrict access with firewall rules when public exposure is not required.".to_string(),
    ])
}

fn risky_port(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "High-risk public service port exposed",
        "A commonly abused database, Docker, metrics, or dashboard port is publicly listening.",
        Severity::High,
        Category::ConfigRisk,
        "CONFIG-003",
        format!("{}:{}", string_field(event, "local_addr"), string_field(event, "local_port")),
    )
    .with_evidence(socket_evidence(event))
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

fn risky_public_port(port: u16) -> bool {
    matches!(
        port,
        2375 | 2376 | 3000 | 3306 | 5432 | 6379 | 9090 | 9200 | 27017
    )
}
