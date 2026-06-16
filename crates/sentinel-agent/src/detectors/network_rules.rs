use crate::detectors::command_profile::network_execution_assessment_from_event;
use crate::detectors::process_rules::{
    command_matches_allowlist, event_contains_miner_or_scanner, path_in_suspicious_dirs,
};
use crate::detectors::{evidence, path_is_allowlisted, string_field, DetectContext, Detector};
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
                "New public listening port detected",
                Category::Network,
                Severity::Medium,
                "A public listening port appeared after the stored baseline.",
            ),
            RuleMetadata::new(
                "NET-002",
                "Public listener process changed",
                Category::Network,
                Severity::Medium,
                "A public listening port is still present, but the owning process changed from the baseline.",
            ),
            RuleMetadata::new(
                "NET-003",
                "Suspicious process behind public listener",
                Category::Network,
                Severity::High,
                "A public listening port is owned by a process with suspicious execution traits.",
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
        for event in events.iter().filter(|event| {
            matches!(
                event.kind.as_str(),
                "listening_socket" | "listening_socket_owner_changed"
            )
        }) {
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
            } else if let Some(profile) = ListenerRiskProfile::from_event(event, ctx) {
                findings.push(suspicious_listener(event, ctx, profile));
            } else if event.kind == "listening_socket_owner_changed" {
                findings.push(listener_owner_changed(event, ctx));
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
        "New public listening port detected",
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

fn listener_owner_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Public listener process changed",
        "A public listening port is still present, but the owning process changed from the stored baseline.",
        Severity::Medium,
        Category::Network,
        "NET-002",
        format!(
            "{}:{}",
            string_field(event, "local_addr"),
            string_field(event, "local_port")
        ),
    )
    .with_evidence(socket_evidence(event))
    .with_recommendations(vec![
        "Confirm the service replacement was planned.".to_string(),
        "Review the current executable path and service unit.".to_string(),
        "Refresh the baseline after approved service changes.".to_string(),
    ])
}

fn suspicious_listener(
    event: &RawEvent,
    ctx: &DetectContext,
    profile: ListenerRiskProfile,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Suspicious process behind public listener",
        "A public listening port is owned by a process with suspicious execution traits.",
        Severity::High,
        Category::Network,
        "NET-003",
        format!(
            "{}:{}",
            string_field(event, "local_addr"),
            string_field(event, "local_port")
        ),
    )
    .with_evidence({
        let mut items = socket_evidence(event);
        items.push(evidence("risk_score", profile.score.to_string()));
        items.push(evidence("risk_reasons", profile.reasons.join("; ")));
        if !profile.features.is_empty() {
            items.push(evidence("risk_features", profile.features.join(", ")));
        }
        items
    })
    .with_impact(vec![
        "Attackers often bind backdoors or webshell launchers to normal-looking public ports."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Verify the executable path, package ownership, and service unit.".to_string(),
        "Preserve process and socket evidence before stopping the service.".to_string(),
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
    let mut items = vec![
        evidence("protocol", string_field(event, "protocol")),
        evidence("local_addr", string_field(event, "local_addr")),
        evidence("local_port", string_field(event, "local_port")),
    ];
    push_evidence_if_present(&mut items, event, "process_name");
    push_evidence_if_present(&mut items, event, "pid");
    push_evidence_if_present(&mut items, event, "executable");
    push_evidence_if_present(&mut items, event, "cmdline");
    push_evidence_if_present(&mut items, event, "previous_process_name");
    push_evidence_if_present(&mut items, event, "previous_executable");
    items
}

fn push_evidence_if_present(items: &mut Vec<sentinel_core::Evidence>, event: &RawEvent, key: &str) {
    let value = string_field(event, key);
    if !value.trim().is_empty() {
        items.push(evidence(key, value));
    }
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
            .copied()
            .collect();
        let expected_public = ctx
            .config
            .network
            .expected_public_ports
            .iter()
            .chain(ctx.config.network.public_listen_allowlist.iter())
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

struct ListenerRiskProfile {
    score: u16,
    reasons: Vec<String>,
    features: Vec<String>,
}

impl ListenerRiskProfile {
    fn from_event(event: &RawEvent, ctx: &DetectContext) -> Option<Self> {
        let executable = string_field(event, "executable");
        let cmdline = string_field(event, "cmdline");
        let process_name = string_field(event, "process_name");
        if path_is_allowlisted(&executable, &ctx.config.allowlist.process_paths)
            || command_matches_allowlist(&cmdline, &ctx.config.allowlist.process_command_contains)
        {
            return None;
        }
        let mut score = 0;
        let mut reasons = Vec::new();
        let mut features = Vec::new();

        if path_in_suspicious_dirs(&executable, &ctx.config.process.suspicious_dirs) {
            score += 50;
            reasons.push("executable is under a suspicious temporary directory".to_string());
        }
        if executable.contains(" (deleted)") || executable.ends_with("deleted") {
            score += 40;
            reasons.push("executable appears deleted while still running".to_string());
        }
        let command_assessment = network_execution_assessment_from_event(event);
        if command_assessment.is_suspicious() {
            score += 70;
            reasons.push(command_assessment.reason_text());
            features.push(command_assessment.feature_names());
        }
        if event_contains_miner_or_scanner(event, &ctx.config.process.known_bad_tool_names) {
            score += 70;
            reasons.push("command line contains miner or scanner indicators".to_string());
        }
        if is_shell_process_name(&process_name) {
            score += 35;
            reasons.push("listener process name is an interactive shell".to_string());
        }
        if event.kind == "listening_socket_owner_changed" && score > 0 {
            score += 20;
            reasons.push("listener owner changed from baseline".to_string());
        }

        if score >= 50 {
            Some(Self {
                score,
                reasons,
                features,
            })
        } else {
            None
        }
    }
}

fn is_shell_process_name(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh" | "busybox"
    )
}

#[cfg(test)]
mod tests;
