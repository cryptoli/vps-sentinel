use crate::detectors::command_profile::network_execution_assessment_from_event;
use crate::detectors::process_rules::{
    command_matches_allowlist, event_contains_miner_or_scanner, path_in_suspicious_dirs,
};
use crate::detectors::{
    evidence, path_is_allowlisted, string_field, DetectContext, Detector, EventIndex,
};
use crate::rules::model::RuleMetadata;
use crate::utils::ip::is_public_listener_addr;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::{BTreeMap, BTreeSet};

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
        let index = EventIndex::new(events);
        detect_network_events(&index, ctx)
    }

    fn detect_indexed(
        &self,
        _events: &[RawEvent],
        index: &EventIndex<'_>,
        ctx: &DetectContext,
    ) -> Vec<Finding> {
        detect_network_events(index, ctx)
    }
}

fn detect_network_events(index: &EventIndex<'_>, ctx: &DetectContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let policy = PortPolicy::from_context(ctx);
    let firewall = firewall_context(index.kind("firewall_state"));
    let process_context = process_context_by_pid(index.kind("process_snapshot"));
    for event in index
        .kind("listening_socket")
        .chain(index.kind("listening_socket_owner_changed"))
    {
        let port = event
            .field("local_port")
            .and_then(|value| value.parse::<u16>().ok());
        let Some(port) = port else {
            continue;
        };
        if !is_public_listener_addr(event.field("local_addr").unwrap_or("")) {
            continue;
        }
        if policy.is_allowlisted(port) {
            continue;
        }
        let owner_context = event.field("pid").and_then(|pid| process_context.get(pid));
        let high_risk_service = policy.high_risk_service_name(port);
        if let Some(profile) = ListenerRiskProfile::from_event(event, ctx, owner_context) {
            findings.push(suspicious_listener(
                event,
                ctx,
                profile,
                high_risk_service,
                firewall.as_ref(),
                owner_context,
            ));
        } else if let Some(service_name) = high_risk_service {
            findings.push(risky_port(
                event,
                ctx,
                service_name,
                firewall.as_ref(),
                owner_context,
            ));
        } else if event.kind == "listening_socket_owner_changed" {
            findings.push(listener_owner_changed(
                event,
                ctx,
                firewall.as_ref(),
                owner_context,
            ));
        } else if policy.is_expected_public(port) {
            continue;
        } else if event.source == "baseline"
            && ctx.config.network.alert_on_new_listening_port
            && is_tcp_protocol(event)
        {
            findings.push(public_listen(event, ctx, firewall.as_ref(), owner_context));
        }
    }
    findings
}

fn public_listen(
    event: &RawEvent,
    ctx: &DetectContext,
    firewall: Option<&FirewallContext>,
    process: Option<&ProcessContext>,
) -> Finding {
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
    .with_evidence_deduped_by(
        socket_evidence_with_context(event, firewall, process),
        &["protocol", "local_addr", "local_port"],
    )
    .with_recommendations(vec![
        "Confirm the service is intended to be internet-facing.".to_string(),
        "Refresh the baseline after approved service changes.".to_string(),
        "Restrict access with firewall rules when public exposure is not required.".to_string(),
    ])
}

fn listener_owner_changed(
    event: &RawEvent,
    ctx: &DetectContext,
    firewall: Option<&FirewallContext>,
    process: Option<&ProcessContext>,
) -> Finding {
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
    .with_evidence_deduped_by(
        socket_evidence_with_context(event, firewall, process),
        &[
            "protocol",
            "local_addr",
            "local_port",
            "process_name",
            "executable",
            "previous_process_name",
            "previous_executable",
        ],
    )
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
    high_risk_service: Option<&'static str>,
    firewall: Option<&FirewallContext>,
    process: Option<&ProcessContext>,
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
    .with_evidence_deduped_by(
        {
            let mut items = socket_evidence_with_context(event, firewall, process);
            items.push(evidence("risk_score", profile.score.to_string()));
            items.push(evidence("risk_reasons", profile.reasons.join("; ")));
            if !profile.features.is_empty() {
                items.push(evidence("risk_features", profile.features.join(", ")));
            }
            if let Some(service_name) = high_risk_service {
                items.push(evidence("service_profile", service_name));
            }
            items
        },
        &[
            "protocol",
            "local_addr",
            "local_port",
            "process_name",
            "executable",
            "risk_features",
            "service_profile",
        ],
    )
    .with_impact(vec![
        "Attackers often bind backdoors or webshell launchers to normal-looking public ports."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Verify the executable path, package ownership, and service unit.".to_string(),
        "Preserve process and socket evidence before stopping the service.".to_string(),
    ])
}

fn risky_port(
    event: &RawEvent,
    ctx: &DetectContext,
    service_name: &'static str,
    firewall: Option<&FirewallContext>,
    process: Option<&ProcessContext>,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        "High-risk public service port exposed",
        "A database, management, container, metrics, or dashboard service is publicly listening.",
        Severity::High,
        Category::ConfigRisk,
        "CONFIG-003",
        format!("{}:{}", string_field(event, "local_addr"), string_field(event, "local_port")),
    )
    .with_evidence_deduped_by({
        let mut items = socket_evidence_with_context(event, firewall, process);
        items.push(evidence("service_profile", service_name));
        items
    }, &["protocol", "local_addr", "local_port", "service_profile"])
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

fn socket_evidence_with_context(
    event: &RawEvent,
    firewall: Option<&FirewallContext>,
    process: Option<&ProcessContext>,
) -> Vec<sentinel_core::Evidence> {
    let mut items = socket_evidence(event);
    if let Some(firewall) = firewall {
        items.push(evidence("firewall_status", firewall.status.clone()));
        if !firewall.sources.is_empty() {
            items.push(evidence("firewall_sources", firewall.sources.join(", ")));
        }
    }
    if let Some(process) = process {
        for key in [
            "parent_name",
            "systemd_unit",
            "systemd_execstart",
            "container_context",
            "exe_uid",
            "exe_gid",
            "exe_size",
            "exe_hash_blake3",
        ] {
            push_context_evidence(&mut items, process, key);
        }
    }
    items
}

#[derive(Debug, Clone)]
struct FirewallContext {
    status: String,
    sources: Vec<String>,
}

fn firewall_context<'a>(events: impl IntoIterator<Item = &'a RawEvent>) -> Option<FirewallContext> {
    let event = events.into_iter().next()?;
    Some(FirewallContext {
        status: string_field(event, "status"),
        sources: string_field(event, "sources")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
    })
}

#[derive(Debug, Clone, Default)]
struct ProcessContext {
    fields: BTreeMap<String, String>,
}

impl ProcessContext {
    fn field(&self, key: &str) -> &str {
        self.fields.get(key).map(String::as_str).unwrap_or("")
    }
}

fn process_context_by_pid<'a>(
    events: impl IntoIterator<Item = &'a RawEvent>,
) -> BTreeMap<String, ProcessContext> {
    let mut contexts = BTreeMap::new();
    for event in events {
        let Some(pid) = event.field("pid").filter(|pid| !pid.trim().is_empty()) else {
            continue;
        };
        let fields = [
            "parent_name",
            "systemd_unit",
            "systemd_execstart",
            "container_context",
            "exe_uid",
            "exe_gid",
            "exe_size",
            "exe_hash_blake3",
        ]
        .into_iter()
        .filter_map(|key| {
            event
                .field(key)
                .filter(|value| !value.trim().is_empty())
                .map(|value| (key.to_string(), value.to_string()))
        })
        .collect();
        contexts.insert(pid.to_string(), ProcessContext { fields });
    }
    contexts
}

fn push_context_evidence(
    items: &mut Vec<sentinel_core::Evidence>,
    context: &ProcessContext,
    key: &str,
) {
    let value = context.field(key);
    if !value.trim().is_empty() {
        items.push(evidence(key, value));
    }
}

fn push_evidence_if_present(items: &mut Vec<sentinel_core::Evidence>, event: &RawEvent, key: &str) {
    let value = string_field(event, key);
    if !value.trim().is_empty() {
        items.push(evidence(key, value));
    }
}

fn is_tcp_protocol(event: &RawEvent) -> bool {
    event
        .field("protocol")
        .is_some_and(|protocol| protocol.starts_with("tcp"))
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

    fn high_risk_service_name(&self, port: u16) -> Option<&'static str> {
        self.is_high_risk(port)
            .then(|| known_port_profile(port).unwrap_or("configured high-risk service"))
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
    fn from_event(
        event: &RawEvent,
        ctx: &DetectContext,
        process: Option<&ProcessContext>,
    ) -> Option<Self> {
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
            reasons.push("process identity matches a configured miner or scanner tool".to_string());
            features.push("known_bad_tool".to_string());
        }
        if is_shell_process_name(&process_name) {
            score += 35;
            reasons.push("listener process name is an interactive shell".to_string());
        }
        if process.is_some_and(|process| {
            let execstart = process.field("systemd_execstart");
            !execstart.trim().is_empty()
                && !execstart_matches_process(execstart, &executable, &process_name)
        }) {
            score += 30;
            reasons.push(
                "systemd ExecStart does not appear to match the listener executable".to_string(),
            );
            features.push("systemd_execstart_mismatch".to_string());
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

fn execstart_matches_process(execstart: &str, executable: &str, process_name: &str) -> bool {
    if executable.trim().is_empty() && process_name.trim().is_empty() {
        return true;
    }
    let executable = executable.trim();
    if !executable.is_empty() && execstart.contains(executable) {
        return true;
    }
    let executable_name = executable_basename(executable);
    execstart.split_whitespace().any(|token| {
        let token = token.trim_matches(|ch: char| {
            ch.is_ascii_whitespace()
                || matches!(
                    ch,
                    '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
                )
        });
        let token_name = executable_basename(token);
        (!executable_name.is_empty() && token_name == executable_name)
            || (!process_name.trim().is_empty() && token_name == process_name)
    })
}

fn executable_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn is_shell_process_name(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh" | "busybox"
    )
}

#[cfg(test)]
mod tests;
