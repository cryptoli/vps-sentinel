use crate::collectors::{CollectContext, Collector};
use crate::utils::command::successful_stdout;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const FIREWALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

pub struct FirewallCollector;

#[async_trait]
impl Collector for FirewallCollector {
    fn name(&self) -> &'static str {
        "firewall"
    }

    async fn collect(&self, _ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        let state = firewall_state();
        let protected_tcp_ports = state
            .protected_tcp_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Ok(vec![RawEvent::new("firewall", "firewall_state")
            .with_field("status", state.status)
            .with_field("sources", state.sources.join(", "))
            .with_field("protected_tcp_ports", protected_tcp_ports)])
    }
}

#[derive(Debug, Clone, Default)]
struct FirewallState {
    status: String,
    sources: Vec<String>,
    protected_tcp_ports: BTreeSet<u16>,
}

fn firewall_state() -> FirewallState {
    firewall_state_from_outputs(
        run_command("ufw", &["status"]),
        run_command("firewall-cmd", &["--state"]),
        run_command("nft", &["list", "ruleset"]),
        run_command("iptables", &["-S"]),
    )
}

fn firewall_state_from_outputs(
    ufw: Option<String>,
    firewalld: Option<String>,
    nftables: Option<String>,
    iptables: Option<String>,
) -> FirewallState {
    let mut active_sources = Vec::new();
    let mut observed_sources = Vec::new();
    let mut protected_tcp_ports = BTreeSet::new();

    if let Some(output) = ufw {
        observed_sources.push("ufw".to_string());
        let lowered = output.to_ascii_lowercase();
        if lowered.contains("status: active") {
            active_sources.push("ufw".to_string());
        }
    }
    if let Some(output) = firewalld {
        observed_sources.push("firewalld".to_string());
        if output.trim() == "running" {
            active_sources.push("firewalld".to_string());
        }
    }
    if let Some(output) = nftables {
        observed_sources.push("nftables".to_string());
        if !output.trim().is_empty() {
            active_sources.push("nftables".to_string());
            protected_tcp_ports.extend(protected_tcp_ports_from_nft(&output));
        }
    }
    if let Some(output) = iptables {
        observed_sources.push("iptables".to_string());
        if output
            .lines()
            .any(|line| line.starts_with("-A ") || line.starts_with("-P INPUT DROP"))
        {
            active_sources.push("iptables".to_string());
            protected_tcp_ports.extend(protected_tcp_ports_from_iptables(&output));
        }
    }

    if !active_sources.is_empty() {
        return FirewallState {
            status: "active".to_string(),
            sources: active_sources,
            protected_tcp_ports,
        };
    }
    if !observed_sources.is_empty() {
        return FirewallState {
            status: "inactive".to_string(),
            sources: observed_sources,
            protected_tcp_ports,
        };
    }
    FirewallState {
        status: "unknown".to_string(),
        sources: Vec::new(),
        protected_tcp_ports,
    }
}

fn protected_tcp_ports_from_nft(output: &str) -> BTreeSet<u16> {
    let sets = nft_port_sets(output);
    let mut ports = BTreeSet::new();
    for line in output.lines().map(str::trim) {
        if !is_drop_or_reject_rule(line) || !line.contains("tcp dport") {
            continue;
        }
        if let Some(set_name) = nft_tcp_dport_set_ref(line) {
            if let Some(set_ports) = sets.get(set_name) {
                ports.extend(set_ports.iter().copied());
            }
            continue;
        }
        ports.extend(ports_after_marker(line, "tcp dport"));
    }
    ports
}

fn nft_port_sets(output: &str) -> BTreeMap<String, BTreeSet<u16>> {
    let mut sets = BTreeMap::new();
    let mut current_name: Option<String> = None;
    let mut current_body = String::new();

    for line in output.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("set ").and_then(|rest| {
            rest.split_whitespace()
                .next()
                .filter(|value| !value.is_empty())
        }) {
            current_name = Some(name.to_string());
            current_body.clear();
        }
        if current_name.is_some() {
            current_body.push_str(line);
            current_body.push(' ');
            if line == "}" {
                if let Some(name) = current_name.take() {
                    let ports = extract_port_numbers(&current_body);
                    if !ports.is_empty() {
                        sets.insert(name, ports);
                    }
                }
                current_body.clear();
            }
        }
    }

    sets
}

fn nft_tcp_dport_set_ref(line: &str) -> Option<&str> {
    let rest = line.split_once("tcp dport")?.1.trim_start();
    let rest = rest.strip_prefix('@')?;
    rest.split(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == ';')
        .next()
        .filter(|name| !name.is_empty())
}

fn protected_tcp_ports_from_iptables(output: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in output.lines().map(str::trim) {
        if !line.contains(" -p tcp ")
            || !is_drop_or_reject_rule(line)
            || is_source_restricted_iptables_rule(line)
        {
            continue;
        }
        ports.extend(ports_after_marker(line, "--dports"));
        ports.extend(ports_after_marker(line, "--dport"));
    }
    ports
}

fn is_drop_or_reject_rule(line: &str) -> bool {
    line.split_whitespace()
        .any(|token| matches!(token, "drop" | "reject" | "DROP" | "REJECT"))
}

fn is_source_restricted_iptables_rule(line: &str) -> bool {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    tokens.windows(2).any(|pair| {
        matches!(pair[0], "-s" | "--source") && !matches!(pair[1], "0.0.0.0/0" | "0/0" | "::/0")
    })
}

fn ports_after_marker(line: &str, marker: &str) -> BTreeSet<u16> {
    line.split_once(marker)
        .map(|(_, rest)| extract_port_numbers(&port_fragment_before_verdict(rest)))
        .unwrap_or_default()
}

fn port_fragment_before_verdict(rest: &str) -> String {
    let mut fragment = Vec::new();
    for token in rest.split_whitespace() {
        if matches!(
            token,
            "drop" | "reject" | "accept" | "counter" | "DROP" | "REJECT" | "ACCEPT"
        ) || token == "-j"
        {
            break;
        }
        fragment.push(token);
    }
    fragment.join(" ")
}

fn extract_port_numbers(value: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for token in value
        .replace(['{', '}', ',', ';'], " ")
        .split_whitespace()
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
    {
        if let Some((start, end)) = parse_port_range(token) {
            ports.extend(start..=end);
        } else if let Ok(port) = token.parse::<u16>() {
            ports.insert(port);
        }
    }
    ports
}

fn parse_port_range(token: &str) -> Option<(u16, u16)> {
    let (start, end) = token.split_once('-').or_else(|| token.split_once(".."))?;
    let start = start.parse::<u16>().ok()?;
    let end = end.parse::<u16>().ok()?;
    (start <= end && end.saturating_sub(start) <= 1024).then_some((start, end))
}

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    successful_stdout(program, args, FIREWALL_COMMAND_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::firewall_state_from_outputs;
    use super::{protected_tcp_ports_from_iptables, protected_tcp_ports_from_nft};

    #[test]
    fn classifies_active_and_observed_firewall_sources() {
        let state = firewall_state_from_outputs(
            Some("Status: active\n".to_string()),
            Some("not running\n".to_string()),
            Some("table inet filter {}\n".to_string()),
            Some("-P INPUT ACCEPT\n".to_string()),
        );

        assert_eq!(state.status, "active");
        assert!(state.sources.contains(&"ufw".to_string()));
        assert!(state.sources.contains(&"nftables".to_string()));
        assert!(!state.sources.contains(&"iptables".to_string()));
    }

    #[test]
    fn reports_inactive_when_tools_exist_without_rules() {
        let state = firewall_state_from_outputs(
            Some("Status: inactive\n".to_string()),
            None,
            Some(String::new()),
            Some("-P INPUT ACCEPT\n".to_string()),
        );

        assert_eq!(state.status, "inactive");
        assert_eq!(
            state.sources,
            vec![
                "ufw".to_string(),
                "nftables".to_string(),
                "iptables".to_string()
            ]
        );
    }

    #[test]
    fn extracts_unrestricted_nft_drop_ports() {
        let ports = protected_tcp_ports_from_nft(
            r#"
table inet vps_sentinel_exposure_guard {
  set protected_tcp_ports {
    type inet_service
    flags interval
    elements = { 3306, 5672, 6379, 27017 }
  }
  chain protect_tcp {
    ip saddr { 10.0.0.0/8 } tcp dport @protected_tcp_ports accept
    tcp dport @protected_tcp_ports drop comment "vps-sentinel exposure guard"
  }
}
"#,
        );

        assert!(ports.contains(&3306));
        assert!(ports.contains(&5672));
        assert!(ports.contains(&6379));
        assert!(ports.contains(&27017));
    }

    #[test]
    fn extracts_unrestricted_iptables_drop_ports() {
        let ports = protected_tcp_ports_from_iptables(
            "-A INPUT -p tcp -m multiport --dports 3000,3306 -j DROP\n\
             -A INPUT -s 203.0.113.10/32 -p tcp --dport 6379 -j DROP\n",
        );

        assert!(ports.contains(&3000));
        assert!(ports.contains(&3306));
        assert!(!ports.contains(&6379));
    }
}
