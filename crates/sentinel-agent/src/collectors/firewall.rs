use crate::collectors::{CollectContext, Collector};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::process::Command;

pub struct FirewallCollector;

#[async_trait]
impl Collector for FirewallCollector {
    fn name(&self) -> &'static str {
        "firewall"
    }

    async fn collect(&self, _ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        let state = firewall_state();
        Ok(vec![RawEvent::new("firewall", "firewall_state")
            .with_field("status", state.status)
            .with_field("sources", state.sources.join(", "))])
    }
}

#[derive(Debug, Clone, Default)]
struct FirewallState {
    status: String,
    sources: Vec<String>,
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
        }
    }
    if let Some(output) = iptables {
        observed_sources.push("iptables".to_string());
        if output
            .lines()
            .any(|line| line.starts_with("-A ") || line.starts_with("-P INPUT DROP"))
        {
            active_sources.push("iptables".to_string());
        }
    }

    if !active_sources.is_empty() {
        return FirewallState {
            status: "active".to_string(),
            sources: active_sources,
        };
    }
    if !observed_sources.is_empty() {
        return FirewallState {
            status: "inactive".to_string(),
            sources: observed_sources,
        };
    }
    FirewallState {
        status: "unknown".to_string(),
        sources: Vec::new(),
    }
}

fn run_command(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::firewall_state_from_outputs;

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
}
