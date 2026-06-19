use crate::detectors::string_field;
use sentinel_core::RawEvent;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default)]
pub(crate) struct OutboundProfile {
    pub total: usize,
    pub public: usize,
    pub remote_ports: Vec<String>,
    pub public_remote_addrs: Vec<String>,
    pub remote_addr_sample_truncated: bool,
}

pub(crate) fn outbound_profiles_by_pid<'a>(
    events: impl IntoIterator<Item = &'a RawEvent>,
    remote_addr_sample_limit: usize,
) -> BTreeMap<String, OutboundProfile> {
    let mut by_pid = BTreeMap::<String, OutboundProfile>::new();
    let mut public_addr_sets = BTreeMap::<String, BTreeSet<String>>::new();
    for event in events {
        let Some(pid) = event.field("pid").filter(|pid| !pid.trim().is_empty()) else {
            continue;
        };
        let context = by_pid.entry(pid.to_string()).or_default();
        context.total += 1;
        if event.field("remote_public") == Some("true") {
            context.public += 1;
            if let Some(addr) = event
                .field("remote_addr")
                .filter(|addr| !addr.trim().is_empty())
            {
                let addrs = public_addr_sets.entry(pid.to_string()).or_default();
                if addrs.len() < remote_addr_sample_limit {
                    addrs.insert(addr.to_string());
                } else if !addrs.contains(addr) {
                    context.remote_addr_sample_truncated = true;
                }
            }
        }
        if let Some(port) = event
            .field("remote_port")
            .filter(|port| !port.trim().is_empty())
        {
            push_unique_sorted(&mut context.remote_ports, port);
        }
    }
    for (pid, addrs) in public_addr_sets {
        if let Some(context) = by_pid.get_mut(&pid) {
            context.public_remote_addrs = addrs.into_iter().collect();
        }
    }
    by_pid
}

pub(crate) fn attach_outbound_profile(event: RawEvent, profile: &OutboundProfile) -> RawEvent {
    let mut event = event
        .with_field("outbound_connection_count", profile.total.to_string())
        .with_field("public_outbound_count", profile.public.to_string())
        .with_field("outbound_remote_ports", profile.remote_ports.join(", "));
    if !profile.public_remote_addrs.is_empty() {
        event = event.with_field(
            "public_outbound_remote_addrs",
            profile.public_remote_addrs.join(", "),
        );
    }
    if profile.remote_addr_sample_truncated {
        event = event.with_field("outbound_remote_addr_sample_truncated", "true");
    }
    event
}

pub(crate) fn is_shell_or_scheduler_parent(parent_name: &str) -> bool {
    matches!(
        parent_name.trim().to_ascii_lowercase().as_str(),
        "sh" | "bash" | "dash" | "zsh" | "fish" | "cron" | "crond" | "atd"
    )
}

pub(crate) fn hidden_basename(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .map(|name| name.starts_with('.') && name.len() > 1)
        .unwrap_or(false)
}

pub(crate) fn execstart_mismatch(event: &RawEvent) -> bool {
    let execstart = string_field(event, "systemd_execstart");
    if execstart.trim().is_empty() {
        return false;
    }
    !execstart_matches_process(
        &execstart,
        &string_field(event, "exe_path"),
        &string_field(event, "name"),
    ) && !execstart_matches_process(
        &execstart,
        &string_field(event, "executable"),
        &string_field(event, "process_name"),
    )
}

pub(crate) fn execstart_matches_process(
    execstart: &str,
    executable: &str,
    process_name: &str,
) -> bool {
    if executable.trim().is_empty() && process_name.trim().is_empty() {
        return true;
    }
    let executable = executable.trim();
    if !executable.is_empty() && execstart.contains(executable) {
        return true;
    }
    let executable_name = command_basename(executable);
    execstart.split_whitespace().any(|token| {
        let token_name = command_basename(token);
        (!executable_name.is_empty() && token_name == executable_name)
            || (!process_name.trim().is_empty() && token_name == process_name)
    })
}

fn command_basename(token: &str) -> &str {
    let trimmed = token.trim_matches(|ch: char| {
        ch.is_ascii_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    });
    trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed)
}

fn push_unique_sorted(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() || values.iter().any(|item| item == value) {
        return;
    }
    values.push(value.to_string());
    values.sort();
}

#[cfg(test)]
mod tests {
    use super::{execstart_matches_process, outbound_profiles_by_pid};
    use sentinel_core::RawEvent;

    #[test]
    fn outbound_profile_counts_public_connections_and_caps_address_sample() {
        let events = vec![
            outbound("42", "8.8.8.8", "443", "true"),
            outbound("42", "1.1.1.1", "3333", "true"),
            outbound("42", "9.9.9.9", "3333", "true"),
            outbound("42", "10.0.0.1", "8080", "false"),
        ];

        let profiles = outbound_profiles_by_pid(&events, 2);
        let profile = profiles.get("42").expect("profile");

        assert_eq!(profile.total, 4);
        assert_eq!(profile.public, 3);
        assert_eq!(profile.remote_ports, vec!["3333", "443", "8080"]);
        assert_eq!(profile.public_remote_addrs.len(), 2);
        assert!(profile.remote_addr_sample_truncated);
    }

    #[test]
    fn execstart_matching_uses_executable_or_process_basename() {
        assert!(execstart_matches_process(
            "/usr/sbin/nginx -g 'daemon off;'",
            "/usr/sbin/nginx",
            "nginx"
        ));
        assert!(!execstart_matches_process(
            "/usr/sbin/nginx -g 'daemon off;'",
            "/tmp/.x/kworker",
            "kworker"
        ));
    }

    fn outbound(pid: &str, addr: &str, port: &str, public: &str) -> RawEvent {
        RawEvent::new("network", "outbound_connection")
            .with_field("pid", pid)
            .with_field("remote_addr", addr)
            .with_field("remote_port", port)
            .with_field("remote_public", public)
    }
}
