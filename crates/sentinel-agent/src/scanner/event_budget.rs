use sentinel_core::{RawEvent, SentinelConfig};
use std::cmp::Reverse;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct RawEventBudgetReport {
    pub dropped_events: usize,
}

pub(super) fn apply_raw_event_budget(
    events: &mut Vec<RawEvent>,
    config: &SentinelConfig,
) -> RawEventBudgetReport {
    if !config.resource_budget.enabled {
        return RawEventBudgetReport::default();
    }
    let limit = config.resource_budget.max_raw_events_per_scan;
    if limit == 0 || events.len() <= limit {
        return RawEventBudgetReport::default();
    }
    events.sort_by_key(|event| {
        (
            Reverse(raw_event_priority(event)),
            Reverse(event.timestamp.timestamp_millis()),
            event.source.clone(),
            event.kind.clone(),
            event.id.clone(),
        )
    });
    let dropped_events = events.len() - limit;
    events.truncate(limit);
    RawEventBudgetReport { dropped_events }
}

fn raw_event_priority(event: &RawEvent) -> u8 {
    match event.kind.as_str() {
        "ssh_auth" | "ssh_auth_aggregate" => 100,
        "user_created" | "user_modified" | "user_uid_changed_to_zero" => 95,
        "persistence_created" | "persistence_modified" | "persistence_item" => 90,
        "file_snapshot" | "file_created" | "file_modified" | "file_deleted" => {
            sensitive_path_priority(event).max(75)
        }
        "process_exec" | "process_snapshot" => 70,
        "gpu_compute_process" => 68,
        "listening_socket" | "listening_socket_owner_changed" => 65,
        "log_file_snapshot" | "log_file_truncated" => 62,
        "audit_exec" | "audit_network_exec" | "ebpf_exec" => 60,
        "web_access" if event.field("probe_family").is_some() => 55,
        "web_access" => 25,
        "outbound_connection" => 20,
        _ => 40,
    }
}

fn sensitive_path_priority(event: &RawEvent) -> u8 {
    let path = event.field("path").unwrap_or_default();
    if path.contains("/.ssh/authorized_keys")
        || path == "/etc/passwd"
        || path == "/etc/shadow"
        || path.starts_with("/etc/sudoers")
        || path.contains("ld.so.preload")
    {
        98
    } else if path.starts_with("/etc/systemd/")
        || path.starts_with("/etc/cron")
        || path.starts_with("/var/spool/cron")
    {
        88
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::apply_raw_event_budget;
    use sentinel_core::{RawEvent, SentinelConfig};

    #[test]
    fn raw_event_budget_keeps_security_events_before_noisy_web_rows() {
        let mut config = SentinelConfig::default();
        config.resource_budget.max_raw_events_per_scan = 2;
        let mut events = vec![
            RawEvent::new("web", "web_access").with_field("path", "/"),
            RawEvent::new("network", "outbound_connection").with_field("pid", "1"),
            RawEvent::new("ssh", "ssh_auth")
                .with_field("outcome", "failure")
                .with_field("source_ip", "8.8.8.8"),
            RawEvent::new("file", "file_snapshot").with_field("path", "/root/.ssh/authorized_keys"),
        ];

        let report = apply_raw_event_budget(&mut events, &config);

        assert_eq!(report.dropped_events, 2);
        assert!(events.iter().any(|event| event.kind == "ssh_auth"));
        let retained_authorized_keys = events
            .iter()
            .any(|event| event.field("path") == Some("/root/.ssh/authorized_keys"));
        assert!(retained_authorized_keys);
    }
}
