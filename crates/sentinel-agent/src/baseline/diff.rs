use crate::baseline::semantic::semantic_delta;
use crate::baseline::snapshot::{
    BaselineSnapshot, FileBaseline, ListenerBaseline, PersistenceBaseline,
};
use sentinel_core::RawEvent;

/// Produce synthetic raw events representing baseline drift.
pub fn diff_snapshots(previous: &BaselineSnapshot, current: &BaselineSnapshot) -> Vec<RawEvent> {
    let mut events = Vec::new();
    diff_files(previous, current, &mut events);
    diff_users(previous, current, &mut events);
    diff_persistence(previous, current, &mut events);
    diff_listening_ports(previous, current, &mut events);
    events
}

fn diff_files(previous: &BaselineSnapshot, current: &BaselineSnapshot, events: &mut Vec<RawEvent>) {
    for (path, now) in &current.files {
        match previous.files.get(path) {
            Some(old) if old.hash != now.hash => {
                events.push(file_diff_event("file_modified", path, Some(old), Some(now)))
            }
            None => events.push(file_diff_event("file_created", path, None, Some(now))),
            _ => {}
        }
    }
    for (path, old) in &previous.files {
        if !current.files.contains_key(path) {
            events.push(file_diff_event("file_deleted", path, Some(old), None));
        }
    }
}

fn file_diff_event(
    kind: &str,
    path: &str,
    previous: Option<&FileBaseline>,
    current: Option<&FileBaseline>,
) -> RawEvent {
    let mut event = RawEvent::new("baseline", kind).with_field("path", path);
    if let Some(previous) = previous {
        event = event
            .with_field("previous_hash", &previous.hash)
            .with_field("previous_size", &previous.size)
            .with_field("previous_executable", &previous.executable)
            .with_field("previous_is_web_path", &previous.is_web_path)
            .with_field("previous_semantic_kind", &previous.semantic_kind)
            .with_field("previous_semantic_hash", &previous.semantic_hash)
            .with_field("previous_semantic_summary", &previous.semantic_summary)
            .with_field("previous_semantic_features", &previous.semantic_features);
    } else {
        event = event.with_field("previous_hash", "");
    }
    if let Some(current) = current {
        event = event
            .with_field("current_hash", &current.hash)
            .with_field("current_size", &current.size)
            .with_field("current_executable", &current.executable)
            .with_field("current_is_web_path", &current.is_web_path)
            .with_field("semantic_kind", &current.semantic_kind)
            .with_field("semantic_hash", &current.semantic_hash)
            .with_field("semantic_summary", &current.semantic_summary)
            .with_field("semantic_features", &current.semantic_features)
            .with_field("current_semantic_kind", &current.semantic_kind)
            .with_field("current_semantic_hash", &current.semantic_hash)
            .with_field("current_semantic_summary", &current.semantic_summary)
            .with_field("current_semantic_features", &current.semantic_features)
            .with_field("size", &current.size)
            .with_field("executable", &current.executable)
            .with_field("is_web_path", &current.is_web_path);
    } else {
        event = event.with_field("current_hash", "");
    }
    attach_semantic_delta(event)
}

fn diff_users(previous: &BaselineSnapshot, current: &BaselineSnapshot, events: &mut Vec<RawEvent>) {
    for (name, now) in &current.users {
        match previous.users.get(name) {
            Some(old) if old.uid != now.uid && now.uid == "0" => events.push(
                RawEvent::new("baseline", "user_uid_changed_to_zero")
                    .with_field("name", name)
                    .with_field("previous_uid", &old.uid)
                    .with_field("uid", &now.uid),
            ),
            Some(old) if old != now => events.push(
                RawEvent::new("baseline", "user_modified")
                    .with_field("name", name)
                    .with_field("previous_uid", &old.uid)
                    .with_field("uid", &now.uid),
            ),
            None => events.push(
                RawEvent::new("baseline", "user_created")
                    .with_field("name", name)
                    .with_field("uid", &now.uid)
                    .with_field("gid", &now.gid)
                    .with_field("home", &now.home)
                    .with_field("shell", &now.shell),
            ),
            _ => {}
        }
    }
}

fn diff_persistence(
    previous: &BaselineSnapshot,
    current: &BaselineSnapshot,
    events: &mut Vec<RawEvent>,
) {
    for (path, now) in &current.persistence {
        match previous.persistence.get(path) {
            Some(old) if old.hash != now.hash => events.push(persistence_diff_event(
                "persistence_modified",
                path,
                Some(old),
                Some(now),
            )),
            None => events.push(persistence_diff_event(
                "persistence_created",
                path,
                None,
                Some(now),
            )),
            _ => {}
        }
    }
}

fn persistence_diff_event(
    kind: &str,
    path: &str,
    previous: Option<&PersistenceBaseline>,
    current: Option<&PersistenceBaseline>,
) -> RawEvent {
    let mut event = RawEvent::new("baseline", kind).with_field("path", path);
    if let Some(previous) = previous {
        event = event
            .with_field("previous_hash", &previous.hash)
            .with_field("previous_type", &previous.persistence_type)
            .with_field("previous_semantic_kind", &previous.semantic_kind)
            .with_field("previous_semantic_hash", &previous.semantic_hash)
            .with_field("previous_semantic_summary", &previous.semantic_summary)
            .with_field("previous_semantic_features", &previous.semantic_features);
    } else {
        event = event.with_field("previous_hash", "");
    }
    if let Some(current) = current {
        event = event
            .with_field("type", &current.persistence_type)
            .with_field("current_hash", &current.hash)
            .with_field("semantic_kind", &current.semantic_kind)
            .with_field("semantic_hash", &current.semantic_hash)
            .with_field("semantic_summary", &current.semantic_summary)
            .with_field("semantic_features", &current.semantic_features)
            .with_field("current_semantic_kind", &current.semantic_kind)
            .with_field("current_semantic_hash", &current.semantic_hash)
            .with_field("current_semantic_summary", &current.semantic_summary)
            .with_field("current_semantic_features", &current.semantic_features);
    } else {
        event = event.with_field("current_hash", "");
    }
    attach_semantic_delta(event)
}

fn attach_semantic_delta(event: RawEvent) -> RawEvent {
    if let Some(delta) = semantic_delta(
        event.field("previous_semantic_kind").unwrap_or_default(),
        event.field("previous_semantic_hash").unwrap_or_default(),
        event.field("previous_semantic_summary").unwrap_or_default(),
        event.field("current_semantic_kind").unwrap_or_default(),
        event.field("current_semantic_hash").unwrap_or_default(),
        event.field("current_semantic_summary").unwrap_or_default(),
    ) {
        event.with_field("semantic_delta", delta)
    } else {
        event
    }
}

fn diff_listening_ports(
    previous: &BaselineSnapshot,
    current: &BaselineSnapshot,
    events: &mut Vec<RawEvent>,
) {
    for key in current
        .listening_ports
        .difference(&previous.listening_ports)
    {
        let Some((protocol, local_addr, local_port)) = split_listener_key(key) else {
            continue;
        };
        let mut event = RawEvent::new("baseline", "listening_socket")
            .with_field("protocol", protocol)
            .with_field("local_addr", local_addr)
            .with_field("local_port", local_port);
        if let Some(service) = current.listening_services.get(key) {
            event = add_listener_owner_fields(event, service);
        }
        events.push(event);
    }

    for (key, now) in &current.listening_services {
        let Some(old) = previous.listening_services.get(key) else {
            continue;
        };
        if !old.owner_changed(now) {
            continue;
        }
        events.push(
            RawEvent::new("baseline", "listening_socket_owner_changed")
                .with_field("protocol", &now.protocol)
                .with_field("local_addr", &now.local_addr)
                .with_field("local_port", &now.local_port)
                .with_field("previous_process_name", &old.process_name)
                .with_field("previous_executable", &old.executable)
                .with_field("process_name", &now.process_name)
                .with_field("executable", &now.executable),
        );
    }
}

fn split_listener_key(key: &str) -> Option<(&str, &str, &str)> {
    let (protocol, rest) = key.split_once(':')?;
    let (local_addr, local_port) = rest.rsplit_once(':')?;
    Some((protocol, local_addr, local_port))
}

fn add_listener_owner_fields(mut event: RawEvent, service: &ListenerBaseline) -> RawEvent {
    event
        .fields
        .insert("process_name".to_string(), service.process_name.clone());
    event
        .fields
        .insert("executable".to_string(), service.executable.clone());
    add_listener_field(&mut event, "cmdline", &service.cmdline);
    add_listener_field(&mut event, "systemd_unit", &service.systemd_unit);
    add_listener_field(&mut event, "container_context", &service.container_context);
    add_listener_field(&mut event, "container_id", &service.container_id);
    add_listener_field(&mut event, "container_cgroup", &service.container_cgroup);
    add_listener_field(&mut event, "exe_hash_blake3", &service.exe_hash_blake3);
    event
}

fn add_listener_field(event: &mut RawEvent, key: &str, value: &str) {
    if !value.trim().is_empty() {
        event.fields.insert(key.to_string(), value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::diff_snapshots;
    use crate::baseline::snapshot::BaselineSnapshot;
    use sentinel_core::RawEvent;

    #[test]
    fn detects_authorized_keys_hash_change() {
        let old = BaselineSnapshot::from_events(&[RawEvent::new("file", "file_snapshot")
            .with_field("path", "/home/app/.ssh/authorized_keys")
            .with_field("hash", "old")
            .with_field("size", "64")
            .with_field("executable", "false")
            .with_field("semantic_kind", "authorized_keys")
            .with_field("semantic_hash", "semantic-old")
            .with_field("semantic_summary", "keys=1")]);
        let new = BaselineSnapshot::from_events(&[RawEvent::new("file", "file_snapshot")
            .with_field("path", "/home/app/.ssh/authorized_keys")
            .with_field("hash", "new")
            .with_field("size", "128")
            .with_field("executable", "false")
            .with_field("semantic_kind", "authorized_keys")
            .with_field("semantic_hash", "semantic-new")
            .with_field("semantic_summary", "keys=2 options=from")]);
        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, "file_modified");
        assert_eq!(diff[0].field("previous_size"), Some("64"));
        assert_eq!(diff[0].field("current_size"), Some("128"));
        assert_eq!(diff[0].field("current_executable"), Some("false"));
        assert_eq!(
            diff[0].field("semantic_delta"),
            Some("authorized_keys: keys=1 -> keys=2 options=from")
        );
    }

    #[test]
    fn detects_persistence_semantic_delta() {
        let old =
            BaselineSnapshot::from_events(&[RawEvent::new("persistence", "persistence_entry")
                .with_field("path", "/etc/systemd/system/app.service")
                .with_field("type", "systemd")
                .with_field("hash", "old")
                .with_field("semantic_kind", "systemd_unit")
                .with_field("semantic_hash", "semantic-old")
                .with_field("semantic_summary", "commands=1")]);
        let new =
            BaselineSnapshot::from_events(&[RawEvent::new("persistence", "persistence_entry")
                .with_field("path", "/etc/systemd/system/app.service")
                .with_field("type", "systemd")
                .with_field("hash", "new")
                .with_field("semantic_kind", "systemd_unit")
                .with_field("semantic_hash", "semantic-new")
                .with_field("semantic_summary", "commands=2")
                .with_field("semantic_features", "network_or_shell_command")]);

        let diff = diff_snapshots(&old, &new);

        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, "persistence_modified");
        assert_eq!(
            diff[0].field("semantic_delta"),
            Some("systemd_unit: commands=1 -> commands=2")
        );
        assert_eq!(
            diff[0].field("current_semantic_features"),
            Some("network_or_shell_command")
        );
    }

    #[test]
    fn detects_listener_owner_change() {
        let old = BaselineSnapshot::from_events(&[listener("nginx", "/usr/sbin/nginx")]);
        let new = BaselineSnapshot::from_events(&[listener("sh", "/tmp/.cache/sh")]);
        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, "listening_socket_owner_changed");
        assert_eq!(diff[0].field("previous_process_name"), Some("nginx"));
        assert_eq!(diff[0].field("process_name"), Some("sh"));
    }

    #[test]
    fn parses_ipv6_listener_key_for_new_port() {
        let old = BaselineSnapshot::default();
        let new = BaselineSnapshot::from_events(&[RawEvent::new("network", "listening_socket")
            .with_field("protocol", "tcp6")
            .with_field("local_addr", "::")
            .with_field("local_port", "443")]);
        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff[0].field("local_addr"), Some("::"));
        assert_eq!(diff[0].field("local_port"), Some("443"));
    }

    fn listener(process_name: &str, executable: &str) -> RawEvent {
        RawEvent::new("network", "listening_socket")
            .with_field("protocol", "tcp")
            .with_field("local_addr", "0.0.0.0")
            .with_field("local_port", "443")
            .with_field("process_name", process_name)
            .with_field("executable", executable)
    }
}
