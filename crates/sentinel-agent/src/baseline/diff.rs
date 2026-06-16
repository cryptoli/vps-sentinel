use crate::baseline::snapshot::BaselineSnapshot;
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
            Some(old) if old.hash != now.hash => events.push(
                RawEvent::new("baseline", "file_modified")
                    .with_field("path", path)
                    .with_field("previous_hash", &old.hash)
                    .with_field("current_hash", &now.hash)
                    .with_field("size", &now.size),
            ),
            None => events.push(
                RawEvent::new("baseline", "file_created")
                    .with_field("path", path)
                    .with_field("previous_hash", "")
                    .with_field("current_hash", &now.hash)
                    .with_field("size", &now.size),
            ),
            _ => {}
        }
    }
    for (path, old) in &previous.files {
        if !current.files.contains_key(path) {
            events.push(
                RawEvent::new("baseline", "file_deleted")
                    .with_field("path", path)
                    .with_field("previous_hash", &old.hash)
                    .with_field("current_hash", ""),
            );
        }
    }
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
            Some(old) if old.hash != now.hash => events.push(
                RawEvent::new("baseline", "persistence_modified")
                    .with_field("path", path)
                    .with_field("type", &now.persistence_type)
                    .with_field("previous_hash", &old.hash)
                    .with_field("current_hash", &now.hash),
            ),
            None => events.push(
                RawEvent::new("baseline", "persistence_created")
                    .with_field("path", path)
                    .with_field("type", &now.persistence_type)
                    .with_field("previous_hash", "")
                    .with_field("current_hash", &now.hash),
            ),
            _ => {}
        }
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
        let parts = key.split(':').collect::<Vec<_>>();
        if parts.len() < 3 {
            continue;
        }
        events.push(
            RawEvent::new("baseline", "listening_socket")
                .with_field("protocol", parts[0])
                .with_field("local_addr", parts[1])
                .with_field("local_port", parts[2]),
        );
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
            .with_field("hash", "old")]);
        let new = BaselineSnapshot::from_events(&[RawEvent::new("file", "file_snapshot")
            .with_field("path", "/home/app/.ssh/authorized_keys")
            .with_field("hash", "new")]);
        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].kind, "file_modified");
    }
}
