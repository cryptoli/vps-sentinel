use crate::baseline::diff_snapshots;
use crate::baseline::snapshot::{listener_key, BaselineSnapshot};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use sentinel_core::RawEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const BASELINE_APPROVAL_STATE_ID: &str = "baseline_approvals";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineApprovalItem {
    pub key: String,
    pub kind: String,
    pub subject: String,
    pub action: String,
    pub risk_hint: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineApproval {
    pub key: String,
    pub kind: String,
    pub subject: String,
    pub approved_at: DateTime<Utc>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineApprovalState {
    pub approvals: BTreeMap<String, BaselineApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRefreshReport {
    pub snapshot_id: String,
    pub approved_changes: usize,
    pub remaining_changes: usize,
}

pub fn approval_items(
    previous: &BaselineSnapshot,
    current: &BaselineSnapshot,
) -> Vec<BaselineApprovalItem> {
    diff_snapshots(previous, current)
        .into_iter()
        .map(|event| approval_item_from_event(&event))
        .collect()
}

pub fn approve_keys(
    state: &mut BaselineApprovalState,
    items: &[BaselineApprovalItem],
    requested_keys: &[String],
    note: Option<String>,
) -> Vec<String> {
    let available = items
        .iter()
        .map(|item| (item.key.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let keys = if requested_keys.iter().any(|key| key == "all") {
        available.keys().map(|key| (*key).to_string()).collect()
    } else {
        requested_keys.to_vec()
    };

    let mut approved = Vec::new();
    for key in keys {
        let Some(item) = available.get(key.as_str()) else {
            continue;
        };
        state.approvals.insert(
            key.clone(),
            BaselineApproval {
                key: key.clone(),
                kind: item.kind.clone(),
                subject: item.subject.clone(),
                approved_at: Utc::now(),
                note: note.clone().filter(|value| !value.trim().is_empty()),
            },
        );
        approved.push(key);
    }
    approved
}

pub fn apply_approved_changes(
    previous: &BaselineSnapshot,
    current: &BaselineSnapshot,
    state: &mut BaselineApprovalState,
) -> (BaselineSnapshot, BaselineRefreshReport) {
    let mut next = previous.clone();
    next.id = Uuid::new_v4().to_string();
    next.created_at = Utc::now();

    let mut applied_keys = BTreeSet::new();
    for event in diff_snapshots(previous, current) {
        let item = approval_item_from_event(&event);
        if !state.approvals.contains_key(&item.key) {
            continue;
        }
        if apply_event_to_snapshot(&mut next, current, &event) {
            applied_keys.insert(item.key);
        }
    }

    for key in &applied_keys {
        state.approvals.remove(key);
    }
    let remaining_changes = approval_items(&next, current).len();
    let report = BaselineRefreshReport {
        snapshot_id: next.id.clone(),
        approved_changes: applied_keys.len(),
        remaining_changes,
    };
    (next, report)
}

fn approval_item_from_event(event: &RawEvent) -> BaselineApprovalItem {
    let subject = event_subject(event);
    BaselineApprovalItem {
        key: approval_key(event, &subject),
        kind: event.kind.clone(),
        subject: subject.clone(),
        action: event_action(event.kind.as_str()).to_string(),
        risk_hint: risk_hint(event, &subject).to_string(),
        fields: event.fields.clone(),
    }
}

fn approval_key(event: &RawEvent, subject: &str) -> String {
    let stable_fields = stable_key_fields(event);
    let mut hasher = Hasher::new();
    hasher.update(event.kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(subject.as_bytes());
    hasher.update(b"\n");
    for (key, value) in stable_fields {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().to_hex().to_string()[..16].to_string()
}

fn stable_key_fields(event: &RawEvent) -> BTreeMap<&str, &str> {
    let mut fields = BTreeMap::new();
    for key in [
        "current_hash",
        "uid",
        "gid",
        "home",
        "shell",
        "type",
        "protocol",
        "local_addr",
        "local_port",
        "process_name",
        "executable",
    ] {
        if let Some(value) = event.field(key) {
            fields.insert(key, value);
        }
    }
    fields
}

fn event_subject(event: &RawEvent) -> String {
    for key in ["path", "name", "local_port"] {
        if let Some(value) = event.field(key).filter(|value| !value.trim().is_empty()) {
            if key == "local_port" {
                return listener_key(event);
            }
            return value.to_string();
        }
    }
    event.kind.clone()
}

fn event_action(kind: &str) -> &'static str {
    match kind {
        "file_created" | "file_modified" => "update_file_baseline",
        "file_deleted" => "remove_file_from_baseline",
        "user_created" | "user_modified" | "user_uid_changed_to_zero" => "update_user_baseline",
        "persistence_created" | "persistence_modified" => "update_persistence_baseline",
        "listening_socket" | "listening_socket_owner_changed" => "update_listener_baseline",
        _ => "update_baseline",
    }
}

fn risk_hint(event: &RawEvent, subject: &str) -> &'static str {
    if subject.ends_with("/authorized_keys") || subject.ends_with("/authorized_keys2") {
        return "ssh_authorized_keys";
    }
    match event.kind.as_str() {
        "user_uid_changed_to_zero" => "privileged_user_change",
        "persistence_created" | "persistence_modified" => "persistence_change",
        "listening_socket" | "listening_socket_owner_changed" => "network_exposure_change",
        "file_created" | "file_modified" | "file_deleted" => "file_integrity_change",
        _ => "baseline_change",
    }
}

fn apply_event_to_snapshot(
    next: &mut BaselineSnapshot,
    current: &BaselineSnapshot,
    event: &RawEvent,
) -> bool {
    match event.kind.as_str() {
        "file_created" | "file_modified" => event
            .field("path")
            .and_then(|path| current.files.get(path).map(|item| (path, item)))
            .map(|(path, item)| next.files.insert(path.to_string(), item.clone()))
            .is_some(),
        "file_deleted" => event
            .field("path")
            .map(|path| next.files.remove(path).is_some())
            .unwrap_or(false),
        "user_created" | "user_modified" | "user_uid_changed_to_zero" => event
            .field("name")
            .and_then(|name| current.users.get(name).map(|item| (name, item)))
            .map(|(name, item)| next.users.insert(name.to_string(), item.clone()))
            .is_some(),
        "persistence_created" | "persistence_modified" => event
            .field("path")
            .and_then(|path| current.persistence.get(path).map(|item| (path, item)))
            .map(|(path, item)| next.persistence.insert(path.to_string(), item.clone()))
            .is_some(),
        "listening_socket" | "listening_socket_owner_changed" => {
            let key = listener_key(event);
            if !current.listening_ports.contains(&key) {
                return false;
            }
            next.listening_ports.insert(key.clone());
            if let Some(service) = current.listening_services.get(&key) {
                next.listening_services.insert(key, service.clone());
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_approved_changes, approval_items, approve_keys, BaselineApprovalState};
    use crate::baseline::snapshot::BaselineSnapshot;
    use sentinel_core::RawEvent;

    #[test]
    fn approval_key_is_stable_for_same_diff() {
        let old = BaselineSnapshot::from_events(&[file("/etc/passwd", "old")]);
        let new = BaselineSnapshot::from_events(&[file("/etc/passwd", "new")]);

        let left = approval_items(&old, &new);
        let right = approval_items(&old, &new);

        assert_eq!(left.len(), 1);
        assert_eq!(left[0].key, right[0].key);
        assert_eq!(left[0].action, "update_file_baseline");
    }

    #[test]
    fn refresh_applies_only_approved_changes() {
        let old = BaselineSnapshot::from_events(&[
            file("/etc/passwd", "old-passwd"),
            file("/root/.ssh/authorized_keys", "old-key"),
        ]);
        let new = BaselineSnapshot::from_events(&[
            file("/etc/passwd", "new-passwd"),
            file("/root/.ssh/authorized_keys", "new-key"),
        ]);
        let items = approval_items(&old, &new);
        let passwd_key = items
            .iter()
            .find(|item| item.subject == "/etc/passwd")
            .expect("passwd diff")
            .key
            .clone();
        let mut state = BaselineApprovalState::default();
        assert_eq!(
            approve_keys(
                &mut state,
                &items,
                &[passwd_key],
                Some("package update".to_string())
            )
            .len(),
            1
        );

        let (refreshed, report) = apply_approved_changes(&old, &new, &mut state);

        assert_eq!(report.approved_changes, 1);
        assert_eq!(report.remaining_changes, 1);
        assert_eq!(
            refreshed
                .files
                .get("/etc/passwd")
                .map(|item| item.hash.as_str()),
            Some("new-passwd")
        );
        assert_eq!(
            refreshed
                .files
                .get("/root/.ssh/authorized_keys")
                .map(|item| item.hash.as_str()),
            Some("old-key")
        );
        assert!(state.approvals.is_empty());
    }

    fn file(path: &str, hash: &str) -> RawEvent {
        RawEvent::new("file", "file_snapshot")
            .with_field("path", path)
            .with_field("hash", hash)
            .with_field("size", "1")
    }
}
