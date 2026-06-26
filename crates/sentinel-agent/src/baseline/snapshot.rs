use chrono::{DateTime, Utc};
use sentinel_core::RawEvent;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Baseline snapshot derived from collected raw host facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub files: BTreeMap<String, FileBaseline>,
    pub users: BTreeMap<String, UserBaseline>,
    pub persistence: BTreeMap<String, PersistenceBaseline>,
    pub listening_ports: BTreeSet<String>,
    #[serde(default)]
    pub listening_services: BTreeMap<String, ListenerBaseline>,
}

impl Default for BaselineSnapshot {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            files: BTreeMap::new(),
            users: BTreeMap::new(),
            persistence: BTreeMap::new(),
            listening_ports: BTreeSet::new(),
            listening_services: BTreeMap::new(),
        }
    }
}

impl BaselineSnapshot {
    /// Build a normalized baseline from raw collector events.
    pub fn from_events(events: &[RawEvent]) -> Self {
        let mut snapshot = Self::default();
        for event in events {
            match event.kind.as_str() {
                "file_snapshot" => {
                    if let (Some(path), Some(hash)) = (event.field("path"), event.field("hash")) {
                        snapshot.files.insert(
                            path.to_string(),
                            FileBaseline {
                                hash: hash.to_string(),
                                size: event.field("size").unwrap_or_default().to_string(),
                                executable: event
                                    .field("executable")
                                    .unwrap_or_default()
                                    .to_string(),
                                is_web_path: event
                                    .field("is_web_path")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_kind: event
                                    .field("semantic_kind")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_hash: event
                                    .field("semantic_hash")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_summary: event
                                    .field("semantic_summary")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_features: event
                                    .field("semantic_features")
                                    .unwrap_or_default()
                                    .to_string(),
                            },
                        );
                    }
                }
                "user_account" => {
                    if let Some(name) = event.field("name") {
                        snapshot.users.insert(
                            name.to_string(),
                            UserBaseline {
                                uid: event.field("uid").unwrap_or_default().to_string(),
                                gid: event.field("gid").unwrap_or_default().to_string(),
                                home: event.field("home").unwrap_or_default().to_string(),
                                shell: event.field("shell").unwrap_or_default().to_string(),
                            },
                        );
                    }
                }
                "persistence_entry" => {
                    if let Some(path) = event.field("path") {
                        let key = canonical_persistence_path(
                            path,
                            event.field("type").unwrap_or_default(),
                        );
                        snapshot.persistence.insert(
                            key,
                            PersistenceBaseline {
                                hash: event.field("hash").unwrap_or_default().to_string(),
                                persistence_type: event
                                    .field("type")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_kind: event
                                    .field("semantic_kind")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_hash: event
                                    .field("semantic_hash")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_summary: event
                                    .field("semantic_summary")
                                    .unwrap_or_default()
                                    .to_string(),
                                semantic_features: event
                                    .field("semantic_features")
                                    .unwrap_or_default()
                                    .to_string(),
                            },
                        );
                    }
                }
                "listening_socket" => {
                    let key = listener_key(event);
                    snapshot.listening_ports.insert(key.clone());
                    snapshot
                        .listening_services
                        .insert(key, ListenerBaseline::from_event(event));
                }
                _ => {}
            }
        }
        snapshot
    }
}

fn canonical_persistence_path(path: &str, persistence_type: &str) -> String {
    if !persistence_type.eq_ignore_ascii_case("systemd") {
        return path.to_string();
    }
    canonical_systemd_unit_path(path)
}

fn canonical_systemd_unit_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    for prefix in ["/lib/systemd/system/", "/usr/lib/systemd/system/"] {
        if let Some(rest) = normalized.strip_prefix(prefix) {
            return format!("/usr/lib/systemd/system/{rest}");
        }
    }
    normalized
}

pub fn listener_key(event: &RawEvent) -> String {
    format!(
        "{}:{}:{}",
        event.field("protocol").unwrap_or_default(),
        event.field("local_addr").unwrap_or_default(),
        event.field("local_port").unwrap_or_default()
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileBaseline {
    pub hash: String,
    pub size: String,
    pub executable: String,
    pub is_web_path: String,
    #[serde(default)]
    pub semantic_kind: String,
    #[serde(default)]
    pub semantic_hash: String,
    #[serde(default)]
    pub semantic_summary: String,
    #[serde(default)]
    pub semantic_features: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserBaseline {
    pub uid: String,
    pub gid: String,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceBaseline {
    pub hash: String,
    pub persistence_type: String,
    #[serde(default)]
    pub semantic_kind: String,
    #[serde(default)]
    pub semantic_hash: String,
    #[serde(default)]
    pub semantic_summary: String,
    #[serde(default)]
    pub semantic_features: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerBaseline {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: String,
    pub process_name: String,
    pub executable: String,
    #[serde(default)]
    pub cmdline: String,
    #[serde(default)]
    pub systemd_unit: String,
    #[serde(default)]
    pub container_context: String,
    #[serde(default)]
    pub container_id: String,
    #[serde(default)]
    pub container_cgroup: String,
    #[serde(default)]
    pub exe_hash_blake3: String,
}

impl ListenerBaseline {
    fn from_event(event: &RawEvent) -> Self {
        Self {
            protocol: event.field("protocol").unwrap_or_default().to_string(),
            local_addr: event.field("local_addr").unwrap_or_default().to_string(),
            local_port: event.field("local_port").unwrap_or_default().to_string(),
            process_name: event.field("process_name").unwrap_or_default().to_string(),
            executable: event.field("executable").unwrap_or_default().to_string(),
            cmdline: event.field("cmdline").unwrap_or_default().to_string(),
            systemd_unit: event.field("systemd_unit").unwrap_or_default().to_string(),
            container_context: event
                .field("container_context")
                .unwrap_or_default()
                .to_string(),
            container_id: event.field("container_id").unwrap_or_default().to_string(),
            container_cgroup: event
                .field("container_cgroup")
                .unwrap_or_default()
                .to_string(),
            exe_hash_blake3: event
                .field("exe_hash_blake3")
                .unwrap_or_default()
                .to_string(),
        }
    }

    pub fn has_owner(&self) -> bool {
        !self.process_name.is_empty() || !self.executable.is_empty()
    }

    pub fn owner_changed(&self, other: &Self) -> bool {
        self.has_owner()
            && other.has_owner()
            && (self.process_name != other.process_name || self.executable != other.executable)
    }
}

#[cfg(test)]
mod tests {
    use super::BaselineSnapshot;
    use sentinel_core::RawEvent;

    #[test]
    fn builds_snapshot_from_file_and_user_events() {
        let events = vec![
            RawEvent::new("file", "file_snapshot")
                .with_field("path", "/etc/passwd")
                .with_field("hash", "abc")
                .with_field("size", "12"),
            RawEvent::new("users", "user_account")
                .with_field("name", "root")
                .with_field("uid", "0"),
        ];
        let snapshot = BaselineSnapshot::from_events(&events);
        assert!(snapshot.files.contains_key("/etc/passwd"));
        assert!(snapshot.users.contains_key("root"));
    }

    #[test]
    fn builds_listener_service_baseline() {
        let event = RawEvent::new("network", "listening_socket")
            .with_field("protocol", "tcp")
            .with_field("local_addr", "0.0.0.0")
            .with_field("local_port", "443")
            .with_field("process_name", "nginx")
            .with_field("executable", "/usr/sbin/nginx")
            .with_field("systemd_unit", "nginx.service")
            .with_field("exe_hash_blake3", "abc123");
        let snapshot = BaselineSnapshot::from_events(&[event]);
        let service = snapshot.listening_services.get("tcp:0.0.0.0:443");
        assert!(service.is_some());
        assert_eq!(
            service.map(|item| item.process_name.as_str()),
            Some("nginx")
        );
        assert_eq!(
            service.map(|item| item.systemd_unit.as_str()),
            Some("nginx.service")
        );
    }

    #[test]
    fn canonicalizes_equivalent_systemd_unit_paths() {
        let snapshot = BaselineSnapshot::from_events(&[
            RawEvent::new("persistence", "persistence_entry")
                .with_field("path", "/lib/systemd/system/sing-box.service")
                .with_field("type", "systemd")
                .with_field("hash", "abc"),
            RawEvent::new("persistence", "persistence_entry")
                .with_field("path", "/usr/lib/systemd/system/sing-box.service")
                .with_field("type", "systemd")
                .with_field("hash", "abc"),
        ]);

        assert_eq!(snapshot.persistence.len(), 1);
        assert!(snapshot
            .persistence
            .contains_key("/usr/lib/systemd/system/sing-box.service"));
    }
}
