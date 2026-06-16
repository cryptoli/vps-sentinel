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
                        snapshot.persistence.insert(
                            path.to_string(),
                            PersistenceBaseline {
                                hash: event.field("hash").unwrap_or_default().to_string(),
                                persistence_type: event
                                    .field("type")
                                    .unwrap_or_default()
                                    .to_string(),
                            },
                        );
                    }
                }
                "listening_socket" => {
                    let key = format!(
                        "{}:{}:{}",
                        event.field("protocol").unwrap_or_default(),
                        event.field("local_addr").unwrap_or_default(),
                        event.field("local_port").unwrap_or_default()
                    );
                    snapshot.listening_ports.insert(key);
                }
                _ => {}
            }
        }
        snapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileBaseline {
    pub hash: String,
    pub size: String,
    pub executable: String,
    pub is_web_path: String,
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
}
