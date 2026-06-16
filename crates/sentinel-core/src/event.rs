use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Raw fact collected from the host before any risk judgment is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvent {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub timestamp: DateTime<Utc>,
    pub fields: BTreeMap<String, String>,
}

impl RawEvent {
    /// Create a raw event with a generated ID and current timestamp.
    pub fn new(source: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source: source.into(),
            kind: kind.into(),
            timestamp: Utc::now(),
            fields: BTreeMap::new(),
        }
    }

    /// Attach one field.
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// Return one field as a string slice.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}
