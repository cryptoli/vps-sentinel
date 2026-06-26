use crate::finding::Evidence;
use std::borrow::Cow;
use std::collections::BTreeMap;

pub mod keys {
    pub const SOURCE_IP: &str = "source_ip";
    pub const ACTIVE_RESPONSE_IP: &str = "active_response_ip";
    pub const ACTIVE_RESPONSE_STATUS: &str = "active_response_status";
    pub const PROXY_SOURCE_UNRESOLVED: &str = "proxy_source_unresolved";
    pub const USER: &str = "user";
    pub const USERS: &str = "users";
    pub const FAILED_USERS: &str = "failed_users";
    pub const SUCCESS_USERS: &str = "success_users";
    pub const FAILURE_COUNT: &str = "failure_count";
    pub const PROBE_FAMILY: &str = "probe_family";
    pub const PROBE_FAMILIES: &str = "probe_families";
    pub const RESPONSE_PROFILE: &str = "response_profile";
    pub const RESPONSE_PROFILES: &str = "response_profiles";
    pub const REQUEST_COUNT: &str = "request_count";
    pub const ERROR_COUNT: &str = "error_count";
    pub const METHODS: &str = "methods";
    pub const STATUSES: &str = "statuses";
    pub const SAMPLE_PATHS: &str = "sample_paths";
    pub const PATH: &str = "path";
    pub const PROCESS_NAME: &str = "process_name";
    pub const EXE_PATH: &str = "exe_path";
    pub const EXE_HASH_BLAKE3: &str = "exe_hash_blake3";
    pub const PACKAGE_OWNER: &str = "package_owner";
    pub const PARENT_NAME: &str = "parent_name";
    pub const SYSTEMD_UNIT: &str = "systemd_unit";
    pub const OUTBOUND_REMOTE_PORTS: &str = "outbound_remote_ports";
    pub const GPU_PROCESS: &str = "gpu_process";
    pub const FILE_TYPE: &str = "file_type";
    pub const ENTRY_TYPE: &str = "entry_type";
    pub const CMDLINE: &str = "cmdline";
    pub const RISK_SCORE: &str = "risk_score";
    pub const UNIFIED_RISK_SCORE: &str = "unified_risk_score";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceValueKind {
    Text,
    Boolean,
    Integer,
    IpAddress,
    List,
    Path,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceField {
    pub key: &'static str,
    pub aliases: &'static [&'static str],
    pub kind: EvidenceValueKind,
    pub stable_identity: bool,
}

const FIELDS: &[EvidenceField] = &[
    EvidenceField {
        key: keys::SOURCE_IP,
        aliases: &["ip", "remote_ip", "remote_addr", "client_ip"],
        kind: EvidenceValueKind::IpAddress,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::ACTIVE_RESPONSE_IP,
        aliases: &[],
        kind: EvidenceValueKind::IpAddress,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::PROXY_SOURCE_UNRESOLVED,
        aliases: &[],
        kind: EvidenceValueKind::Boolean,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::USER,
        aliases: &["username"],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::USERS,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::FAILED_USERS,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::SUCCESS_USERS,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::FAILURE_COUNT,
        aliases: &["failures"],
        kind: EvidenceValueKind::Integer,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::PROBE_FAMILY,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::PROBE_FAMILIES,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::RESPONSE_PROFILE,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::RESPONSE_PROFILES,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::REQUEST_COUNT,
        aliases: &["requests"],
        kind: EvidenceValueKind::Integer,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::ERROR_COUNT,
        aliases: &["errors"],
        kind: EvidenceValueKind::Integer,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::METHODS,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::STATUSES,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::SAMPLE_PATHS,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::PATH,
        aliases: &["file_path", "target_path"],
        kind: EvidenceValueKind::Path,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::PROCESS_NAME,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::EXE_PATH,
        aliases: &[],
        kind: EvidenceValueKind::Path,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::EXE_HASH_BLAKE3,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::PACKAGE_OWNER,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::PARENT_NAME,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::SYSTEMD_UNIT,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::OUTBOUND_REMOTE_PORTS,
        aliases: &[],
        kind: EvidenceValueKind::List,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::GPU_PROCESS,
        aliases: &[],
        kind: EvidenceValueKind::Boolean,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::FILE_TYPE,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::ENTRY_TYPE,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: true,
    },
    EvidenceField {
        key: keys::CMDLINE,
        aliases: &[],
        kind: EvidenceValueKind::Command,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::RISK_SCORE,
        aliases: &[],
        kind: EvidenceValueKind::Integer,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::UNIFIED_RISK_SCORE,
        aliases: &[],
        kind: EvidenceValueKind::Integer,
        stable_identity: false,
    },
    EvidenceField {
        key: keys::ACTIVE_RESPONSE_STATUS,
        aliases: &[],
        kind: EvidenceValueKind::Text,
        stable_identity: false,
    },
];

pub fn field_spec(key: &str) -> Option<&'static EvidenceField> {
    let normalized = normalize_key_text(key);
    FIELDS.iter().find(|field| {
        field.key == normalized || field.aliases.iter().any(|alias| *alias == normalized)
    })
}

pub fn canonical_key(key: &str) -> Cow<'_, str> {
    let normalized = normalize_key_text(key);
    match field_spec(&normalized) {
        Some(field) => Cow::Borrowed(field.key),
        None => Cow::Owned(normalized),
    }
}

pub fn normalize_evidence_value(key: &str, value: &str) -> String {
    let value = collapse_horizontal_space(value.trim());
    match field_spec(key).map(|field| field.kind) {
        Some(EvidenceValueKind::Boolean) => normalize_boolean(&value),
        Some(EvidenceValueKind::Integer) => normalize_integer(&value),
        Some(EvidenceValueKind::IpAddress) => value.to_ascii_lowercase(),
        Some(EvidenceValueKind::List) => normalize_list(&value),
        Some(EvidenceValueKind::Path) => normalize_path(&value),
        Some(EvidenceValueKind::Command) | Some(EvidenceValueKind::Text) | None => value,
    }
}

pub fn normalize_evidence_items(evidence: Vec<Evidence>) -> Vec<Evidence> {
    let mut normalized = Vec::<Evidence>::new();
    let mut positions = BTreeMap::<String, usize>::new();
    for item in evidence {
        let key = canonical_key(&item.key).into_owned();
        let value = normalize_evidence_value(&key, &item.value);
        if key.is_empty() || value.is_empty() {
            continue;
        }
        if let Some(index) = positions.get(&key).copied() {
            normalized[index].value = merge_value(&normalized[index].value, &value);
        } else {
            positions.insert(key.clone(), normalized.len());
            normalized.push(Evidence { key, value });
        }
    }
    normalized
}

pub fn evidence_value<'a>(evidence: &'a [Evidence], key: &str) -> Option<&'a str> {
    let wanted = canonical_key(key);
    evidence
        .iter()
        .find(|item| canonical_key(&item.key) == wanted)
        .map(|item| item.value.trim())
        .filter(|value| !value.is_empty())
}

pub fn evidence_values(evidence: &[Evidence], key: &str) -> Vec<String> {
    evidence_value(evidence, key)
        .map(split_list)
        .unwrap_or_default()
}

pub fn upsert_evidence(evidence: &mut Vec<Evidence>, key: &str, value: impl Into<String>) {
    let key = canonical_key(key).into_owned();
    let value = normalize_evidence_value(&key, &value.into());
    if value.is_empty() {
        return;
    }
    if let Some(existing) = evidence
        .iter_mut()
        .find(|item| canonical_key(&item.key) == key.as_str())
    {
        existing.key = key;
        existing.value = value;
        return;
    }
    evidence.push(Evidence { key, value });
}

pub fn stable_evidence_keys(evidence: &[Evidence]) -> Vec<String> {
    evidence
        .iter()
        .filter_map(|item| {
            field_spec(&item.key)
                .filter(|field| field.stable_identity)
                .map(|field| field.key.to_string())
        })
        .collect()
}

fn normalize_key_text(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('-', "_")
}

fn collapse_horizontal_space(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_space = false;
    for ch in value.chars() {
        if ch.is_whitespace() && ch != '\n' {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(ch);
            in_space = false;
        }
    }
    out
}

fn normalize_boolean(value: &str) -> String {
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" => "true".to_string(),
        "0" | "no" | "n" | "false" => "false".to_string(),
        _ => value.to_ascii_lowercase(),
    }
}

fn normalize_integer(value: &str) -> String {
    value
        .parse::<u64>()
        .map(|number| number.to_string())
        .unwrap_or_else(|_| value.to_string())
}

fn normalize_path(value: &str) -> String {
    let mut path = value.replace('\\', "/");
    while path.contains("//") {
        path = path.replace("//", "/");
    }
    path
}

fn normalize_list(value: &str) -> String {
    split_list(value).join(", ")
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn merge_value(existing: &str, value: &str) -> String {
    if existing == value {
        return existing.to_string();
    }
    let mut values = split_list(existing);
    values.extend(split_list(value));
    values.sort();
    values.dedup();
    values.join(", ")
}

#[cfg(test)]
mod tests {
    use super::{evidence_value, normalize_evidence_items, Evidence};

    #[test]
    fn canonicalizes_source_ip_aliases() {
        let evidence = normalize_evidence_items(vec![Evidence::new("ip", " 8.8.8.8 ")]);

        assert_eq!(evidence[0].key, "source_ip");
        assert_eq!(evidence_value(&evidence, "remote_addr"), Some("8.8.8.8"));
    }

    #[test]
    fn normalizes_list_values_deterministically() {
        let evidence = normalize_evidence_items(vec![Evidence::new("users", "root, admin, root")]);

        assert_eq!(evidence_value(&evidence, "users"), Some("admin, root"));
    }
}
