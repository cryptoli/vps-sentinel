// This file is generated from panel/shared/contract.json.
// Run: node scripts/generate-panel-contract.mjs

use super::{PanelDataset, PanelRole};

pub(crate) const SIGNATURE_WINDOW_SECONDS: i64 = 300;
pub(crate) const DEFAULT_PAGE_LIMIT: usize = 50;
pub(crate) const MAX_PAGE_LIMIT: usize = 200;
pub(crate) const DEFAULT_FRESHNESS_THRESHOLD_MINUTES: u64 = 30;
pub(crate) const DEFAULT_OFFLINE_THRESHOLD_MINUTES: u64 = 90;
pub(crate) const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES: u64 = 720;
pub(crate) const PANEL_TRANSPORT_ENCODING: &str = "json-base64";
pub(crate) const DEFAULT_PUBLIC_PAGES: &str = "overview,probe_sources,nodes";
pub(crate) const DEFAULT_ADMIN_PATH: &str = "/panel-admin";
pub(crate) const DEFAULT_THEMES: &str = "default:Default";

const STREAM_REFRESH_DATASETS: &[&str] = &[
    "summary",
    "trends",
    "nodes",
    "findings",
    "incidents",
    "baseline_drifts",
    "active_blocks",
    "probe_sources",
    "audit_logs",
];
pub(crate) const PUBLIC_PROBE_SOURCE_HIDDEN_KEYS: &[&str] = &[
    "node_name",
    "network_prefix",
    "latest_reason",
    "block_reason",
    "first_seen",
];
const NODES_PUBLIC_COLUMNS: &[&str] =
    &["last_seen_at", "node_name", "agent_version", "metrics_json"];
const NODES_PRIVATE_COLUMNS: &[&str] = &[
    "last_seen_at",
    "node_name",
    "hostname",
    "agent_version",
    "privacy_mode",
    "storage_json",
    "metrics_json",
];

pub(crate) fn stream_refresh_datasets() -> Vec<&'static str> {
    STREAM_REFRESH_DATASETS.to_vec()
}

pub(crate) fn node_columns(role: PanelRole) -> &'static [&'static str] {
    match role {
        PanelRole::Public => NODES_PUBLIC_COLUMNS,
        PanelRole::Private => NODES_PRIVATE_COLUMNS,
    }
}

pub(crate) fn findings_dataset() -> PanelDataset {
    PanelDataset {
        table: "findings",
        order_column: "timestamp",
        active_filter: None,
        columns: &[
            "id",
            "timestamp",
            "node_id AS node_name",
            "severity",
            "rule_id",
            "category",
            "subject",
            "review_signature",
            "title",
        ],
    }
}

pub(crate) fn incidents_dataset() -> PanelDataset {
    PanelDataset {
        table: "incidents",
        order_column: "last_seen",
        active_filter: None,
        columns: &[
            "id",
            "last_seen",
            "node_id AS node_name",
            "severity",
            "score",
            "title",
            "summary",
            "review_signature",
        ],
    }
}

pub(crate) fn baseline_drifts_dataset() -> PanelDataset {
    PanelDataset {
        table: "baseline_drifts",
        order_column: "timestamp",
        active_filter: None,
        columns: &[
            "id",
            "finding_id",
            "timestamp",
            "node_id AS node_name",
            "severity",
            "rule_id",
            "category",
            "tier",
            "subject",
            "review_signature",
            "review_action",
        ],
    }
}

pub(crate) fn active_blocks_private_dataset() -> PanelDataset {
    PanelDataset {
        table: "active_blocks",
        order_column: "blocked_at",
        active_filter: Some("expired = 0"),
        columns: &["blocked_at", "node_id AS node_name", "ip", "(SELECT network_prefix FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND network_prefix IS NOT NULL AND network_prefix <> '' AND LOWER(network_prefix) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS network_prefix", "(SELECT country FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND country IS NOT NULL AND country <> '' AND LOWER(country) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS country", "(SELECT asn FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND asn IS NOT NULL AND asn <> '' AND LOWER(asn) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS asn", "(SELECT organization FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND organization IS NOT NULL AND organization <> '' AND LOWER(organization) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS organization", "rule_id", "backend", "reason", "expires_at"],
    }
}

pub(crate) fn audit_logs_dataset() -> PanelDataset {
    PanelDataset {
        table: "panel_audit_logs",
        order_column: "created_at",
        active_filter: None,
        columns: &["created_at", "action", "actor", "target_type", "target_id"],
    }
}

pub(crate) fn active_blocks_dataset(role: PanelRole) -> PanelDataset {
    match role {
        PanelRole::Public => PanelDataset {
            table: "active_blocks",
            order_column: "blocked_at",
            active_filter: Some("expired = 0"),
            columns: &["blocked_at", "node_id AS node_name"],
        },
        PanelRole::Private => active_blocks_private_dataset(),
    }
}
