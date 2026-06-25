// This file is generated from panel/shared/contract.json.
// Run: node scripts/generate-panel-contract.mjs


export const SIGNATURE_WINDOW_SECONDS = 300;
export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_PAGE_LIMIT = 200;
export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = 30;
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = 720;
export const ROLE_LEVELS = Object.freeze({ public: 0, private: 1 });
export const PANEL_TRANSPORT_ENCODING = "json-base64";
export const DEFAULT_PUBLIC_PAGES = "overview,probe_sources,nodes";
export const DEFAULT_ADMIN_PATH = "/panel-admin";
export const DEFAULT_THEMES = "default:Default";
export const PUBLIC_PROBE_SOURCE_HIDDEN_KEYS = Object.freeze([
  "node_name",
  "network_prefix",
  "latest_reason",
  "block_reason",
  "first_seen"
]
);
export const DATASETS = deepFreeze({
  "/api/v1/nodes": {
    "pageId": "nodes",
    "minRole": "public",
    "table": "nodes",
    "orderColumn": "node_name",
    "orderDirection": "ASC",
    "filterColumn": "last_seen_at",
    "columns": [
      "last_seen_at",
      "node_name",
      "agent_version",
      "privacy_mode",
      "metrics_json"
    ]
  },
  "/api/v1/findings": {
    "pageId": "findings",
    "minRole": "private",
    "table": "findings",
    "orderColumn": "timestamp",
    "columns": [
      "id",
      "timestamp",
      "node_id AS node_name",
      "severity",
      "rule_id",
      "category",
      "subject",
      "review_signature",
      "title"
    ]
  },
  "/api/v1/incidents": {
    "pageId": "incidents",
    "minRole": "private",
    "table": "incidents",
    "orderColumn": "last_seen",
    "columns": [
      "id",
      "last_seen",
      "node_id AS node_name",
      "severity",
      "score",
      "title",
      "summary",
      "review_signature"
    ]
  },
  "/api/v1/baseline-drifts": {
    "pageId": "baseline_drifts",
    "minRole": "private",
    "table": "baseline_drifts",
    "orderColumn": "timestamp",
    "columns": [
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
      "review_action"
    ]
  },
  "/api/v1/active-blocks": {
    "pageId": "active_blocks",
    "minRole": "private",
    "sensitive": true,
    "table": "active_blocks",
    "orderColumn": "blocked_at",
    "activeFilter": "expired = 0",
    "publicColumns": [
      "blocked_at",
      "node_id AS node_name"
    ],
    "columns": [
      "blocked_at",
      "node_id AS node_name",
      "ip",
      "(SELECT network_prefix FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND network_prefix IS NOT NULL AND network_prefix <> '' AND LOWER(network_prefix) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS network_prefix",
      "(SELECT country FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND country IS NOT NULL AND country <> '' AND LOWER(country) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS country",
      "(SELECT asn FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND asn IS NOT NULL AND asn <> '' AND LOWER(asn) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS asn",
      "(SELECT organization FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND organization IS NOT NULL AND organization <> '' AND LOWER(organization) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS organization",
      "rule_id",
      "backend",
      "reason",
      "expires_at"
    ]
  },
  "/api/v1/probe-sources": {
    "pageId": "probe_sources",
    "minRole": "private",
    "sensitive": true,
    "optional": true,
    "table": "probe_sources",
    "orderColumn": "last_seen",
    "columns": [
      "last_seen",
      "node_id AS node_name",
      "source_ip",
      "ip_version",
      "network_prefix",
      "seen_count",
      "block_status",
      "country",
      "asn",
      "organization",
      "categories_json",
      "rule_ids_json",
      "latest_reason",
      "block_reason"
    ]
  },
  "/api/v1/audit-logs": {
    "pageId": "audit_logs",
    "minRole": "private",
    "table": "panel_audit_logs",
    "orderColumn": "created_at",
    "columns": [
      "created_at",
      "action",
      "actor",
      "target_type",
      "target_id"
    ]
  }
}
);

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return Object.freeze(value);
}
