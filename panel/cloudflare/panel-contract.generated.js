// This file is generated from panel/shared/contract.json.
// Run: node scripts/generate-panel-contract.mjs


export const SIGNATURE_WINDOW_SECONDS = 300;
export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_PAGE_LIMIT = 200;
export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = 30;
export const DEFAULT_OFFLINE_THRESHOLD_MINUTES = 90;
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = 720;
export const ROLE_LEVELS = Object.freeze({ public: 0, private: 1 });
export const PANEL_TRANSPORT_ENCODING = "json-base64";
export const DEFAULT_PUBLIC_PAGES = "overview,probe_sources,nodes";
export const DEFAULT_ADMIN_PATH = "/panel-admin";
export const DEFAULT_THEMES = "default:Default";
export const PANEL_DICTIONARIES = deepFreeze({
  "severities": [
    {
      "value": "critical",
      "labelKey": "critical",
      "tone": "red",
      "rank": 100
    },
    {
      "value": "high",
      "labelKey": "high",
      "tone": "orange",
      "rank": 80
    },
    {
      "value": "medium",
      "labelKey": "medium",
      "tone": "amber",
      "rank": 50
    },
    {
      "value": "low",
      "labelKey": "low",
      "tone": "green",
      "rank": 20
    }
  ],
  "reviewVerdicts": [
    {
      "value": "needs_review",
      "labelKey": "needs_review",
      "tone": "orange",
      "rank": 10
    },
    {
      "value": "confirmed",
      "labelKey": "confirmed",
      "tone": "green",
      "rank": 20
    },
    {
      "value": "false_positive",
      "labelKey": "false_positive",
      "tone": "blue",
      "rank": 30
    }
  ],
  "nodeStatusFilters": [
    {
      "value": "all",
      "labelKey": "allNodes",
      "tone": "neutral",
      "rank": 0
    },
    {
      "value": "fresh",
      "labelKey": "online",
      "tone": "green",
      "rank": 10
    },
    {
      "value": "stale",
      "labelKey": "stale",
      "tone": "amber",
      "rank": 20
    },
    {
      "value": "offline",
      "labelKey": "offline",
      "tone": "orange",
      "rank": 30
    },
    {
      "value": "retired",
      "labelKey": "retired",
      "tone": "gray",
      "rank": 40
    }
  ],
  "baselineReviewFilters": [
    {
      "value": "",
      "labels": {
        "zh": "全部",
        "en": "All"
      },
      "tone": "neutral",
      "rank": 0
    },
    {
      "value": "suspicious",
      "labelKey": "suspicious",
      "tone": "orange",
      "rank": 10
    },
    {
      "value": "needs_confirmation",
      "labelKey": "needs_confirmation",
      "tone": "blue",
      "rank": 20
    },
    {
      "value": "expected",
      "labelKey": "expected",
      "tone": "green",
      "rank": 30
    }
  ],
  "actionKinds": [
    {
      "value": "unblock",
      "labelKey": "unblock",
      "tone": "green",
      "rank": 10
    },
    {
      "value": "refresh_baseline",
      "labelKey": "refresh_baseline",
      "tone": "blue",
      "rank": 20
    },
    {
      "value": "allowlist",
      "labelKey": "allowlist",
      "tone": "orange",
      "rank": 30
    }
  ],
  "actionTargetTypes": [
    {
      "value": "active_block",
      "labelKey": "blocks",
      "tone": "blue",
      "rank": 10
    },
    {
      "value": "probe_source",
      "labelKey": "blacklist",
      "tone": "orange",
      "rank": 20
    },
    {
      "value": "baseline_drift",
      "labelKey": "drifts",
      "tone": "green",
      "rank": 30
    },
    {
      "value": "finding",
      "labelKey": "findings",
      "tone": "red",
      "rank": 40
    },
    {
      "value": "incident",
      "labelKey": "incidents",
      "tone": "red",
      "rank": 50
    }
  ]
}
);
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
    "publicSearchColumns": [
      "node_name",
      "agent_version"
    ],
    "searchColumns": [
      "node_name",
      "hostname",
      "agent_version",
      "privacy_mode"
    ],
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
    "searchColumns": [
      "node_id",
      "severity",
      "rule_id",
      "category",
      "confidence",
      "subject",
      "title"
    ],
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
    "searchColumns": [
      "node_id",
      "severity",
      "title",
      "summary"
    ],
    "columns": [
      "id",
      "last_seen",
      "node_id AS node_name",
      "severity",
      "score",
      "title",
      "summary",
      "review_signature",
      "payload_json"
    ]
  },
  "/api/v1/baseline-drifts": {
    "pageId": "baseline_drifts",
    "minRole": "private",
    "table": "baseline_drifts",
    "orderColumn": "timestamp",
    "searchColumns": [
      "node_id",
      "severity",
      "rule_id",
      "category",
      "tier",
      "subject",
      "review_action"
    ],
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
    "publicSearchColumns": [
      "node_id",
      "rule_id"
    ],
    "searchColumns": [
      "node_id",
      "ip",
      "rule_id",
      "backend",
      "reason"
    ],
    "publicColumns": [
      "blocked_at",
      "node_id AS node_name"
    ],
    "columns": [
      "id",
      "blocked_at",
      "node_id AS node_name",
      "ip",
      "(SELECT network_prefix FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND network_prefix IS NOT NULL AND network_prefix <> '' AND LOWER(network_prefix) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS network_prefix",
      "(SELECT country FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND country IS NOT NULL AND country <> '' AND LOWER(country) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS country",
      "(SELECT asn FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND asn IS NOT NULL AND asn <> '' AND LOWER(asn) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS asn",
      "(SELECT organization FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND organization IS NOT NULL AND organization <> '' AND LOWER(organization) <> 'unknown' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS organization",
      "(SELECT categories_json FROM probe_sources WHERE probe_sources.source_ip = active_blocks.ip AND categories_json IS NOT NULL AND categories_json <> '' AND categories_json <> '[]' ORDER BY probe_sources.last_seen DESC LIMIT 1) AS categories_json",
      "rule_id",
      "backend",
      "reason",
      "expires_at"
    ]
  },
  "/api/v1/attack-fingerprints": {
    "pageId": "attack_fingerprints",
    "minRole": "private",
    "table": "attack_fingerprints",
    "orderColumn": "last_seen_at",
    "searchColumns": [
      "id",
      "kind",
      "title",
      "verdict",
      "summary",
      "nodes_json",
      "source_ips_json",
      "rule_ids_json",
      "categories_json"
    ],
    "columns": [
      "id",
      "last_seen_at",
      "first_seen_at",
      "kind",
      "title",
      "seen_count",
      "node_count",
      "source_count",
      "rule_ids_json",
      "categories_json",
      "score",
      "confidence",
      "verdict",
      "summary"
    ]
  },
  "/api/v1/probe-sources": {
    "pageId": "probe_sources",
    "minRole": "private",
    "sensitive": true,
    "optional": true,
    "table": "probe_sources",
    "orderColumn": "last_seen",
    "publicSearchColumns": [
      "source_ip",
      "block_status",
      "country",
      "asn",
      "organization",
      "categories_json",
      "rule_ids_json"
    ],
    "searchColumns": [
      "node_id",
      "source_ip",
      "network_prefix",
      "block_status",
      "country",
      "asn",
      "organization",
      "categories_json",
      "rule_ids_json",
      "latest_reason",
      "block_reason"
    ],
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
    "searchColumns": [
      "action",
      "actor",
      "target_type",
      "target_id",
      "detail_json"
    ],
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
