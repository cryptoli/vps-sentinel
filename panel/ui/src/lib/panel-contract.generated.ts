// This file is generated from panel/shared/contract.json.
// Run: node scripts/generate-panel-contract.mjs


import type { PageConfig } from "@/types";

export const ROLE_LEVELS = {
  public: 0,
  private: 1,
} as const;

export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = 30;
export const DEFAULT_OFFLINE_THRESHOLD_MINUTES = 90;
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = 720;
export const PAGES = [
  {
    "id": "overview",
    "labelKey": "overview",
    "titleKey": "overviewTitle",
    "descriptionKey": "overviewDescription",
    "minRole": "public"
  },
  {
    "id": "findings",
    "labelKey": "findings",
    "titleKey": "findingsTitle",
    "descriptionKey": "findingsDescription",
    "minRole": "private",
    "endpoint": "/findings",
    "columns": [
      "timestamp",
      "node_name",
      "severity",
      "rule_id",
      "category",
      "review_verdict",
      "subject",
      "title"
    ]
  },
  {
    "id": "incidents",
    "labelKey": "incidents",
    "titleKey": "incidentsTitle",
    "descriptionKey": "incidentsDescription",
    "minRole": "private",
    "endpoint": "/incidents",
    "columns": [
      "last_seen",
      "node_name",
      "severity",
      "score",
      "review_verdict",
      "title",
      "summary"
    ]
  },
  {
    "id": "baseline_drifts",
    "labelKey": "drifts",
    "titleKey": "driftsTitle",
    "descriptionKey": "driftsDescription",
    "minRole": "private",
    "endpoint": "/baseline-drifts",
    "columns": [
      "timestamp",
      "node_name",
      "severity",
      "rule_id",
      "tier",
      "review_verdict",
      "subject",
      "review_action"
    ]
  },
  {
    "id": "active_blocks",
    "labelKey": "blocks",
    "titleKey": "blocksTitle",
    "descriptionKey": "blocksDescription",
    "minRole": "private",
    "endpoint": "/active-blocks",
    "columns": [
      "blocked_at",
      "node_name",
      "rule_id",
      "reason",
      "expires_at"
    ],
    "privateColumns": [
      "blocked_at",
      "node_name",
      "ip",
      "country",
      "asn",
      "organization",
      "reason",
      "rule_id",
      "backend",
      "expires_at"
    ]
  },
  {
    "id": "probe_sources",
    "labelKey": "blacklist",
    "titleKey": "blacklistTitle",
    "descriptionKey": "blacklistDescription",
    "minRole": "private",
    "endpoint": "/probe-sources",
    "columns": [
      "last_seen",
      "source_ip",
      "seen_count",
      "block_status",
      "country",
      "asn",
      "organization",
      "categories",
      "rule_ids"
    ],
    "privateColumns": [
      "last_seen",
      "node_name",
      "source_ip",
      "seen_count",
      "block_status",
      "country",
      "asn",
      "organization",
      "categories",
      "rule_ids",
      "latest_reason",
      "block_reason"
    ]
  },
  {
    "id": "audit_logs",
    "labelKey": "auditLogs",
    "titleKey": "auditLogsTitle",
    "descriptionKey": "auditLogsDescription",
    "minRole": "private",
    "endpoint": "/audit-logs",
    "columns": [
      "created_at",
      "action",
      "actor",
      "target_type",
      "target_id"
    ]
  },
  {
    "id": "nodes",
    "labelKey": "nodes",
    "titleKey": "nodesTitle",
    "descriptionKey": "nodesDescription",
    "minRole": "public",
    "endpoint": "/nodes",
    "columns": [
      "last_seen_at",
      "node_name",
      "agent_version"
    ],
    "privateColumns": [
      "last_seen_at",
      "node_name",
      "hostname",
      "agent_version",
      "privacy_mode"
    ]
  }
] satisfies PageConfig[];
