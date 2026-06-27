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
export const PANEL_DICTIONARIES = {
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
} as const;
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
      "categories",
      "reason",
      "rule_id",
      "backend",
      "expires_at"
    ]
  },
  {
    "id": "attack_fingerprints",
    "labelKey": "attackFingerprints",
    "titleKey": "attackFingerprintsTitle",
    "descriptionKey": "attackFingerprintsDescription",
    "minRole": "private",
    "endpoint": "/attack-fingerprints",
    "columns": [
      "last_seen_at",
      "kind",
      "score",
      "node_count",
      "source_count",
      "seen_count",
      "conclusion",
      "rule_ids",
      "categories",
      "title"
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
