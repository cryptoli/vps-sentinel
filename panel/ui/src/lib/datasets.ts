import type { PageConfig, PageId } from "@/types";

export const ROLE_LEVELS = {
  public: 0,
  operator: 1,
  admin: 2,
} as const;

export const DEFAULT_LIMIT = 25;
export const OVERVIEW_LIMIT = 12;
export const API_BASE = "/api/v1";
export const TOKEN_STORAGE_KEY = "vps-sentinel-panel-token";
export const STREAM_RECONNECT_MS = 5000;
export const TIME_PRESETS = ["1h", "6h", "24h", "today", "7d"] as const;
export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = 30;
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = 720;

export const PAGES: PageConfig[] = [
  {
    id: "overview",
    labelKey: "overview",
    titleKey: "overviewTitle",
    descriptionKey: "overviewDescription",
    minRole: "public",
  },
  {
    id: "findings",
    labelKey: "findings",
    titleKey: "findingsTitle",
    descriptionKey: "findingsDescription",
    minRole: "operator",
    endpoint: "/findings",
    columns: ["timestamp", "node_name", "severity", "rule_id", "category", "review_verdict", "subject", "title"],
  },
  {
    id: "incidents",
    labelKey: "incidents",
    titleKey: "incidentsTitle",
    descriptionKey: "incidentsDescription",
    minRole: "operator",
    endpoint: "/incidents",
    columns: ["last_seen", "node_name", "severity", "score", "review_verdict", "title", "summary"],
  },
  {
    id: "baseline_drifts",
    labelKey: "drifts",
    titleKey: "driftsTitle",
    descriptionKey: "driftsDescription",
    minRole: "operator",
    endpoint: "/baseline-drifts",
    columns: ["timestamp", "node_name", "severity", "rule_id", "tier", "review_verdict", "subject", "review_action"],
  },
  {
    id: "active_blocks",
    labelKey: "blocks",
    titleKey: "blocksTitle",
    descriptionKey: "blocksDescription",
    minRole: "operator",
    endpoint: "/active-blocks",
    columns: ["blocked_at", "node_name", "rule_id", "reason", "expires_at"],
    adminColumns: ["blocked_at", "node_name", "ip", "country", "asn", "organization", "reason", "rule_id", "backend", "expires_at"],
  },
  {
    id: "probe_sources",
    labelKey: "blacklist",
    titleKey: "blacklistTitle",
    descriptionKey: "blacklistDescription",
    minRole: "admin",
    endpoint: "/probe-sources",
    columns: [
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
      "block_reason",
    ],
  },
  {
    id: "audit_logs",
    labelKey: "auditLogs",
    titleKey: "auditLogsTitle",
    descriptionKey: "auditLogsDescription",
    minRole: "admin",
    endpoint: "/audit-logs",
    columns: ["created_at", "action", "actor", "target_type", "target_id"],
  },
  {
    id: "nodes",
    labelKey: "nodes",
    titleKey: "nodesTitle",
    descriptionKey: "nodesDescription",
    minRole: "public",
    endpoint: "/nodes",
    columns: ["last_seen_at", "node_name", "agent_version"],
    adminColumns: ["last_seen_at", "node_name", "agent_version", "privacy_mode"],
  },
];

export const DATASET_BY_ID = new Map(PAGES.filter((page) => page.endpoint).map((page) => [page.id, page]));

export function pageById(id: PageId): PageConfig {
  return PAGES.find((page) => page.id === id) ?? PAGES[0];
}
