export const DATASETS = {
  findings: {
    navKey: "findings",
    titleKey: "findingsTitle",
    descriptionKey: "findingsDescription",
    endpoint: "/findings",
    columns: ["timestamp", "node_name", "severity", "rule_id", "category", "subject", "title"],
  },
  incidents: {
    navKey: "incidents",
    titleKey: "incidentsTitle",
    descriptionKey: "incidentsDescription",
    endpoint: "/incidents",
    columns: ["last_seen", "node_name", "severity", "score", "title", "summary"],
  },
  baseline_drifts: {
    navKey: "drifts",
    titleKey: "driftsTitle",
    descriptionKey: "driftsDescription",
    endpoint: "/baseline-drifts",
    columns: ["timestamp", "node_name", "severity", "rule_id", "tier", "subject", "review_action"],
  },
  active_blocks: {
    navKey: "blocks",
    titleKey: "blocksTitle",
    descriptionKey: "blocksDescription",
    endpoint: "/active-blocks",
    columns: ["blocked_at", "node_name", "rule_id", "backend", "reason", "expires_at"],
  },
  audit_logs: {
    navKey: "auditLogs",
    titleKey: "auditLogsTitle",
    descriptionKey: "auditLogsDescription",
    endpoint: "/audit-logs",
    columns: ["created_at", "action", "actor", "target_type", "target_id"],
  },
  nodes: {
    navKey: "nodes",
    titleKey: "nodesTitle",
    descriptionKey: "nodesDescription",
    endpoint: "/nodes",
    columns: ["last_seen_at", "node_name", "agent_version", "privacy_mode"],
  },
};
