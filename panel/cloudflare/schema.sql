CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  node_name TEXT NOT NULL,
  host_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  agent_version TEXT NOT NULL,
  privacy_mode TEXT NOT NULL,
  enabled_features_json TEXT NOT NULL,
  storage_json TEXT NOT NULL,
  metrics_json TEXT NOT NULL DEFAULT '{}',
  last_seen_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS heartbeats (
  message_id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  sent_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  scan_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  category TEXT NOT NULL,
  subject TEXT NOT NULL,
  review_signature TEXT NOT NULL DEFAULT '',
  timestamp TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  impact_json TEXT NOT NULL,
  recommendations_json TEXT NOT NULL,
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_reviews (
  finding_id TEXT PRIMARY KEY,
  verdict TEXT NOT NULL,
  note TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  reviewed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS panel_reviews (
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  verdict TEXT NOT NULL,
  note TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  review_signature TEXT NOT NULL DEFAULT '',
  reviewed_at TEXT NOT NULL,
  PRIMARY KEY (target_type, target_id)
);

CREATE TABLE IF NOT EXISTS panel_audit_logs (
  id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  score INTEGER NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  summary TEXT NOT NULL,
  review_signature TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL,
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_drifts (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  subject TEXT NOT NULL,
  review_signature TEXT NOT NULL DEFAULT '',
  timestamp TEXT NOT NULL,
  tier TEXT NOT NULL,
  score INTEGER,
  review_action TEXT NOT NULL,
  reasons_json TEXT NOT NULL,
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS active_blocks (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  backend TEXT NOT NULL,
  blocked_at TEXT NOT NULL,
  expires_at TEXT,
  expired INTEGER NOT NULL,
  firewall_present INTEGER,
  received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS probe_sources (
  id TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  ip_version TEXT NOT NULL,
  network_prefix TEXT NOT NULL,
  country TEXT NOT NULL,
  asn TEXT NOT NULL,
  organization TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  seen_count INTEGER NOT NULL,
  categories_json TEXT NOT NULL,
  rule_ids_json TEXT NOT NULL,
  latest_reason TEXT NOT NULL,
  block_status TEXT NOT NULL,
  block_reason TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_nonces (
  nonce TEXT PRIMARY KEY,
  node_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_findings_node_time ON findings(node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_severity_time ON findings(severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_finding_reviews_verdict ON finding_reviews(verdict, reviewed_at);
CREATE INDEX IF NOT EXISTS idx_panel_reviews_verdict ON panel_reviews(target_type, verdict, reviewed_at);
CREATE INDEX IF NOT EXISTS idx_panel_reviews_signature ON panel_reviews(target_type, review_signature, verdict, reviewed_at);
CREATE INDEX IF NOT EXISTS idx_panel_audit_logs_created ON panel_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_node_time ON incidents(node_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_incidents_review_signature ON incidents(review_signature);
CREATE INDEX IF NOT EXISTS idx_baseline_node_time ON baseline_drifts(node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_baseline_review_signature ON baseline_drifts(review_signature);
CREATE INDEX IF NOT EXISTS idx_findings_review_signature ON findings(review_signature);
CREATE INDEX IF NOT EXISTS idx_blocks_node ON active_blocks(node_id);
CREATE INDEX IF NOT EXISTS idx_probe_sources_node_seen ON probe_sources(node_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_probe_sources_ip_seen ON probe_sources(source_ip, last_seen);
CREATE INDEX IF NOT EXISTS idx_nonces_expires ON ingest_nonces(expires_at);
