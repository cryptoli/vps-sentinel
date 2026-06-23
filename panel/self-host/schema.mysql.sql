CREATE TABLE IF NOT EXISTS nodes (
  node_id VARCHAR(191) PRIMARY KEY,
  node_name VARCHAR(255) NOT NULL,
  host_id VARCHAR(255) NOT NULL,
  hostname VARCHAR(255) NOT NULL,
  agent_version VARCHAR(64) NOT NULL,
  privacy_mode VARCHAR(32) NOT NULL,
  enabled_features_json TEXT NOT NULL,
  storage_json TEXT NOT NULL,
  metrics_json TEXT NOT NULL,
  last_seen_at VARCHAR(64) NOT NULL,
  updated_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS heartbeats (
  message_id VARCHAR(191) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  sent_at VARCHAR(64) NOT NULL,
  received_at VARCHAR(64) NOT NULL,
  scan_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id VARCHAR(191) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  rule_id VARCHAR(64) NOT NULL,
  title VARCHAR(512) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  confidence VARCHAR(32) NOT NULL,
  category VARCHAR(64) NOT NULL,
  subject VARCHAR(512) NOT NULL,
  review_signature VARCHAR(96) NOT NULL DEFAULT '',
  timestamp VARCHAR(64) NOT NULL,
  dedup_key VARCHAR(191) NOT NULL,
  evidence_json TEXT NOT NULL,
  impact_json TEXT NOT NULL,
  recommendations_json TEXT NOT NULL,
  received_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_reviews (
  finding_id VARCHAR(191) PRIMARY KEY,
  verdict VARCHAR(32) NOT NULL,
  note TEXT NOT NULL,
  reviewer VARCHAR(128) NOT NULL,
  reviewed_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS panel_reviews (
  target_type VARCHAR(64) NOT NULL,
  target_id VARCHAR(191) NOT NULL,
  verdict VARCHAR(32) NOT NULL,
  note TEXT NOT NULL,
  reviewer VARCHAR(128) NOT NULL,
  review_signature VARCHAR(96) NOT NULL DEFAULT '',
  reviewed_at VARCHAR(64) NOT NULL,
  PRIMARY KEY (target_type, target_id)
);

CREATE TABLE IF NOT EXISTS panel_audit_logs (
  id VARCHAR(191) PRIMARY KEY,
  action VARCHAR(64) NOT NULL,
  actor VARCHAR(128) NOT NULL,
  target_type VARCHAR(64) NOT NULL,
  target_id VARCHAR(191) NOT NULL,
  detail_json TEXT NOT NULL,
  created_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
  id VARCHAR(191) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  title VARCHAR(512) NOT NULL,
  severity VARCHAR(32) NOT NULL,
  score INTEGER NOT NULL,
  first_seen VARCHAR(64) NOT NULL,
  last_seen VARCHAR(64) NOT NULL,
  summary TEXT NOT NULL,
  review_signature VARCHAR(96) NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL,
  received_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_drifts (
  id VARCHAR(191) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  finding_id VARCHAR(191) NOT NULL,
  rule_id VARCHAR(64) NOT NULL,
  category VARCHAR(64) NOT NULL DEFAULT 'system',
  severity VARCHAR(32) NOT NULL,
  subject VARCHAR(512) NOT NULL,
  review_signature VARCHAR(96) NOT NULL DEFAULT '',
  timestamp VARCHAR(64) NOT NULL,
  tier VARCHAR(32) NOT NULL,
  score INTEGER,
  review_action VARCHAR(128) NOT NULL,
  reasons_json TEXT NOT NULL,
  received_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS active_blocks (
  id VARCHAR(191) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  rule_id VARCHAR(64) NOT NULL,
  finding_id VARCHAR(191) NOT NULL,
  reason VARCHAR(512) NOT NULL,
  backend VARCHAR(64) NOT NULL,
  blocked_at VARCHAR(64) NOT NULL,
  expires_at VARCHAR(64),
  expired INTEGER NOT NULL,
  firewall_present INTEGER,
  received_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS probe_sources (
  id VARCHAR(191) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  ip_version VARCHAR(8) NOT NULL,
  network_prefix VARCHAR(96) NOT NULL,
  country VARCHAR(96) NOT NULL,
  asn VARCHAR(64) NOT NULL,
  organization VARCHAR(255) NOT NULL,
  first_seen VARCHAR(64) NOT NULL,
  last_seen VARCHAR(64) NOT NULL,
  seen_count INTEGER NOT NULL,
  categories_json TEXT NOT NULL,
  rule_ids_json TEXT NOT NULL,
  latest_reason VARCHAR(512) NOT NULL,
  block_status VARCHAR(64) NOT NULL,
  block_reason VARCHAR(512) NOT NULL,
  updated_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_nonces (
  nonce VARCHAR(255) PRIMARY KEY,
  node_id VARCHAR(191) NOT NULL,
  expires_at BIGINT NOT NULL
);

CREATE INDEX idx_nodes_last_seen ON nodes(last_seen_at);
CREATE INDEX idx_findings_node_time ON findings(node_id, timestamp);
CREATE INDEX idx_findings_severity_time ON findings(severity, timestamp);
CREATE INDEX idx_finding_reviews_verdict ON finding_reviews(verdict, reviewed_at);
CREATE INDEX idx_panel_reviews_verdict ON panel_reviews(target_type, verdict, reviewed_at);
CREATE INDEX idx_panel_reviews_signature ON panel_reviews(target_type, review_signature, verdict, reviewed_at);
CREATE INDEX idx_panel_audit_logs_created ON panel_audit_logs(created_at);
CREATE INDEX idx_incidents_node_time ON incidents(node_id, last_seen);
CREATE INDEX idx_incidents_review_signature ON incidents(review_signature);
CREATE INDEX idx_baseline_node_time ON baseline_drifts(node_id, timestamp);
CREATE INDEX idx_baseline_review_signature ON baseline_drifts(review_signature);
CREATE INDEX idx_findings_review_signature ON findings(review_signature);
CREATE INDEX idx_blocks_node ON active_blocks(node_id);
CREATE INDEX idx_probe_sources_node_seen ON probe_sources(node_id, last_seen);
CREATE INDEX idx_probe_sources_ip_seen ON probe_sources(source_ip, last_seen);
CREATE INDEX idx_nonces_expires ON ingest_nonces(expires_at);
