const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const SIGNATURE_WINDOW_SECONDS = 300;
const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGE_LIMIT = 200;
const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = 30;
const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = 720;
const ROLE_LEVELS = { public: 0, operator: 1, admin: 2 };
const PANEL_TRANSPORT_ENCODING = "json-base64";
const DEFAULT_ADMIN_PATH = "/panel-admin";
const DEFAULT_THEMES = "default:Default";
let compatSchemaPromise = null;

const DATASETS = {
  "/api/v1/nodes": {
    pageId: "nodes",
    minRole: "public",
    table: "nodes",
    orderColumn: "node_name",
    orderDirection: "ASC",
    filterColumn: "last_seen_at",
    columns: ["last_seen_at", "node_name", "agent_version", "privacy_mode", "metrics_json"],
  },
  "/api/v1/findings": {
    pageId: "findings",
    minRole: "operator",
    table: "findings",
    orderColumn: "timestamp",
    columns: ["id", "timestamp", "node_id AS node_name", "severity", "rule_id", "category", "subject", "review_signature", "title"],
  },
  "/api/v1/incidents": {
    pageId: "incidents",
    minRole: "operator",
    table: "incidents",
    orderColumn: "last_seen",
    columns: ["id", "last_seen", "node_id AS node_name", "severity", "score", "title", "summary", "review_signature"],
  },
  "/api/v1/baseline-drifts": {
    pageId: "baseline_drifts",
    minRole: "operator",
    table: "baseline_drifts",
    orderColumn: "timestamp",
    columns: ["id", "finding_id", "timestamp", "node_id AS node_name", "severity", "rule_id", "tier", "subject", "review_signature", "review_action"],
  },
  "/api/v1/active-blocks": {
    pageId: "active_blocks",
    minRole: "operator",
    sensitive: true,
    table: "active_blocks",
    orderColumn: "blocked_at",
    activeFilter: "expired = 0",
    columns: [
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
      "expires_at",
    ],
  },
  "/api/v1/probe-sources": {
    pageId: "probe_sources",
    minRole: "admin",
    sensitive: true,
    optional: true,
    table: "probe_sources",
    orderColumn: "last_seen",
    columns: [
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
      "block_reason",
    ],
  },
  "/api/v1/audit-logs": {
    pageId: "audit_logs",
    minRole: "admin",
    table: "panel_audit_logs",
    orderColumn: "created_at",
    columns: ["created_at", "action", "actor", "target_type", "target_id"],
  },
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "OPTIONS") {
        return withCors(new Response(null, { status: 204 }), request, env);
      }
      if (env.DB && url.pathname.startsWith("/api/v1/")) {
        await ensureCompatSchema(env);
      }
      if (request.method === "POST" && url.pathname === "/api/v1/ingest") {
        return withCors(await ingest(request, env), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/settings") {
        const role = resolvePanelRole(request, env, { allowAnonymous: true });
        const pages = publicPages(env);
        return withCors(json({
          theme: env.PANEL_THEME || "default",
          themes: panelThemes(env),
          admin_path: adminPath(env),
          auth_required: !publicAccessEnabled(env),
          auth_configured: Boolean(operatorTokens(env).length || adminToken(env)),
          operator_configured: Boolean(operatorTokens(env).length),
          admin_configured: Boolean(adminToken(env)),
          public_enabled: publicAccessEnabled(env),
          public_pages: pages,
          role,
          freshness_threshold_minutes: DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
          node_retired_threshold_minutes: DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
          server_time: new Date().toISOString(),
        }), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/summary") {
        const auth = panelAuth(request, env, "public");
        if (auth.error) return withCors(auth.error, request, env);
        return withCors(json(await summary(env, auth.role)), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/trends") {
        const auth = panelAuth(request, env, "public");
        if (auth.error) return withCors(auth.error, request, env);
        return withCors(json({ items: await trendPoints(env, url) }), request, env);
      }
      if (request.method === "GET" && DATASETS[url.pathname]) {
        const dataset = DATASETS[url.pathname];
        const auth = panelAuth(request, env, datasetMinimumRole(dataset, env));
        if (auth.error) return withCors(auth.error, request, env);
        return withCors(json(await queryPage(env, dataset, url, auth.role)), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/finding") {
        const authError = viewAuthError(request, env);
        if (authError) return withCors(authError, request, env);
        return withCors(json(await findingDetail(env, url)), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/incident") {
        const authError = viewAuthError(request, env);
        if (authError) return withCors(authError, request, env);
        return withCors(json(await incidentDetail(env, url)), request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/v1/finding-review") {
        const authError = adminAuthError(request, env);
        if (authError) return withCors(authError, request, env);
        return withCors(json(await findingReview(request, env)), request, env);
      }
      if (request.method === "POST" && url.pathname === "/api/v1/review") {
        const authError = adminAuthError(request, env);
        if (authError) return withCors(authError, request, env);
        return withCors(json(await panelReview(request, env)), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/stream-ticket") {
        return withCors(json({ error: "stream_unavailable", detail: "stream_unavailable" }, 501), request, env);
      }
      if (request.method === "GET" && env.ASSETS) {
        return env.ASSETS.fetch(request);
      }
      return withCors(json({ error: "not_found" }, 404), request, env);
    } catch (error) {
      console.error(error);
      if (error?.status && error?.code) {
        return withCors(json({ error: error.code, detail: error.code }, error.status), request, env);
      }
      return withCors(json({ error: "internal_error", detail: safeInternalErrorCode(error) }, 500), request, env);
    }
  },
};

async function ensureCompatSchema(env) {
  if (!compatSchemaPromise) {
    compatSchemaPromise = (async () => {
      const columns = [
        ["nodes", "metrics_json", "TEXT NOT NULL DEFAULT '{}'"],
        ["findings", "review_signature", "TEXT NOT NULL DEFAULT ''"],
        ["incidents", "review_signature", "TEXT NOT NULL DEFAULT ''"],
        ["baseline_drifts", "review_signature", "TEXT NOT NULL DEFAULT ''"],
        ["panel_reviews", "review_signature", "TEXT NOT NULL DEFAULT ''"],
      ];
      for (const [table, column, definition] of columns) {
        await ignoreExistingSchemaError(
          env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run(),
        );
      }
      const indexes = [
        "CREATE INDEX IF NOT EXISTS idx_findings_review_signature ON findings(review_signature)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_review_signature ON incidents(review_signature)",
        "CREATE INDEX IF NOT EXISTS idx_baseline_review_signature ON baseline_drifts(review_signature)",
        "CREATE INDEX IF NOT EXISTS idx_panel_reviews_signature ON panel_reviews(target_type, review_signature, verdict, reviewed_at)",
      ];
      for (const statement of indexes) {
        await env.DB.prepare(statement).run();
      }
    })();
  }
  return compatSchemaPromise;
}

async function ignoreExistingSchemaError(promise) {
  try {
    await promise;
  } catch (error) {
    const message = String(error?.message || error).toLowerCase();
    if (!message.includes("duplicate column") && !message.includes("already exists")) {
      throw error;
    }
  }
}

async function ingest(request, env) {
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.byteLength > Number(env.PANEL_MAX_BODY_BYTES || 1048576)) {
    return json({ error: "body_too_large" }, 413);
  }
  const nodeName = ingestNodeName(request);
  const timestamp = Number(requiredHeader(request, "x-vps-sentinel-timestamp"));
  const nonce = requiredHeader(request, "x-vps-sentinel-nonce");
  const bodyHash = requiredHeader(request, "x-vps-sentinel-body-sha256");
  const signature = requiredHeader(request, "x-vps-sentinel-signature");
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > SIGNATURE_WINDOW_SECONDS) {
    return json({ error: "signature_timestamp_out_of_window" }, 401);
  }
  if (!nonce.startsWith(`${nodeName}:`)) {
    return json({ error: "nonce_node_mismatch" }, 401);
  }
  const actualHash = await sha256Hex(body);
  if (!timingSafeEqual(actualHash, bodyHash)) {
    return json({ error: "body_hash_mismatch" }, 401);
  }
  const secret = secretForNode(env, nodeName);
  if (!secret) {
    return json({ error: "unknown_node_secret" }, 401);
  }
  const signing = ["POST", "/api/v1/ingest", String(timestamp), nonce, bodyHash].join("\n");
  const expected = await hmacSha256Hex(secret, signing);
  if (!timingSafeEqual(expected, signature)) {
    return json({ error: "signature_mismatch" }, 401);
  }
  await env.DB.prepare("DELETE FROM ingest_nonces WHERE expires_at < ?").bind(now).run();
  const seen = await env.DB.prepare("SELECT nonce FROM ingest_nonces WHERE nonce = ?").bind(nonce).first();
  if (seen) {
    return json({ error: "nonce_replay" }, 409);
  }
  await env.DB.prepare("INSERT INTO ingest_nonces (nonce, node_id, expires_at) VALUES (?, ?, ?)")
    .bind(nonce, nodeName, now + SIGNATURE_WINDOW_SECONDS)
    .run();

  const payloadBody = decodePanelPayloadBody(request, body);
  const payload = JSON.parse(new TextDecoder().decode(payloadBody));
  if (!validPanelPayloadIdentity(payload, nodeName)) {
    return json({ error: "invalid_payload" }, 400);
  }
  await persistPayload(env, payload, nodeName);
  return json({ ok: true, message_id: payload.message_id });
}

function ingestNodeName(request) {
  try {
    return requiredHeader(request, "x-vps-sentinel-node-name");
  } catch {
    return requiredHeader(request, "x-vps-sentinel-node");
  }
}

function decodePanelPayloadBody(request, body) {
  const encoding = String(request.headers.get("x-vps-sentinel-payload-encoding") || "").trim();
  if (!encoding) return body;
  if (encoding !== PANEL_TRANSPORT_ENCODING) throwHttp(400, "unsupported_payload_encoding");
  const wrapper = JSON.parse(new TextDecoder().decode(body));
  if (wrapper?.encoding !== PANEL_TRANSPORT_ENCODING || typeof wrapper?.payload !== "string") {
    throwHttp(400, "payload_encoding_mismatch");
  }
  return base64ToBytes(wrapper.payload);
}

function base64ToBytes(value) {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    throwHttp(400, "invalid_payload_base64");
  }
}

function validPanelPayloadIdentity(payload, nodeName) {
  if (payload?.schema_version === 2) return payload?.node?.node_name === nodeName;
  if (payload?.schema_version === 1) {
    return payload?.node?.node_id === nodeName || payload?.node?.node_name === nodeName;
  }
  return false;
}

async function persistPayload(env, payload, signedNodeName) {
  const receivedAt = new Date().toISOString();
  const node = payload.node;
  const nodeName = redactIpText(signedNodeName || node.node_name || "");
  const statements = [];
  const nodeStatement = panelNodeStatement(env, nodeName, node, payload.sent_at, receivedAt, true);
  statements.push(nodeStatement);
  statements.push(env.DB.prepare("INSERT OR REPLACE INTO heartbeats (message_id, node_id, sent_at, received_at, scan_json) VALUES (?, ?, ?, ?, ?)")
    .bind(payload.message_id, nodeName, payload.sent_at, receivedAt, JSON.stringify(redactPanelValue(payload.scan || {})))
  );

  for (const finding of payload.findings || []) {
    const evidence = redactPanelValue(finding.evidence || []);
    const impact = redactPanelValue(finding.impact || []);
    const recommendations = redactPanelValue(finding.recommendations || []);
    const title = redactIpText(finding.title || "");
    const subject = redactIpText(finding.subject || "");
    const reviewSignature = await findingReviewSignature(nodeName, finding.rule_id, finding.category, subject, title);
    statements.push(env.DB.prepare(`
      INSERT OR REPLACE INTO findings
        (id, node_id, rule_id, title, severity, confidence, category, subject, review_signature, timestamp, dedup_key, evidence_json, impact_json, recommendations_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      finding.id,
      nodeName,
      finding.rule_id,
      title,
      finding.severity,
      finding.confidence,
      finding.category,
      subject,
      reviewSignature,
      finding.timestamp,
      redactIpText(finding.dedup_key || ""),
      JSON.stringify(evidence),
      JSON.stringify(impact),
      JSON.stringify(recommendations),
      receivedAt,
    ));
  }

  for (const incident of payload.incidents || []) {
    const incidentPayload = redactPanelValue(incident);
    const title = redactIpText(incident.title || "");
    const summary = redactIpText(incident.summary || "");
    const reviewSignature = await incidentReviewSignature(nodeName, incident.severity, title, summary);
    statements.push(env.DB.prepare(`
      INSERT OR REPLACE INTO incidents
        (id, node_id, title, severity, score, first_seen, last_seen, summary, review_signature, payload_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      incident.id,
      nodeName,
      title,
      incident.severity,
      Number(incident.score || 0),
      incident.first_seen,
      incident.last_seen,
      summary,
      reviewSignature,
      JSON.stringify(incidentPayload),
      receivedAt,
    ));
  }

  for (const drift of payload.baseline_drifts || []) {
    const subject = redactIpText(drift.subject || "");
    const category = String(drift.category || baselineCategoryFromRule(drift.rule_id || ""));
    const reviewSignature = await driftReviewSignature(nodeName, drift.rule_id, category, subject, drift.tier);
    const id = `${nodeName}:${drift.finding_id || drift.rule_id}:${subject}:${drift.timestamp}`;
    statements.push(env.DB.prepare(`
      INSERT OR REPLACE INTO baseline_drifts
        (id, node_id, finding_id, rule_id, severity, subject, review_signature, timestamp, tier, score, review_action, reasons_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      nodeName,
      drift.finding_id || "",
      drift.rule_id,
      drift.severity,
      subject,
      reviewSignature,
      drift.timestamp,
      drift.tier,
      drift.score ?? null,
      drift.review_action,
      JSON.stringify(redactPanelValue(drift.reasons || [])),
      receivedAt,
    ));
  }

  for (const block of payload.active_blocks || []) {
    const id = panelBlockStorageId(nodeName, block);
    statements.push(env.DB.prepare(`
      INSERT OR REPLACE INTO active_blocks
        (id, node_id, ip, rule_id, finding_id, reason, backend, blocked_at, expires_at, expired, firewall_present, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      nodeName,
      String(block.ip || "").trim() || redactedIp(),
      block.rule_id,
      block.finding_id,
      redactIpText(block.reason || ""),
      block.backend,
      block.blocked_at,
      block.expires_at || null,
      block.expired ? 1 : 0,
      block.firewall_present === null || block.firewall_present === undefined ? null : (block.firewall_present ? 1 : 0),
      receivedAt,
    ));
  }

  try {
    await runD1Batch(env, statements);
  } catch (error) {
    if (!missingColumnError(error, "metrics_json")) throw error;
    statements[0] = panelNodeStatement(env, nodeName, node, payload.sent_at, receivedAt, false);
    await runD1Batch(env, statements);
  }
  const probeStatements = [];
  for (const source of payload.probe_sources || []) {
    const statement = probeSourceStatement(env, nodeName, source, receivedAt);
    if (statement) probeStatements.push(statement);
  }
  try {
    await runD1Batch(env, probeStatements);
  } catch (error) {
    if (missingTableError(error, "probe_sources")) {
      console.warn("probe_sources table is missing; apply panel/cloudflare/schema.sql to enable probe-source blacklist storage");
    } else {
      throw error;
    }
  }
}

function panelNodeStatement(env, nodeName, node, sentAt, receivedAt, includeMetrics) {
  if (!includeMetrics) {
    return env.DB.prepare(`
      INSERT INTO nodes
        (node_id, node_name, host_id, hostname, agent_version, privacy_mode, enabled_features_json, storage_json, last_seen_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(node_id) DO UPDATE SET
        node_name = excluded.node_name,
        host_id = excluded.host_id,
        hostname = excluded.hostname,
        agent_version = excluded.agent_version,
        privacy_mode = excluded.privacy_mode,
        enabled_features_json = excluded.enabled_features_json,
        storage_json = excluded.storage_json,
        last_seen_at = excluded.last_seen_at,
        updated_at = excluded.updated_at
    `).bind(
      nodeName,
      nodeName,
      "",
      "",
      node.agent_version,
      node.privacy_mode,
      JSON.stringify(node.enabled_features || []),
      JSON.stringify(redactPanelValue(node.storage || {})),
      sentAt,
      receivedAt,
    );
  }
  return env.DB.prepare(`
    INSERT INTO nodes
      (node_id, node_name, host_id, hostname, agent_version, privacy_mode, enabled_features_json, storage_json, metrics_json, last_seen_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(node_id) DO UPDATE SET
      node_name = excluded.node_name,
      host_id = excluded.host_id,
      hostname = excluded.hostname,
      agent_version = excluded.agent_version,
      privacy_mode = excluded.privacy_mode,
      enabled_features_json = excluded.enabled_features_json,
      storage_json = excluded.storage_json,
      metrics_json = excluded.metrics_json,
      last_seen_at = excluded.last_seen_at,
      updated_at = excluded.updated_at
  `).bind(
    nodeName,
    nodeName,
    "",
    "",
    node.agent_version,
    node.privacy_mode,
    JSON.stringify(node.enabled_features || []),
    JSON.stringify(redactPanelValue(node.storage || {})),
    JSON.stringify(redactPanelValue(node.metrics || {})),
    sentAt,
    receivedAt,
  );
}

function probeSourceStatement(env, nodeName, source, receivedAt) {
  const sourceIp = String(source?.source_ip || "").trim();
  if (!sourceIp) return null;
  const id = `${nodeName}:${sourceIp}`;
  const firstSeen = String(source.first_seen || receivedAt);
  const lastSeen = String(source.last_seen || firstSeen);
  const seenCount = Math.max(1, Number(source.seen_count || 1) || 1);
  return env.DB.prepare(`
    INSERT INTO probe_sources
      (id, node_id, source_ip, ip_version, network_prefix, country, asn, organization,
       first_seen, last_seen, seen_count, categories_json, rule_ids_json, latest_reason,
       block_status, block_reason, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      network_prefix = CASE
        WHEN excluded.network_prefix IS NOT NULL AND excluded.network_prefix <> '' AND LOWER(excluded.network_prefix) <> 'unknown' THEN excluded.network_prefix
        WHEN probe_sources.network_prefix IS NOT NULL AND probe_sources.network_prefix <> '' AND LOWER(probe_sources.network_prefix) <> 'unknown' THEN probe_sources.network_prefix
        ELSE excluded.network_prefix
      END,
      country = CASE
        WHEN excluded.country IS NOT NULL AND excluded.country <> '' AND LOWER(excluded.country) <> 'unknown' THEN excluded.country
        WHEN probe_sources.country IS NOT NULL AND probe_sources.country <> '' AND LOWER(probe_sources.country) <> 'unknown' THEN probe_sources.country
        ELSE excluded.country
      END,
      asn = CASE
        WHEN excluded.asn IS NOT NULL AND excluded.asn <> '' AND LOWER(excluded.asn) <> 'unknown' THEN excluded.asn
        WHEN probe_sources.asn IS NOT NULL AND probe_sources.asn <> '' AND LOWER(probe_sources.asn) <> 'unknown' THEN probe_sources.asn
        ELSE excluded.asn
      END,
      organization = CASE
        WHEN excluded.organization IS NOT NULL AND excluded.organization <> '' AND LOWER(excluded.organization) <> 'unknown' THEN excluded.organization
        WHEN probe_sources.organization IS NOT NULL AND probe_sources.organization <> '' AND LOWER(probe_sources.organization) <> 'unknown' THEN probe_sources.organization
        ELSE excluded.organization
      END,
      first_seen = CASE
        WHEN probe_sources.first_seen <= excluded.first_seen THEN probe_sources.first_seen
        ELSE excluded.first_seen
      END,
      last_seen = CASE
        WHEN probe_sources.last_seen >= excluded.last_seen THEN probe_sources.last_seen
        ELSE excluded.last_seen
      END,
      seen_count = probe_sources.seen_count + excluded.seen_count,
      categories_json = excluded.categories_json,
      rule_ids_json = excluded.rule_ids_json,
      latest_reason = excluded.latest_reason,
      block_status = CASE
        WHEN LOWER(COALESCE(excluded.block_status, '')) LIKE '%permanent%' THEN excluded.block_status
        WHEN LOWER(COALESCE(probe_sources.block_status, '')) LIKE '%permanent%' THEN probe_sources.block_status
        WHEN LOWER(COALESCE(excluded.block_status, '')) LIKE '%block%' OR LOWER(COALESCE(excluded.block_status, '')) IN ('temporary', 'blocked') THEN excluded.block_status
        WHEN LOWER(COALESCE(probe_sources.block_status, '')) LIKE '%block%' OR LOWER(COALESCE(probe_sources.block_status, '')) IN ('temporary', 'blocked') THEN probe_sources.block_status
        ELSE excluded.block_status
      END,
      block_reason = excluded.block_reason,
      updated_at = excluded.updated_at
  `).bind(
    id,
    nodeName,
    sourceIp,
    String(source.ip_version || "unknown"),
    String(source.network_prefix || "unknown"),
    String(source.country || "unknown"),
    String(source.asn || "unknown"),
    redactIpText(source.organization || "unknown"),
    firstSeen,
    lastSeen,
    seenCount,
    JSON.stringify((source.categories || []).map((item) => String(item || "")).filter(Boolean)),
    JSON.stringify((source.rule_ids || []).map((item) => String(item || "")).filter(Boolean)),
    redactIpText(source.latest_reason || ""),
    String(source.block_status || "observed"),
    redactIpText(source.block_reason || ""),
    receivedAt,
  );
}

async function summary(env, role = "public") {
  const activeFindingsFilter = reviewNotFalsePositiveFilter("findings", "finding");
  const activeIncidentsFilter = reviewNotFalsePositiveFilter("incidents", "incident");
  const activeDriftsFilter = reviewNotFalsePositiveFilter("baseline_drifts", "baseline_drift");
  const [nodes, findings, incidents, drifts, blocks, probeSources, bySeverity, byCategory, byBlockStatus, nodeRows] = await Promise.all([
    countDistinct(env, "nodes", "node_name"),
    countWhere(env, "findings", activeFindingsFilter),
    countWhere(env, "incidents", activeIncidentsFilter),
    countWhere(env, "baseline_drifts", activeDriftsFilter),
    countWhere(env, "active_blocks", "expired = 0"),
    countDistinctWhereOptional(env, "probe_sources", "source_ip", blockedProbeSourceFilter()),
    queryAll(env, `SELECT severity, COUNT(*) AS count FROM findings WHERE ${activeFindingsFilter} GROUP BY severity`),
    queryAll(env, `SELECT category, COUNT(*) AS count FROM findings WHERE ${activeFindingsFilter} GROUP BY category`),
    queryAllOptional(env, `SELECT block_status, COUNT(DISTINCT source_ip) AS count FROM probe_sources WHERE ${blockedProbeSourceFilter()} GROUP BY block_status`, "probe_sources"),
    queryAll(env, "SELECT node_name, agent_version, last_seen_at FROM nodes"),
  ]);
  const result = {
    nodes,
    findings,
    incidents,
    baseline_drifts: drifts,
    active_blocks: blocks,
    probe_sources: probeSources,
    by_severity: bySeverity,
    by_category: byCategory,
    by_block_status: byBlockStatus,
    node_status: nodeStatusCounts(nodeRows),
  };
  return redactPanelValue(result);
}

async function trendPoints(env, url) {
  const page = pageRequest(url);
  const values = [];
  const parts = [reviewNotFalsePositiveFilter("findings", "finding")];
  if (page.from) {
    values.push(page.from);
    parts.push("timestamp >= ?");
  }
  if (page.to) {
    values.push(page.to);
    parts.push("timestamp <= ?");
  }
  const whereSql = ` WHERE ${parts.join(" AND ")}`;
  const result = await env.DB.prepare(
    `SELECT timestamp, severity FROM findings${whereSql} ORDER BY timestamp DESC LIMIT ?`,
  ).bind(...values, 5000).all();
  const buckets = new Map();
  for (const row of result.results || []) {
    const bucket = String(row.timestamp || "").slice(0, 13);
    if (bucket.length !== 13) continue;
    const severity = String(row.severity || "Unknown");
    const severities = buckets.get(bucket) || new Map();
    severities.set(severity, (severities.get(severity) || 0) + 1);
    buckets.set(bucket, severities);
  }
  return [...buckets.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([bucket, severities]) => {
    const severity = Object.fromEntries(severities);
    const total = Object.values(severity).reduce((sum, value) => sum + Number(value || 0), 0);
    return { bucket, total, severity };
  });
}

function reviewNotFalsePositiveFilter(table, targetType) {
  return `NOT EXISTS (
    SELECT 1 FROM panel_reviews review
    WHERE review.target_type = '${targetType}'
      AND (
        review.target_id = ${table}.id
        OR (
          review.review_signature <> ''
          AND review.review_signature = ${table}.review_signature
        )
      )
      AND review.verdict = 'false_positive'
  )`;
}

async function queryPage(env, dataset, url, role = "operator") {
  if (dataset.table === "probe_sources") {
    return queryProbeSourcesPage(env, dataset, url, role);
  }
  const page = pageRequest(url);
  const values = [];
  const parts = [];
  if (dataset.activeFilter) parts.push(dataset.activeFilter);
  if (page.from) {
    values.push(page.from);
    parts.push(`${dataset.filterColumn || dataset.orderColumn} >= ?`);
  }
  if (page.to) {
    values.push(page.to);
    parts.push(`${dataset.filterColumn || dataset.orderColumn} <= ?`);
  }
  const whereSql = parts.length ? ` WHERE ${parts.join(" AND ")}` : "";
  try {
    const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${dataset.table}${whereSql}`)
      .bind(...values)
      .first();
    const result = await env.DB.prepare(
      `SELECT ${dataset.columns.join(", ")} FROM ${dataset.table}${whereSql} ORDER BY ${dataset.orderColumn} ${dataset.orderDirection === "ASC" ? "ASC" : "DESC"} LIMIT ? OFFSET ?`,
    ).bind(...values, page.limit, page.offset).all();
    let items = expandDatasetJsonColumns(dataset.table, result.results || []);
    items = await attachPanelReviews(env, dataset.table, items, role);
    return {
      items: shouldRedactDataset(dataset, role) ? redactPanelValue(items) : items,
      total: Number(countRow?.count || 0),
      limit: page.limit,
      offset: page.offset,
    };
  } catch (error) {
    if (dataset.optional && missingTableError(error, dataset.table)) {
      return { items: [], total: 0, limit: page.limit, offset: page.offset };
    }
    throw error;
  }
}

async function queryProbeSourcesPage(env, dataset, url, role = "operator") {
  const page = pageRequest(url);
  const values = [];
  const parts = [blockedProbeSourceFilter()];
  if (page.from) {
    values.push(page.from);
    parts.push("last_seen >= ?");
  }
  if (page.to) {
    values.push(page.to);
    parts.push("last_seen <= ?");
  }
  const whereSql = ` WHERE ${parts.join(" AND ")}`;
  try {
    const countRow = await env.DB.prepare(
      `SELECT COUNT(*) AS count FROM (SELECT source_ip FROM probe_sources${whereSql} GROUP BY source_ip) grouped_sources`,
    ).bind(...values).first();
    const result = await env.DB.prepare(`
      SELECT
        MAX(last_seen) AS last_seen,
        MIN(first_seen) AS first_seen,
        MAX(node_id) AS node_name,
        source_ip,
        MAX(ip_version) AS ip_version,
        MAX(CASE WHEN network_prefix IS NOT NULL AND network_prefix <> '' AND LOWER(network_prefix) <> 'unknown' THEN network_prefix ELSE '' END) AS network_prefix,
        SUM(seen_count) AS seen_count,
        CASE
          WHEN SUM(CASE WHEN LOWER(COALESCE(block_status, '')) LIKE '%permanent%' THEN 1 ELSE 0 END) > 0 THEN 'permanent_block'
          WHEN SUM(CASE WHEN LOWER(COALESCE(block_status, '')) LIKE '%block%' OR LOWER(COALESCE(block_status, '')) IN ('temporary', 'blocked') THEN 1 ELSE 0 END) > 0 THEN 'temporary_block'
          ELSE MAX(block_status)
        END AS block_status,
        COALESCE(NULLIF(MAX(CASE WHEN country IS NOT NULL AND country <> '' AND LOWER(country) <> 'unknown' THEN country ELSE '' END), ''), 'unknown') AS country,
        COALESCE(NULLIF(MAX(CASE WHEN asn IS NOT NULL AND asn <> '' AND LOWER(asn) <> 'unknown' THEN asn ELSE '' END), ''), 'unknown') AS asn,
        COALESCE(NULLIF(MAX(CASE WHEN organization IS NOT NULL AND organization <> '' AND LOWER(organization) <> 'unknown' THEN organization ELSE '' END), ''), 'unknown') AS organization,
        MAX(categories_json) AS categories_json,
        MAX(rule_ids_json) AS rule_ids_json,
        MAX(CASE WHEN latest_reason IS NOT NULL AND latest_reason <> '' THEN latest_reason ELSE '' END) AS latest_reason,
        MAX(CASE WHEN block_reason IS NOT NULL AND block_reason <> '' THEN block_reason ELSE '' END) AS block_reason
      FROM probe_sources${whereSql}
      GROUP BY source_ip
      ORDER BY last_seen DESC
      LIMIT ? OFFSET ?
    `).bind(...values, page.limit, page.offset).all();
    let items = expandDatasetJsonColumns("probe_sources", result.results || []);
    if (shouldRedactDataset(dataset, role)) items = redactPanelValue(items);
    items = scopeProbeSourceRows(items, role);
    return {
      items,
      total: Number(countRow?.count || 0),
      limit: page.limit,
      offset: page.offset,
    };
  } catch (error) {
    if (dataset.optional && missingTableError(error, dataset.table)) {
      return { items: [], total: 0, limit: page.limit, offset: page.offset };
    }
    throw error;
  }
}

function blockedProbeSourceFilter() {
  return "(LOWER(COALESCE(block_status, '')) LIKE '%block%' OR LOWER(COALESCE(block_status, '')) IN ('temporary', 'permanent', 'blocked'))";
}

function scopeProbeSourceRows(items, role) {
  if (role !== "public") return items;
  return (items || []).map((item) => {
    const next = { ...item };
    for (const key of ["network_prefix", "latest_reason", "block_reason", "first_seen"]) {
      delete next[key];
    }
    if (next.node_name) next.node_name = publicNodeName(next.node_name);
    return next;
  });
}

async function attachPanelReviews(env, table, items, role) {
  const targetType = reviewTargetForTable(table);
  if (!targetType || !items.length) return items;
  const ids = items.map((item) => String(item?.id || "").trim()).filter(Boolean);
  const signatures = [...new Set(items.map((item) => String(item?.review_signature || "").trim()).filter(Boolean))];
  if (!ids.length && !signatures.length) {
    return items.map((item) => ({ ...item, review_verdict: "needs_review" }));
  }
  const idPlaceholders = ids.map(() => "?").join(", ");
  const signaturePlaceholders = signatures.map(() => "?").join(", ");
  const predicates = [];
  if (ids.length) predicates.push(`target_id IN (${idPlaceholders})`);
  if (signatures.length) predicates.push(`review_signature IN (${signaturePlaceholders})`);
  const result = await env.DB.prepare(
    `SELECT target_id, review_signature, verdict, note, reviewer, reviewed_at
     FROM panel_reviews
     WHERE target_type = ? AND (${predicates.join(" OR ")})
     ORDER BY reviewed_at DESC`,
  ).bind(targetType, ...ids, ...signatures).all();
  const exactReviews = new Map();
  const signatureReviews = new Map();
  for (const review of result.results || []) {
    const targetId = String(review.target_id || "");
    const signature = String(review.review_signature || "");
    if (targetId && !exactReviews.has(targetId)) exactReviews.set(targetId, review);
    if (signature && !signatureReviews.has(signature)) signatureReviews.set(signature, review);
  }
  return items.map((item) => {
    const review = exactReviews.get(String(item?.id || ""))
      || signatureReviews.get(String(item?.review_signature || ""));
    if (!review) return { ...item, review_verdict: "needs_review", status: "needs_review" };
    const verdict = review.verdict || "needs_review";
    const next = { ...item, review_verdict: verdict, status: verdict };
    if (role === "admin") next.review = { target_type: targetType, ...review };
    return next;
  });
}

function reviewTargetForTable(table) {
  if (table === "findings") return "finding";
  if (table === "incidents") return "incident";
  if (table === "baseline_drifts") return "baseline_drift";
  return null;
}

async function findingDetail(env, url) {
  const id = requiredQuery(url, "id");
  const row = await env.DB.prepare(`
    SELECT id, node_id AS node_name, rule_id, title, severity, confidence, category, subject, review_signature, timestamp, dedup_key,
           evidence_json, impact_json, recommendations_json, received_at
    FROM findings
    WHERE id = ?
  `).bind(id).first();
  if (!row) throwHttp(404, "finding_not_found");
  row.evidence = parseJsonField(row.evidence_json, []);
  row.impact = parseJsonField(row.impact_json, []);
  row.recommendations = parseJsonField(row.recommendations_json, []);
  delete row.evidence_json;
  delete row.impact_json;
  delete row.recommendations_json;
  row.review = await panelReviewValue(env, "finding", id, row.review_signature)
    || await env.DB.prepare(
      "SELECT finding_id, verdict, note, reviewer, reviewed_at FROM finding_reviews WHERE finding_id = ?",
    ).bind(id).first();
  return redactPanelValue(row);
}

async function incidentDetail(env, url) {
  const id = requiredQuery(url, "id");
  const row = await env.DB.prepare(`
    SELECT id, node_id AS node_name, title, severity, score, first_seen, last_seen, summary, review_signature, payload_json, received_at
    FROM incidents
    WHERE id = ?
  `).bind(id).first();
  if (!row) throwHttp(404, "incident_not_found");
  row.payload = parseJsonField(row.payload_json, null);
  delete row.payload_json;
  row.review = await panelReviewValue(env, "incident", id, row.review_signature);
  return redactPanelValue(row);
}

async function panelReviewValue(env, targetType, targetId, reviewSignature = "") {
  const signature = String(reviewSignature || "").trim();
  const result = signature
    ? await env.DB.prepare(`
        SELECT target_type, target_id, review_signature, verdict, note, reviewer, reviewed_at
        FROM panel_reviews
        WHERE target_type = ? AND (target_id = ? OR review_signature = ?)
        ORDER BY CASE WHEN target_id = ? THEN 0 ELSE 1 END, reviewed_at DESC
        LIMIT 1
      `).bind(targetType, targetId, signature, targetId).first()
    : await env.DB.prepare(`
        SELECT target_type, target_id, review_signature, verdict, note, reviewer, reviewed_at
        FROM panel_reviews
        WHERE target_type = ? AND target_id = ?
        LIMIT 1
      `).bind(targetType, targetId).first();
  return result || null;
}

async function findingReview(request, env) {
  const payload = await request.json();
  const review = normalizeFindingReview(payload);
  const exists = await env.DB.prepare("SELECT id FROM findings WHERE id = ?").bind(review.finding_id).first();
  if (!exists) throwHttp(404, "finding_not_found");
  const reviewSignature = await targetReviewSignature(env, "finding", review.finding_id);
  await writeFindingReview(env, review);
  await writePanelReview(env, {
    target_type: "finding",
    target_id: review.finding_id,
    review_signature: reviewSignature,
    verdict: review.verdict,
    note: review.note,
    reviewer: review.reviewer,
    reviewed_at: review.reviewed_at,
  });
  await env.DB.prepare(`
    INSERT INTO panel_audit_logs (id, action, actor, target_type, target_id, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    `finding_review:finding:${review.finding_id}:${crypto.randomUUID()}`,
    "finding_review",
    review.reviewer || "panel",
    "finding",
    review.finding_id,
    JSON.stringify({ verdict: review.verdict, note_present: Boolean(review.note) }),
    review.reviewed_at,
  ).run();
  return {
    ok: true,
    finding_id: review.finding_id,
    review: panelReviewResponse({
      target_type: "finding",
      target_id: review.finding_id,
      review_signature: reviewSignature,
      verdict: review.verdict,
      note: review.note,
      reviewer: review.reviewer,
      reviewed_at: review.reviewed_at,
    }),
  };
}

async function panelReview(request, env) {
  const payload = await request.json();
  const review = normalizePanelReview(payload);
  const target = panelReviewTarget(review.target_type);
  const exists = await env.DB.prepare(`SELECT ${target.idColumn} FROM ${target.table} WHERE ${target.idColumn} = ?`)
    .bind(review.target_id)
    .first();
  if (!exists) throwHttp(404, target.notFound);
  const reviewSignature = await targetReviewSignature(env, review.target_type, review.target_id);
  const scopedReview = { ...review, review_signature: reviewSignature };
  await writePanelReview(env, scopedReview);
  if (review.target_type === "finding") {
    await writeFindingReview(env, {
      finding_id: review.target_id,
      verdict: review.verdict,
      note: review.note,
      reviewer: review.reviewer,
      reviewed_at: review.reviewed_at,
    });
  }
  await env.DB.prepare(`
    INSERT INTO panel_audit_logs (id, action, actor, target_type, target_id, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    `panel_review:${review.target_type}:${review.target_id}:${crypto.randomUUID()}`,
    "panel_review",
    review.reviewer || "panel",
    review.target_type,
    review.target_id,
    JSON.stringify({ verdict: review.verdict, note_present: Boolean(review.note) }),
    review.reviewed_at,
  ).run();
  return { ok: true, target_type: review.target_type, target_id: review.target_id, review: panelReviewResponse(scopedReview) };
}

function panelReviewResponse(review) {
  return {
    target_type: review.target_type,
    target_id: review.target_id,
    review_signature: review.review_signature || "",
    verdict: review.verdict,
    note: review.note,
    reviewer: review.reviewer,
    reviewed_at: review.reviewed_at,
  };
}

function normalizeFindingReview(payload) {
  const findingId = String(payload?.finding_id || "").trim();
  if (!findingId || findingId.length > 191) throwHttp(400, "invalid_finding_id");
  return {
    finding_id: findingId,
    verdict: normalizeReviewVerdict(payload?.verdict),
    note: String(payload?.note || "").trim().slice(0, 1000),
    reviewer: String(payload?.reviewer || "").trim().slice(0, 128),
    reviewed_at: new Date().toISOString(),
  };
}

function normalizePanelReview(payload) {
  const targetType = normalizeReviewTargetType(payload?.target_type);
  const targetId = String(payload?.target_id || "").trim();
  if (!targetId || targetId.length > 191) throwHttp(400, "invalid_review_target_id");
  return {
    target_type: targetType,
    target_id: targetId,
    verdict: normalizeReviewVerdict(payload?.verdict),
    note: String(payload?.note || "").trim().slice(0, 1000),
    reviewer: String(payload?.reviewer || "").trim().slice(0, 128),
    reviewed_at: new Date().toISOString(),
  };
}

function normalizeReviewVerdict(value) {
  const verdict = String(value || "").trim();
  if (!["false_positive", "confirmed", "needs_review"].includes(verdict)) {
    throwHttp(400, "invalid_review_verdict");
  }
  return verdict;
}

function normalizeReviewTargetType(value) {
  const targetType = String(value || "").trim().toLowerCase();
  if (["finding", "findings"].includes(targetType)) return "finding";
  if (["incident", "incidents"].includes(targetType)) return "incident";
  if (["baseline_drift", "baseline_drifts", "baseline", "drift"].includes(targetType)) return "baseline_drift";
  throwHttp(400, "invalid_review_target_type");
}

function panelReviewTarget(targetType) {
  if (targetType === "finding") return { table: "findings", idColumn: "id", notFound: "finding_not_found" };
  if (targetType === "incident") return { table: "incidents", idColumn: "id", notFound: "incident_not_found" };
  if (targetType === "baseline_drift") return { table: "baseline_drifts", idColumn: "id", notFound: "baseline_drift_not_found" };
  throwHttp(400, "invalid_review_target_type");
}

async function targetReviewSignature(env, targetType, targetId) {
  const target = panelReviewTarget(targetType);
  const columns = targetType === "finding"
    ? "node_id, rule_id, category, subject, title, review_signature"
    : targetType === "incident"
      ? "node_id, severity, title, summary, review_signature"
      : "node_id, rule_id, subject, tier, review_signature";
  const row = await env.DB.prepare(`SELECT ${columns} FROM ${target.table} WHERE ${target.idColumn} = ?`)
    .bind(targetId)
    .first();
  if (!row) throwHttp(404, target.notFound);
  if (String(row.review_signature || "").trim()) return String(row.review_signature);
  const signature = await reviewSignatureFromRow(targetType, row);
  await env.DB.prepare(`UPDATE ${target.table} SET review_signature = ? WHERE ${target.idColumn} = ?`)
    .bind(signature, targetId)
    .run();
  return signature;
}

async function reviewSignatureFromRow(targetType, row) {
  if (targetType === "finding") {
    return findingReviewSignature(row.node_id, row.rule_id, row.category, row.subject, row.title);
  }
  if (targetType === "incident") {
    return incidentReviewSignature(row.node_id, row.severity, row.title, row.summary);
  }
  return driftReviewSignature(
    row.node_id,
    row.rule_id,
    baselineCategoryFromRule(row.rule_id),
    row.subject,
    row.tier,
  );
}

async function findingReviewSignature(nodeId, ruleId, category, subject, title) {
  return reviewSignature([
    ["finding", false],
    [nodeId, false],
    [ruleId, false],
    [category, false],
    [subject, true],
    [title, true],
  ]);
}

async function incidentReviewSignature(nodeId, severity, title, summary) {
  return reviewSignature([
    ["incident", false],
    [nodeId, false],
    [severity, false],
    [title, true],
    [summary, true],
  ]);
}

async function driftReviewSignature(nodeId, ruleId, category, subject, tier) {
  return reviewSignature([
    ["baseline_drift", false],
    [nodeId, false],
    [ruleId, false],
    [category, false],
    [subject, true],
    [tier, false],
  ]);
}

async function reviewSignature(parts) {
  const source = parts.map(([value, dynamic]) => normalizeReviewSignaturePart(value, dynamic)).join("|");
  return `v1:${await sha256Hex(new TextEncoder().encode(source))}`;
}

function normalizeReviewSignaturePart(value, dynamic) {
  let out = "";
  let previousSpace = false;
  let numberOpen = false;
  for (const char of redactIpText(String(value || "")).trim().toLowerCase()) {
    if (dynamic && /[0-9]/.test(char)) {
      if (!numberOpen) out += "#";
      numberOpen = true;
      previousSpace = false;
      continue;
    }
    numberOpen = false;
    if (/\s/.test(char)) {
      if (!previousSpace) out += " ";
      previousSpace = true;
      continue;
    }
    previousSpace = false;
    if (dynamic && ["\"", "'", "`"].includes(char)) continue;
    out += char;
  }
  return out.trim().slice(0, 256);
}

function baselineCategoryFromRule(ruleId) {
  const prefix = String(ruleId || "").split("-")[0].toUpperCase();
  const categories = {
    AUTH: "ssh",
    SSH: "ssh",
    USER: "user",
    PRIV: "privilege",
    PERSIST: "persistence",
    PROC: "process",
    NET: "network",
    SERVICE: "network",
    FILE: "file_integrity",
    WEB: "web",
    DOCKER: "docker",
    ROOTKIT: "rootkit",
    CONFIG: "config_risk",
    SYS: "system",
    SYSTEM: "system",
  };
  return categories[prefix] || "system";
}

async function writeFindingReview(env, review) {
  await env.DB.prepare(`
    INSERT INTO finding_reviews (finding_id, verdict, note, reviewer, reviewed_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(finding_id) DO UPDATE SET
      verdict = excluded.verdict,
      note = excluded.note,
      reviewer = excluded.reviewer,
      reviewed_at = excluded.reviewed_at
  `).bind(review.finding_id, review.verdict, review.note, review.reviewer, review.reviewed_at).run();
}

async function writePanelReview(env, review) {
  await env.DB.prepare(`
    INSERT INTO panel_reviews (target_type, target_id, review_signature, verdict, note, reviewer, reviewed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(target_type, target_id) DO UPDATE SET
      review_signature = excluded.review_signature,
      verdict = excluded.verdict,
      note = excluded.note,
      reviewer = excluded.reviewer,
      reviewed_at = excluded.reviewed_at
  `).bind(
    review.target_type,
    review.target_id,
    review.review_signature || "",
    review.verdict,
    review.note,
    review.reviewer,
    review.reviewed_at,
  ).run();
}

function panelBlockStorageId(nodeId, block) {
  const source = String(block?.finding_id || "").trim()
    || [block?.rule_id || "", block?.blocked_at || "", block?.backend || ""].join(":");
  return `${nodeId}:${source}`;
}

function expandDatasetJsonColumns(table, rows) {
  if (!["probe_sources", "nodes"].includes(table)) return rows;
  return rows.map((row) => {
    const expanded = { ...row };
    if (table === "probe_sources") {
      expanded.categories = parseJsonField(expanded.categories_json, []);
      expanded.rule_ids = parseJsonField(expanded.rule_ids_json, []);
      delete expanded.categories_json;
      delete expanded.rule_ids_json;
    }
    if (table === "nodes") {
      expanded.metrics = parseJsonField(expanded.metrics_json, {});
      delete expanded.metrics_json;
    }
    return expanded;
  });
}

function shouldRedactDataset(dataset, role) {
  if (dataset.table === "probe_sources") return false;
  return !(dataset.sensitive && role === "admin");
}

function nodeStatusCounts(nodes) {
  const counts = { fresh: 0, stale: 0, offline: 0, retired: 0 };
  const now = new Date();
  for (const node of nodes || []) {
    const status = panelNodeStatus(node?.last_seen_at, now, node);
    counts[status] = (counts[status] || 0) + 1;
  }
  return counts;
}

function panelNodeStatus(lastSeenAt, now, node = {}) {
  const name = String(node?.node_name || "").trim().toLowerCase();
  const version = String(node?.agent_version || "").trim().toLowerCase();
  if (!name || name === "local-host" || version.includes("smoke")) return "retired";
  const seen = new Date(lastSeenAt || "");
  if (Number.isNaN(seen.getTime())) return "retired";
  const ageMinutes = Math.max(0, (now.getTime() - seen.getTime()) / 60000);
  if (ageMinutes > DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES) return "retired";
  if (ageMinutes > DEFAULT_FRESHNESS_THRESHOLD_MINUTES * 6) return "offline";
  if (ageMinutes > DEFAULT_FRESHNESS_THRESHOLD_MINUTES) return "stale";
  return "fresh";
}

async function runD1Batch(env, statements) {
  const chunkSize = 50;
  for (let index = 0; index < statements.length; index += chunkSize) {
    const chunk = statements.slice(index, index + chunkSize);
    if (!chunk.length) continue;
    if (typeof env.DB.batch === "function") {
      await env.DB.batch(chunk);
    } else {
      for (const statement of chunk) {
        await statement.run();
      }
    }
  }
}

function redactedIp() {
  return "redacted";
}

function redactPanelValue(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactIpText(value);
  if (Array.isArray(value)) return value.map((item) => redactPanelValue(item));
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => {
      if (String(key || "").toLowerCase() === "review_signature") return null;
      if (sensitiveNetworkKey(key)) return [key, redactedIp()];
      if (String(key || "").toLowerCase() === "node_name") return [key, publicNodeName(item)];
      return [key, redactPanelValue(item)];
    }).filter(Boolean));
  }
  return value;
}

function sensitiveNetworkKey(key) {
  const normalized = String(key || "").toLowerCase();
  return normalized !== "source_ip" && (normalized === "ip" || normalized.includes("_ip") || normalized.includes("addr"));
}

function redactIpText(value) {
  const text = String(value || "");
  const withoutIpv4 = text.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, (match) => {
    const candidate = match.split(":")[0];
    const parts = candidate.split(".").map((part) => Number(part));
    return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
      ? redactedIp()
      : match;
  });
  return withoutIpv4
    .split(/(\s+)/)
    .map((token) => redactIpToken(token))
    .join("");
}

function publicNodeName(value) {
  const text = redactIpText(value).trim();
  if (!text || text === redactedIp()) return "unnamed-node";
  return generatedPanelIdentity(text) ? "legacy-node" : text;
}

function generatedPanelIdentity(value) {
  const match = String(value || "").match(/^(node|host)-([0-9a-fA-F]{16})$/);
  return Boolean(match);
}

function redactIpToken(token) {
  if (!token || /^\s+$/.test(token)) return token;
  return tokenContainsIpLiteral(token) ? redactedIp() : token;
}

function tokenContainsIpLiteral(token) {
  const bracketed = token.match(/\[([0-9a-fA-F:.%]+)\](?::\d+)?/);
  if (bracketed && ipv6Like(bracketed[1])) return true;
  const candidate = token.replace(/^[,;"'({<\[]+|[,;"')}\]>.]+$/g, "");
  return ipv6Like(candidate);
}

function ipv6Like(value) {
  const candidate = String(value || "").split("%")[0];
  const colonCount = (candidate.match(/:/g) || []).length;
  if (colonCount < 2 || !/^[0-9a-fA-F:.]+$/.test(candidate)) return false;
  return candidate.includes("::") || colonCount >= 3 || /[a-fA-F]/.test(candidate);
}

function parseJsonField(value, fallback) {
  try {
    return JSON.parse(String(value || ""));
  } catch {
    return fallback;
  }
}

function requiredQuery(url, name) {
  const value = url.searchParams.get(name);
  if (!value) throwHttp(400, `missing_${name}`);
  return value;
}

function pageRequest(url) {
  const from = parsePanelTime(url.searchParams.get("from"));
  const to = parsePanelTime(url.searchParams.get("to"));
  if (from && to && from > to) throwHttp(400, "invalid_time_range");
  return {
    from,
    to,
    limit: clamp(Number(url.searchParams.get("limit") || DEFAULT_PAGE_LIMIT), 1, MAX_PAGE_LIMIT),
    offset: Math.max(0, Number(url.searchParams.get("offset") || 0) || 0),
  };
}

function parsePanelTime(value) {
  if (!value) return null;
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T00:00:00.000Z` : value;
  const timestamp = new Date(dateOnly);
  if (Number.isNaN(timestamp.getTime())) throwHttp(400, "invalid_time");
  return timestamp.toISOString();
}

function throwHttp(status, code) {
  const error = new Error(code);
  error.status = status;
  error.code = code;
  throw error;
}

function clamp(value, min, max) {
  if (!Number.isFinite(value)) return DEFAULT_PAGE_LIMIT;
  return Math.max(min, Math.min(max, Math.trunc(value)));
}

async function count(env, table) {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first();
  return Number(row?.count || 0);
}

async function countDistinct(env, table, column) {
  const row = await env.DB.prepare(`SELECT COUNT(DISTINCT ${column}) AS count FROM ${table}`).first();
  return Number(row?.count || 0);
}

async function countWhere(env, table, whereClause) {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${whereClause}`).first();
  return Number(row?.count || 0);
}

async function queryAll(env, sql) {
  const result = await env.DB.prepare(sql).all();
  return result.results || [];
}

async function countOptional(env, table) {
  try {
    return await count(env, table);
  } catch (error) {
    if (missingTableError(error, table)) return 0;
    throw error;
  }
}

async function countDistinctWhereOptional(env, table, column, whereClause) {
  try {
    const row = await env.DB.prepare(`SELECT COUNT(DISTINCT ${column}) AS count FROM ${table} WHERE ${whereClause}`).first();
    return Number(row?.count || 0);
  } catch (error) {
    if (missingTableError(error, table)) return 0;
    throw error;
  }
}

async function queryAllOptional(env, sql, table) {
  try {
    return await queryAll(env, sql);
  } catch (error) {
    if (missingTableError(error, table)) return [];
    throw error;
  }
}

function missingTableError(error, table) {
  return String(error?.message || error || "").toLowerCase().includes(`no such table: ${table.toLowerCase()}`);
}

function missingColumnError(error, column) {
  const message = String(error?.message || error || "").toLowerCase();
  const name = column.toLowerCase();
  return message.includes(`no such column: ${name}`) || message.includes(`no column named ${name}`);
}

function safeInternalErrorCode(error) {
  const message = String(error?.message || error || "").toLowerCase();
  if (message.includes("no such table")) return "storage_schema_missing";
  if (message.includes("no such column")) return "storage_schema_mismatch";
  if (error instanceof SyntaxError || message.includes("json")) return "payload_parse_error";
  if (message.includes("constraint")) return "storage_constraint_error";
  if (message.includes("bind") || message.includes("d1_type_error")) return "storage_bind_error";
  if (message.includes("d1") || message.includes("sqlite")) return "storage_error";
  if (message.includes("fetch")) return "network_error";
  return "runtime_error";
}

function secretForNode(env, nodeId) {
  if (env.PANEL_NODE_SECRETS) {
    const map = JSON.parse(env.PANEL_NODE_SECRETS);
    if (map[nodeId]) return map[nodeId];
  }
  return env.PANEL_SHARED_SECRET || "";
}

function operatorTokens(env) {
  return [env.PANEL_OPERATOR_TOKEN, env.PANEL_VIEW_TOKEN]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
}

function adminToken(env) {
  return String(env.PANEL_ADMIN_TOKEN || "").trim();
}

function publicEnabled(env) {
  return ["1", "true", "yes", "on"].includes(String(env.PANEL_PUBLIC_ENABLED || "").trim().toLowerCase());
}

function publicPages(env) {
  const value = String(env.PANEL_PUBLIC_PAGES === undefined ? "overview,probe_sources,nodes" : env.PANEL_PUBLIC_PAGES);
  return [...new Set(value.split(",").map((page) => page.trim().toLowerCase()).filter(Boolean))];
}

function adminPath(env) {
  const raw = String(env.PANEL_ADMIN_PATH || DEFAULT_ADMIN_PATH).trim() || DEFAULT_ADMIN_PATH;
  const withSlash = raw.startsWith("/") ? raw : `/${raw}`;
  const normalized = withSlash.replace(/\/+$/, "");
  return normalized || DEFAULT_ADMIN_PATH;
}

function panelThemes(env) {
  const seen = new Set();
  const themes = String(env.PANEL_THEMES || DEFAULT_THEMES)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [rawId, rawLabel] = entry.includes(":") ? entry.split(/:(.*)/s) : [entry, entry];
      const id = String(rawId || "").replace(/[^a-zA-Z0-9_-]/g, "");
      const label = String(rawLabel || id).trim() || id;
      return { id, label };
    })
    .filter((theme) => theme.id && !seen.has(theme.id) && seen.add(theme.id));
  return themes.length ? themes : [{ id: "default", label: "Default" }];
}

function publicAccessEnabled(env) {
  return publicEnabled(env) || publicPages(env).length > 0;
}

function datasetMinimumRole(dataset, env) {
  return publicPages(env).includes(dataset.pageId) ? "public" : dataset.minRole || "operator";
}

function panelAuth(request, env, minimumRole) {
  const role = resolvePanelRole(request, env);
  if (!role) {
    const hasAnyToken = Boolean(operatorTokens(env).length || adminToken(env));
    const error = hasAnyToken || publicAccessEnabled(env)
      ? json({ error: "missing_or_invalid_panel_token", detail: "missing_or_invalid_panel_token" }, 401)
      : json({ error: "panel_view_token_not_configured", detail: "panel_view_token_not_configured" }, 403);
    return { error, role: "public" };
  }
  if (!roleAllows(role, minimumRole)) {
    return {
      error: json({ error: "insufficient_panel_role", detail: "insufficient_panel_role" }, 403),
      role,
    };
  }
  return { error: null, role };
}

function resolvePanelRole(request, env, options = {}) {
  const actual = bearerToken(request.headers.get("authorization") || "")
    || String(request.headers.get("x-vps-sentinel-view-token") || "").trim();
  const admin = adminToken(env);
  if (admin && actual && timingSafeEqual(admin, actual)) return "admin";
  if (actual && operatorTokens(env).some((token) => timingSafeEqual(token, actual))) return "operator";
  if (!actual && (publicAccessEnabled(env) || options.allowAnonymous)) return "public";
  return null;
}

function roleAllows(role, minimumRole) {
  return (ROLE_LEVELS[role] ?? 0) >= (ROLE_LEVELS[minimumRole] ?? 0);
}

function viewAuthError(request, env) {
  return panelAuth(request, env, "operator").error;
}

function adminAuthError(request, env) {
  if (!adminToken(env)) return json({ error: "panel_admin_token_not_configured", detail: "panel_admin_token_not_configured" }, 403);
  return panelAuth(request, env, "admin").error;
}

function bearerToken(value) {
  const [scheme, ...rest] = value.split(" ");
  const token = rest.join(" ").trim();
  return scheme?.toLowerCase() === "bearer" && token ? token : "";
}

function requiredHeader(request, name) {
  const value = request.headers.get(name);
  if (!value) throwHttp(401, `missing_header:${name}`);
  return value;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return hex(new Uint8Array(digest));
}

async function hmacSha256Hex(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return hex(new Uint8Array(signature));
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return diff === 0;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);
  const origin = request.headers.get("origin") || "";
  const allowedOrigin = String(env.PANEL_CORS_ORIGIN || "").trim();
  if (allowedOrigin && allowedOrigin !== "*" && allowedOrigin === origin) {
    headers.set("access-control-allow-origin", origin);
    headers.set("vary", "Origin");
    headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
    headers.set("access-control-allow-headers", "authorization,content-type,x-vps-sentinel-node-name,x-vps-sentinel-node,x-vps-sentinel-payload-encoding,x-vps-sentinel-timestamp,x-vps-sentinel-nonce,x-vps-sentinel-body-sha256,x-vps-sentinel-signature,x-vps-sentinel-view-token");
  }
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
