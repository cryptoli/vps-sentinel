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

const DATASETS = {
  "/api/v1/nodes": {
    minRole: "public",
    table: "nodes",
    orderColumn: "last_seen_at",
    columns: ["last_seen_at", "node_name", "agent_version", "privacy_mode"],
  },
  "/api/v1/findings": {
    minRole: "operator",
    table: "findings",
    orderColumn: "timestamp",
    columns: ["id", "timestamp", "node_id AS node_name", "severity", "rule_id", "category", "subject", "title"],
  },
  "/api/v1/incidents": {
    minRole: "operator",
    table: "incidents",
    orderColumn: "last_seen",
    columns: ["id", "last_seen", "node_id AS node_name", "severity", "score", "title", "summary"],
  },
  "/api/v1/baseline-drifts": {
    minRole: "operator",
    table: "baseline_drifts",
    orderColumn: "timestamp",
    columns: ["timestamp", "node_id AS node_name", "severity", "rule_id", "tier", "subject", "review_action"],
  },
  "/api/v1/active-blocks": {
    minRole: "operator",
    sensitive: true,
    table: "active_blocks",
    orderColumn: "blocked_at",
    activeFilter: "expired = 0",
    columns: ["blocked_at", "node_id AS node_name", "ip", "rule_id", "backend", "reason", "expires_at"],
  },
  "/api/v1/probe-sources": {
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
      if (request.method === "POST" && url.pathname === "/api/v1/ingest") {
        return withCors(await ingest(request, env), request, env);
      }
      if (request.method === "GET" && url.pathname === "/api/v1/settings") {
        const role = resolvePanelRole(request, env, { allowAnonymous: true });
        return withCors(json({
          theme: env.PANEL_THEME || "default",
          auth_required: !publicEnabled(env),
          auth_configured: Boolean(viewToken(env) || adminToken(env)),
          operator_configured: Boolean(viewToken(env)),
          admin_configured: Boolean(adminToken(env)),
          public_enabled: publicEnabled(env),
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
      if (request.method === "GET" && DATASETS[url.pathname]) {
        const dataset = DATASETS[url.pathname];
        const auth = panelAuth(request, env, dataset.minRole || "operator");
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
      return withCors(json({ error: "internal_error", detail: "internal_error" }, 500), request, env);
    }
  },
};

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

  const payload = JSON.parse(new TextDecoder().decode(body));
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
  await env.DB.prepare(`
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
    payload.sent_at,
    receivedAt,
  ).run();
  await env.DB.prepare("INSERT OR REPLACE INTO heartbeats (message_id, node_id, sent_at, received_at, scan_json) VALUES (?, ?, ?, ?, ?)")
    .bind(payload.message_id, nodeName, payload.sent_at, receivedAt, JSON.stringify(redactPanelValue(payload.scan || {})))
    .run();

  for (const finding of payload.findings || []) {
    const evidence = redactPanelValue(finding.evidence || []);
    const impact = redactPanelValue(finding.impact || []);
    const recommendations = redactPanelValue(finding.recommendations || []);
    await env.DB.prepare(`
      INSERT OR REPLACE INTO findings
        (id, node_id, rule_id, title, severity, confidence, category, subject, timestamp, dedup_key, evidence_json, impact_json, recommendations_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      finding.id,
      nodeName,
      finding.rule_id,
      redactIpText(finding.title || ""),
      finding.severity,
      finding.confidence,
      finding.category,
      redactIpText(finding.subject || ""),
      finding.timestamp,
      redactIpText(finding.dedup_key || ""),
      JSON.stringify(evidence),
      JSON.stringify(impact),
      JSON.stringify(recommendations),
      receivedAt,
    ).run();
  }

  for (const incident of payload.incidents || []) {
    const incidentPayload = redactPanelValue(incident);
    await env.DB.prepare(`
      INSERT OR REPLACE INTO incidents
        (id, node_id, title, severity, score, first_seen, last_seen, summary, payload_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      incident.id,
      nodeName,
      redactIpText(incident.title || ""),
      incident.severity,
      Number(incident.score || 0),
      incident.first_seen,
      incident.last_seen,
      redactIpText(incident.summary || ""),
      JSON.stringify(incidentPayload),
      receivedAt,
    ).run();
  }

  for (const drift of payload.baseline_drifts || []) {
    const subject = redactIpText(drift.subject || "");
    const id = `${nodeName}:${drift.finding_id || drift.rule_id}:${subject}:${drift.timestamp}`;
    await env.DB.prepare(`
      INSERT OR REPLACE INTO baseline_drifts
        (id, node_id, finding_id, rule_id, severity, subject, timestamp, tier, score, review_action, reasons_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      nodeName,
      drift.finding_id || "",
      drift.rule_id,
      drift.severity,
      subject,
      drift.timestamp,
      drift.tier,
      drift.score ?? null,
      drift.review_action,
      JSON.stringify(redactPanelValue(drift.reasons || [])),
      receivedAt,
    ).run();
  }

  for (const block of payload.active_blocks || []) {
    const id = panelBlockStorageId(nodeName, block);
    await env.DB.prepare(`
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
    ).run();
  }

  for (const source of payload.probe_sources || []) {
    try {
      await upsertProbeSource(env, nodeName, source, receivedAt);
    } catch (error) {
      if (missingTableError(error, "probe_sources")) {
        console.warn("probe_sources table is missing; apply panel/cloudflare/schema.sql to enable probe-source blacklist storage");
        break;
      }
      throw error;
    }
  }
}

async function upsertProbeSource(env, nodeName, source, receivedAt) {
  const sourceIp = String(source?.source_ip || "").trim();
  if (!sourceIp) return;
  const id = `${nodeName}:${sourceIp}`;
  const existing = await env.DB.prepare(
    "SELECT first_seen, last_seen, seen_count, categories_json, rule_ids_json FROM probe_sources WHERE id = ?",
  ).bind(id).first();
  const merged = mergeProbeSource(existing, source, receivedAt);
  await env.DB.prepare(`
    INSERT OR REPLACE INTO probe_sources
      (id, node_id, source_ip, ip_version, network_prefix, country, asn, organization,
       first_seen, last_seen, seen_count, categories_json, rule_ids_json, latest_reason,
       block_status, block_reason, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    nodeName,
    sourceIp,
    String(source.ip_version || "unknown"),
    String(source.network_prefix || "unknown"),
    String(source.country || "unknown"),
    String(source.asn || "unknown"),
    redactIpText(source.organization || "unknown"),
    merged.first_seen,
    merged.last_seen,
    merged.seen_count,
    JSON.stringify(merged.categories),
    JSON.stringify(merged.rule_ids),
    redactIpText(source.latest_reason || ""),
    String(source.block_status || "observed"),
    redactIpText(source.block_reason || ""),
    receivedAt,
  ).run();
}

function mergeProbeSource(existing, source, fallbackTime) {
  const firstSeen = String(source.first_seen || fallbackTime);
  const lastSeen = String(source.last_seen || firstSeen);
  const existingFirst = existing?.first_seen ? String(existing.first_seen) : firstSeen;
  const existingLast = existing?.last_seen ? String(existing.last_seen) : lastSeen;
  return {
    first_seen: minTimeString(existingFirst, firstSeen),
    last_seen: maxTimeString(existingLast, lastSeen),
    seen_count: Number(existing?.seen_count || 0) + Math.max(1, Number(source.seen_count || 1) || 1),
    categories: mergeStringSets(parseJsonField(existing?.categories_json, []), source.categories || []),
    rule_ids: mergeStringSets(parseJsonField(existing?.rule_ids_json, []), source.rule_ids || []),
  };
}

async function summary(env, role = "public") {
  const [nodes, findings, incidents, drifts, blocks, probeSources, bySeverity, byCategory, byBlockStatus, nodeRows] = await Promise.all([
    countDistinct(env, "nodes", "node_name"),
    count(env, "findings"),
    count(env, "incidents"),
    count(env, "baseline_drifts"),
    countWhere(env, "active_blocks", "expired = 0"),
    countOptional(env, "probe_sources"),
    queryAll(env, "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity"),
    queryAll(env, "SELECT category, COUNT(*) AS count FROM findings GROUP BY category"),
    queryAllOptional(env, "SELECT block_status, COUNT(*) AS count FROM probe_sources GROUP BY block_status", "probe_sources"),
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

async function queryPage(env, dataset, url, role = "operator") {
  const page = pageRequest(url);
  const values = [];
  const parts = [];
  if (dataset.activeFilter) parts.push(dataset.activeFilter);
  if (page.from) {
    values.push(page.from);
    parts.push(`${dataset.orderColumn} >= ?`);
  }
  if (page.to) {
    values.push(page.to);
    parts.push(`${dataset.orderColumn} <= ?`);
  }
  const whereSql = parts.length ? ` WHERE ${parts.join(" AND ")}` : "";
  try {
    const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${dataset.table}${whereSql}`)
      .bind(...values)
      .first();
    const result = await env.DB.prepare(
      `SELECT ${dataset.columns.join(", ")} FROM ${dataset.table}${whereSql} ORDER BY ${dataset.orderColumn} DESC LIMIT ? OFFSET ?`,
    ).bind(...values, page.limit, page.offset).all();
    const items = expandDatasetJsonColumns(dataset.table, result.results || []);
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

async function findingDetail(env, url) {
  const id = requiredQuery(url, "id");
  const row = await env.DB.prepare(`
    SELECT id, node_id AS node_name, rule_id, title, severity, confidence, category, subject, timestamp, dedup_key,
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
  row.review = await env.DB.prepare(
    "SELECT finding_id, verdict, note, reviewer, reviewed_at FROM finding_reviews WHERE finding_id = ?",
  ).bind(id).first();
  return redactPanelValue(row);
}

async function incidentDetail(env, url) {
  const id = requiredQuery(url, "id");
  const row = await env.DB.prepare(`
    SELECT id, node_id AS node_name, title, severity, score, first_seen, last_seen, summary, payload_json, received_at
    FROM incidents
    WHERE id = ?
  `).bind(id).first();
  if (!row) throwHttp(404, "incident_not_found");
  row.payload = parseJsonField(row.payload_json, null);
  delete row.payload_json;
  return redactPanelValue(row);
}

async function findingReview(request, env) {
  const payload = await request.json();
  const review = normalizeFindingReview(payload);
  const exists = await env.DB.prepare("SELECT id FROM findings WHERE id = ?").bind(review.finding_id).first();
  if (!exists) throwHttp(404, "finding_not_found");
  await env.DB.prepare(`
    INSERT INTO finding_reviews (finding_id, verdict, note, reviewer, reviewed_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(finding_id) DO UPDATE SET
      verdict = excluded.verdict,
      note = excluded.note,
      reviewer = excluded.reviewer,
      reviewed_at = excluded.reviewed_at
  `).bind(review.finding_id, review.verdict, review.note, review.reviewer, review.reviewed_at).run();
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
  return { ok: true, finding_id: review.finding_id };
}

function normalizeFindingReview(payload) {
  const findingId = String(payload?.finding_id || "").trim();
  if (!findingId || findingId.length > 191) throwHttp(400, "invalid_finding_id");
  const verdict = String(payload?.verdict || "").trim();
  if (!["false_positive", "confirmed", "needs_review"].includes(verdict)) {
    throwHttp(400, "invalid_review_verdict");
  }
  return {
    finding_id: findingId,
    verdict,
    note: String(payload?.note || "").trim().slice(0, 1000),
    reviewer: String(payload?.reviewer || "").trim().slice(0, 128),
    reviewed_at: new Date().toISOString(),
  };
}

function panelBlockStorageId(nodeId, block) {
  const source = String(block?.finding_id || "").trim()
    || [block?.rule_id || "", block?.blocked_at || "", block?.backend || ""].join(":");
  return `${nodeId}:${source}`;
}

function expandDatasetJsonColumns(table, rows) {
  if (table !== "probe_sources") return rows;
  return rows.map((row) => {
    const expanded = { ...row };
    expanded.categories = parseJsonField(expanded.categories_json, []);
    expanded.rule_ids = parseJsonField(expanded.rule_ids_json, []);
    delete expanded.categories_json;
    delete expanded.rule_ids_json;
    return expanded;
  });
}

function shouldRedactDataset(dataset, role) {
  return !(dataset.sensitive && role === "admin");
}

function nodeStatusCounts(nodes) {
  const counts = { fresh: 0, stale: 0, offline: 0, retired: 0 };
  const now = new Date();
  for (const node of nodes || []) {
    const status = panelNodeStatus(node?.last_seen_at, now);
    counts[status] = (counts[status] || 0) + 1;
  }
  return Object.entries(counts).map(([status, count]) => ({ status, count }));
}

function panelNodeStatus(lastSeenAt, now) {
  const seen = new Date(lastSeenAt || "");
  if (Number.isNaN(seen.getTime())) return "retired";
  const ageMinutes = Math.max(0, (now.getTime() - seen.getTime()) / 60000);
  if (ageMinutes > DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES) return "retired";
  if (ageMinutes > DEFAULT_FRESHNESS_THRESHOLD_MINUTES * 6) return "offline";
  if (ageMinutes > DEFAULT_FRESHNESS_THRESHOLD_MINUTES) return "stale";
  return "fresh";
}

function mergeStringSets(left, right) {
  return [...new Set([...(left || []), ...(right || [])]
    .map((item) => String(item || "").trim())
    .filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
}

function minTimeString(left, right) {
  return new Date(left).getTime() <= new Date(right).getTime() ? left : right;
}

function maxTimeString(left, right) {
  return new Date(left).getTime() >= new Date(right).getTime() ? left : right;
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
      if (sensitiveNetworkKey(key)) return [key, redactedIp()];
      if (String(key || "").toLowerCase() === "node_name") return [key, publicNodeName(item)];
      return [key, redactPanelValue(item)];
    }));
  }
  return value;
}

function sensitiveNetworkKey(key) {
  const normalized = String(key || "").toLowerCase();
  return normalized === "ip" || normalized.includes("_ip") || normalized.includes("addr");
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

function secretForNode(env, nodeId) {
  if (env.PANEL_NODE_SECRETS) {
    const map = JSON.parse(env.PANEL_NODE_SECRETS);
    if (map[nodeId]) return map[nodeId];
  }
  return env.PANEL_SHARED_SECRET || "";
}

function viewToken(env) {
  return String(env.PANEL_VIEW_TOKEN || env.PANEL_OPERATOR_TOKEN || "").trim();
}

function adminToken(env) {
  return String(env.PANEL_ADMIN_TOKEN || "").trim();
}

function publicEnabled(env) {
  return ["1", "true", "yes", "on"].includes(String(env.PANEL_PUBLIC_ENABLED || "").trim().toLowerCase());
}

function panelAuth(request, env, minimumRole) {
  const role = resolvePanelRole(request, env);
  if (!role) {
    const hasAnyToken = Boolean(viewToken(env) || adminToken(env));
    const error = hasAnyToken || publicEnabled(env)
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
  const view = viewToken(env);
  if (admin && actual && timingSafeEqual(admin, actual)) return "admin";
  if (view && actual && timingSafeEqual(view, actual)) return "operator";
  if (!actual && (publicEnabled(env) || options.allowAnonymous)) return "public";
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
    headers.set("access-control-allow-headers", "authorization,content-type,x-vps-sentinel-node-name,x-vps-sentinel-node,x-vps-sentinel-timestamp,x-vps-sentinel-nonce,x-vps-sentinel-body-sha256,x-vps-sentinel-signature,x-vps-sentinel-view-token");
  }
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("cache-control", "no-store");
  headers.set("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
