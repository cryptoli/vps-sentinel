const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const SIGNATURE_WINDOW_SECONDS = 300;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "OPTIONS") {
        return withCors(new Response(null, { status: 204 }));
      }
      if (request.method === "POST" && url.pathname === "/api/v1/ingest") {
        return withCors(await ingest(request, env));
      }
      if (request.method === "GET" && url.pathname === "/api/v1/summary") {
        return withCors(json(await summary(env)));
      }
      if (request.method === "GET" && url.pathname === "/api/v1/nodes") {
        return withCors(json(await queryAll(env, "SELECT * FROM nodes ORDER BY last_seen_at DESC LIMIT 200")));
      }
      if (request.method === "GET" && url.pathname === "/api/v1/findings") {
        return withCors(json(await queryAll(env, "SELECT * FROM findings ORDER BY timestamp DESC LIMIT 300")));
      }
      if (request.method === "GET" && url.pathname === "/api/v1/incidents") {
        return withCors(json(await queryAll(env, "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 200")));
      }
      if (request.method === "GET" && url.pathname === "/api/v1/baseline-drifts") {
        return withCors(json(await queryAll(env, "SELECT * FROM baseline_drifts ORDER BY timestamp DESC LIMIT 300")));
      }
      if (request.method === "GET" && url.pathname === "/api/v1/active-blocks") {
        return withCors(json(await queryAll(env, "SELECT * FROM active_blocks WHERE expired = 0 ORDER BY blocked_at DESC LIMIT 300")));
      }
      return withCors(json({ error: "not_found" }, 404));
    } catch (error) {
      return withCors(json({ error: "internal_error", detail: String(error?.message || error) }, 500));
    }
  },
};

async function ingest(request, env) {
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.byteLength > Number(env.PANEL_MAX_BODY_BYTES || 1048576)) {
    return json({ error: "body_too_large" }, 413);
  }
  const nodeId = requiredHeader(request, "x-vps-sentinel-node");
  const timestamp = Number(requiredHeader(request, "x-vps-sentinel-timestamp"));
  const nonce = requiredHeader(request, "x-vps-sentinel-nonce");
  const bodyHash = requiredHeader(request, "x-vps-sentinel-body-sha256");
  const signature = requiredHeader(request, "x-vps-sentinel-signature");
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > SIGNATURE_WINDOW_SECONDS) {
    return json({ error: "signature_timestamp_out_of_window" }, 401);
  }
  if (!nonce.startsWith(`${nodeId}:`)) {
    return json({ error: "nonce_node_mismatch" }, 401);
  }
  const actualHash = await sha256Hex(body);
  if (!timingSafeEqual(actualHash, bodyHash)) {
    return json({ error: "body_hash_mismatch" }, 401);
  }
  const secret = secretForNode(env, nodeId);
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
    .bind(nonce, nodeId, now + SIGNATURE_WINDOW_SECONDS)
    .run();

  const payload = JSON.parse(new TextDecoder().decode(body));
  if (payload?.schema_version !== 1 || payload?.node?.node_id !== nodeId) {
    return json({ error: "invalid_payload" }, 400);
  }
  await persistPayload(env, payload);
  return json({ ok: true, message_id: payload.message_id });
}

async function persistPayload(env, payload) {
  const receivedAt = new Date().toISOString();
  const node = payload.node;
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
    node.node_id,
    node.node_name,
    node.host_id,
    node.hostname || "",
    node.agent_version,
    node.privacy_mode,
    JSON.stringify(node.enabled_features || []),
    JSON.stringify(node.storage || {}),
    payload.sent_at,
    receivedAt,
  ).run();
  await env.DB.prepare("INSERT OR REPLACE INTO heartbeats (message_id, node_id, sent_at, received_at, scan_json) VALUES (?, ?, ?, ?, ?)")
    .bind(payload.message_id, node.node_id, payload.sent_at, receivedAt, JSON.stringify(payload.scan || {}))
    .run();

  for (const finding of payload.findings || []) {
    await env.DB.prepare(`
      INSERT OR REPLACE INTO findings
        (id, node_id, rule_id, title, severity, confidence, category, subject, timestamp, dedup_key, evidence_json, impact_json, recommendations_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      finding.id,
      node.node_id,
      finding.rule_id,
      finding.title,
      finding.severity,
      finding.confidence,
      finding.category,
      finding.subject,
      finding.timestamp,
      finding.dedup_key,
      JSON.stringify(finding.evidence || []),
      JSON.stringify(finding.impact || []),
      JSON.stringify(finding.recommendations || []),
      receivedAt,
    ).run();
  }

  for (const incident of payload.incidents || []) {
    await env.DB.prepare(`
      INSERT OR REPLACE INTO incidents
        (id, node_id, title, severity, score, first_seen, last_seen, summary, payload_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      incident.id,
      node.node_id,
      incident.title,
      incident.severity,
      Number(incident.score || 0),
      incident.first_seen,
      incident.last_seen,
      incident.summary || "",
      JSON.stringify(incident),
      receivedAt,
    ).run();
  }

  for (const drift of payload.baseline_drifts || []) {
    const id = `${node.node_id}:${drift.finding_id || drift.rule_id}:${drift.subject}:${drift.timestamp}`;
    await env.DB.prepare(`
      INSERT OR REPLACE INTO baseline_drifts
        (id, node_id, finding_id, rule_id, severity, subject, timestamp, tier, score, review_action, reasons_json, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      node.node_id,
      drift.finding_id || "",
      drift.rule_id,
      drift.severity,
      drift.subject,
      drift.timestamp,
      drift.tier,
      drift.score ?? null,
      drift.review_action,
      JSON.stringify(drift.reasons || []),
      receivedAt,
    ).run();
  }

  for (const block of payload.active_blocks || []) {
    const id = `${node.node_id}:${block.ip}`;
    await env.DB.prepare(`
      INSERT OR REPLACE INTO active_blocks
        (id, node_id, ip, rule_id, finding_id, reason, backend, blocked_at, expires_at, expired, firewall_present, received_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      node.node_id,
      block.ip,
      block.rule_id,
      block.finding_id,
      block.reason,
      block.backend,
      block.blocked_at,
      block.expires_at || null,
      block.expired ? 1 : 0,
      block.firewall_present === null || block.firewall_present === undefined ? null : (block.firewall_present ? 1 : 0),
      receivedAt,
    ).run();
  }
}

async function summary(env) {
  const [nodes, findings, incidents, drifts, blocks] = await Promise.all([
    count(env, "nodes"),
    count(env, "findings"),
    count(env, "incidents"),
    count(env, "baseline_drifts"),
    countWhere(env, "active_blocks", "expired = 0"),
  ]);
  const bySeverity = await queryAll(env, "SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity");
  return { nodes, findings, incidents, baseline_drifts: drifts, active_blocks: blocks, by_severity: bySeverity };
}

async function count(env, table) {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first();
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

function secretForNode(env, nodeId) {
  if (env.PANEL_NODE_SECRETS) {
    const map = JSON.parse(env.PANEL_NODE_SECRETS);
    if (map[nodeId]) return map[nodeId];
  }
  return env.PANEL_SHARED_SECRET || "";
}

function requiredHeader(request, name) {
  const value = request.headers.get(name);
  if (!value) throw new Error(`missing header ${name}`);
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

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  headers.set("access-control-allow-headers", "content-type,x-vps-sentinel-node,x-vps-sentinel-timestamp,x-vps-sentinel-nonce,x-vps-sentinel-body-sha256,x-vps-sentinel-signature");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
