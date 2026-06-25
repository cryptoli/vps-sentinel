# Fleet Panel

The fleet panel is an optional push-mode dashboard. Agents keep local-first detection and only upload signed, bounded, privacy-redacted summaries when `[panel].enabled = true`.

## Access Model

The panel has two browser access levels:

| Level | Purpose |
| --- | --- |
| Public | Optional unauthenticated pages such as overview, blocklist, and nodes. Public APIs never expose raw evidence, node IDs, host IDs, protected-node hostnames, paths, command lines, or generic internal network fields. |
| Private | A single `PANEL_TOKEN` unlocks private details, reviews, audit logs, active-response details, and management pages. |

Agent ingest uses a separate trust boundary: `panel.secret` on the agent must match `PANEL_SHARED_SECRET` or a node-specific value in `PANEL_NODE_SECRETS`.

## Telemetry Shape

Agent payloads use `node_name` as the display identity and strip node IDs, host IDs, public server IPs, raw logs, raw evidence, paths, command lines, and general internal network fields before upload. The panel receiver performs a second redaction pass before storage.

Safe display fields may be uploaded: a sanitized hostname that is not an IP address, plus country, region, and city. Agent-side node-location detection derives those display fields from a trusted HTTPS endpoint and discards the public IP. Cloudflare panels can also use Cloudflare request geolocation; self-hosted panels can optionally use MaxMind/DB-IP MMDB files for real remote request IPs.

Node status is computed from the last successful report: fresh within 30 minutes, stale after 30 minutes, offline after 90 minutes, and retired after 12 hours or when the node record is a placeholder.

## Realtime Behavior

The self-hosted Rust panel supports WebSocket refresh events through `/api/v1/stream-ticket` and `/api/v1/stream`.

Cloudflare Worker mode currently exposes the same API and D1 storage but returns `stream_unavailable` for WebSocket tickets. The UI detects this and switches to a non-reconnecting fallback state instead of repeatedly trying to reconnect.

## More Documentation

- Deployment: [panel-deployment.md](panel-deployment.md)
- Architecture: [panel-architecture.md](panel-architecture.md)
- Theme extensions: [panel-themes.md](panel-themes.md)
- Chinese documentation: [panel.zh-CN.md](panel.zh-CN.md)
