# Fleet Panel

The fleet panel is an optional push-mode dashboard. Agents keep local-first detection and only upload signed, bounded, privacy-redacted summaries when `[panel].enabled = true`.

## Access Model

The panel has two browser access levels:

| Level | Purpose |
| --- | --- |
| Public | Optional unauthenticated pages such as overview, blocklist, and nodes. Public APIs never expose raw evidence, node IDs, hostnames, paths, command lines, or generic internal network fields. |
| Private | A single `PANEL_TOKEN` unlocks private details, reviews, audit logs, active-response details, and management pages. |

Agent ingest uses a separate trust boundary: `panel.secret` on the agent must match `PANEL_SHARED_SECRET` or a node-specific value in `PANEL_NODE_SECRETS`.

## Telemetry Shape

Agent payloads use `node_name` as the display identity and strip node IDs, host IDs, hostnames, raw logs, raw evidence, paths, command lines, and general internal network fields before upload. The panel receiver performs a second redaction pass before storage.

Node country/city display metadata is not configured on the agent. The panel receiver fills it automatically from trusted reverse-proxy metadata when available, such as Cloudflare geolocation headers. It does not require the agent to upload public IPs.

## Realtime Behavior

The self-hosted Rust panel supports WebSocket refresh events through `/api/v1/stream-ticket` and `/api/v1/stream`.

Cloudflare Worker mode currently exposes the same API and D1 storage but returns `stream_unavailable` for WebSocket tickets. The UI detects this and switches to a non-reconnecting fallback state instead of repeatedly trying to reconnect.

## More Documentation

- Deployment: [panel-deployment.md](panel-deployment.md)
- Architecture: [panel-architecture.md](panel-architecture.md)
- Theme extensions: [panel-themes.md](panel-themes.md)
- Chinese documentation: [panel.zh-CN.md](panel.zh-CN.md)
