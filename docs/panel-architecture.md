# Panel Architecture

## Components

| Component | Responsibility |
| --- | --- |
| Agent panel client | Builds a bounded telemetry envelope, strips sensitive host identity, signs it with HMAC, and queues failed uploads locally. |
| Receiver | Verifies signature, nonce, timestamp, and payload size; enriches non-sensitive node location from trusted proxy metadata; stores sanitized rows. |
| Repository | Provides bounded, paginated read models for SQLite, PostgreSQL, MySQL, or Cloudflare D1. |
| Web UI | Reads fixed API datasets, applies client-side privacy guards, and updates changed datasets without full-page reloads. |

## Trust Boundaries

`PANEL_SHARED_SECRET` and `PANEL_NODE_SECRETS` are ingest credentials. `PANEL_TOKEN` is the only browser private-access token. Notification tokens and Cloudflare deployment credentials are separate and must never be committed.

## Realtime Strategy

Self-hosted Rust uses WebSocket tickets so browser tokens are not placed in WebSocket URLs. Cloudflare Worker deployments currently use REST refresh fallback because a plain Worker has no durable broadcast state; Durable Objects can be added later without changing the agent protocol.

## Data Safety

Panel APIs are allowlisted by dataset and column. Public pages expose only aggregate or explicitly public attacker-source data. Private pages can show review and response detail, but node IDs, host IDs, hostnames, and review signatures remain hidden from browser lists.
