# Panel Architecture

## Components

| Component | Responsibility |
| --- | --- |
| Agent panel client | Builds a bounded telemetry envelope, strips sensitive host identity and raw evidence, adds safe display metadata, signs it with HMAC, and queues failed uploads locally. |
| Receiver | Verifies signature, nonce, timestamp, and payload size; merges non-sensitive node location from agent metadata, trusted proxy metadata, or optional local GeoIP databases; stores sanitized rows. |
| Repository | Provides bounded, paginated read models for SQLite, PostgreSQL, MySQL, or Cloudflare D1. |
| Web UI | Reads fixed API datasets, applies client-side privacy guards, and updates changed datasets without full-page reloads. |

## Shared Contract

The self-hosted Rust panel, Cloudflare Worker, and frontend page definitions share `panel/shared/contract.json`. Run `node scripts/generate-panel-contract.mjs` to generate:

- `crates/sentinel-panel/src/panel_contract.rs`
- `panel/cloudflare/panel-contract.generated.js`
- `panel/ui/src/lib/panel-contract.generated.ts`
- `panel/shared/contract.env`

Datasets, public pages, default management path, public blocklist redaction fields, and page columns are generated from this contract. CI runs `node scripts/generate-panel-contract.mjs --check` to prevent implementation drift.

## Trust Boundaries

`PANEL_SHARED_SECRET` and `PANEL_NODE_SECRETS` are ingest credentials. `PANEL_TOKEN` is the only browser private-access token. Notification tokens and Cloudflare deployment credentials are separate credentials stored in local config, Worker secrets, or systemd environment files.

## Realtime Strategy

Self-hosted Rust uses WebSocket tickets so browser tokens are not placed in WebSocket URLs. Cloudflare Worker deployments currently use REST refresh fallback because a plain Worker has no durable broadcast state; Durable Objects can be added later without changing the agent protocol.

## Data Safety

Panel APIs are allowlisted by dataset and column. Public pages expose only aggregate or explicitly public attacker-source data. Private pages can show review and response detail. Node IDs, host IDs, public server IPs, raw paths, command lines, secrets, and review signatures remain hidden from browser lists; sanitized non-IP hostnames are only available on private node datasets.
