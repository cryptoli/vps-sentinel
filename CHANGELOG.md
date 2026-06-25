# Changelog

## Unreleased

## 0.3.0

- Fleet panel: added the Rust self-hosted panel and Cloudflare Worker/D1 panel, Next.js/React UI, public/private access model, self-hosted WebSocket refresh, Cloudflare REST fallback, review flows, blacklist attribution, node metrics, explicit fresh/stale/offline status windows, and theme extension hooks.
- Shared panel contract: Rust panel, Cloudflare Worker, frontend page definitions, deployment defaults, public pages, dataset columns, and public blacklist redaction now come from `panel/shared/contract.json` with generated code and CI drift checks.
- Detection intelligence: added bounded evidence scoring, semantic baseline-drift scoring/review actions, scan-window timeline correlation, explainable attack fingerprint clusters, auditd behavior rules, local behavior profiling, GPU compute signals, layered active-response escalation, and external TOML rule validation.
- Privacy and access: simplified panel access to a single `PANEL_TOKEN`, random management path generation, public `settings` path protection, public blacklist node-name redaction, optional GeoIP enrichment, and agent-side telemetry that avoids uploading public server IPs, node IDs, paths, command lines, or raw evidence.
- Operations: improved memory-conscious collectors, fixed-slot daily reports, storage retention, build-cache cleanup after source install/update, panel deployment scripts, Cloudflare deployment workflow, detailed English/Chinese deployment docs, and one-command agent/panel update paths.

## 0.2.0

- Default security posture: active response is enabled for new installs, SSH brute-force alert/block thresholds now default to 6 failures per scan window, and existing explicit user config values remain preserved during upgrade.
- Advanced evidence: scheduled reports, auditd/eBPF bridge entry points, external rule loading, YARA integration, threat-intel enrichment, and fleet snapshots are enabled by default while safely doing no work until their required inputs or notification channels are configured.
- Detection and response quality: improved incident correlation, service profiling, public-IP safety checks, permanent block escalation, active-response deduplication, and stable state-drift suppression to reduce repeat messages during real operations.
- Documentation and release packaging: refreshed English and Chinese README content for the current architecture, defaults, compatibility, commands, and release-artifact based installation/update flow.

## 0.1.1

- CLI and deployment: added the `vs` shorthand, built-in reload command, release artifact based install/update, config migration/default synchronization, post-update `scan --no-notify`, and multi-architecture release packages.
- Notifications: changed the default language to Simplified Chinese, completed Chinese/English rendering for built-in rules and common evidence fields, and added concise active-response summaries for large block bursts.
- Active response: added temporary IP blocking with nftables/iptables, block listing/cleanup/unblock commands, firewall state reconciliation, shared public-IP safety checks, and stricter SSH/Web block thresholds.
- Web detection: expanded probe classification and blocking decisions for command injection, CGI shell traversal, PHPUnit eval-stdin, PHP config-write payloads, LFI file reads, PHP stream wrappers, JNDI injection, SSRF cloud metadata probes, template injection, SQL injection, and deserialization probes.
- Host detection: added suspicious GPU compute-process scoring, unsafe `authorized_keys` state checks, sensitive auth/log tamper detection, and stronger process/network behavior context while reducing common service false positives.
- Storage and noise control: added SQLite stats, prune/clear/vacuum commands, database size limits, durable deduplication state, complete rule-catalog coverage for system findings, and stable dedup keys for state findings such as high-risk public service exposure.

## 0.1.0

- Initial MVP workspace with `sentinel-core`, `sentinel-agent`, and `sentinel-cli`.
- Added unified `RawEvent` and `Finding` models.
- Added TOML config and SQLite storage.
- Added baseline create/show/diff/reset flow.
- Added SSH, file integrity, user, persistence, process, network, web log, config risk, Docker signal, and Rootkit signal modules.
- Added Telegram, Email SMTP, Webhook, ntfy, Gotify, Bark, and ServerChan notifier implementations.
- Added systemd unit, one-command installer, update script, and documentation.
