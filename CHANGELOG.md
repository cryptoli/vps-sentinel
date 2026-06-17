# Changelog

## 0.1.1

- Added `vs` as a short command alias and moved reload into the CLI command surface.
- Added active-response IP block listing, cleanup, single unblock, and unblock-all commands.
- Added active-response outcome evidence to alerts, so Telegram, Email, webhook, and other channels show whether a block was applied, already existed, failed, or was skipped.
- Added SQLite storage stats, manual prune, manual clear, and vacuum commands.
- Added active-response firewall state reconciliation to remove stale local block records after firewall reloads or manual rule changes.
- Added database size limiting and retention cleanup to reduce disk-full risk on small VPS hosts.
- Improved web alert aggregation, stricter active-response block thresholds, and safer process/network risk scoring context.
- Switched notification language default to Simplified Chinese and completed Chinese/English rendering for built-in rules and evidence fields.
- Fixed `vps-sentinel-update` to prefer release artifacts and fall back to source builds only when the artifact is unavailable or incompatible.
- Hardened install and update Rust toolchain checks so a rustup proxy without a default toolchain is repaired instead of failing at `cargo build`.
- Added a project-level `rust-toolchain.toml` so older source-build updaters can bootstrap on rustup installations without a default toolchain.
- Adjusted the default SSH active-response block threshold to 15 failed logins, while keeping active response disabled unless explicitly enabled.
- Tightened active-response public IP classification to avoid blocking IPv4 special-use ranges.
- Updated installer behavior, Linux compatibility notes, operational documentation, release notes, and release packaging contents.

## 0.1.0

- Initial MVP workspace with `sentinel-core`, `sentinel-agent`, and `sentinel-cli`.
- Added unified `RawEvent` and `Finding` models.
- Added TOML config and SQLite storage.
- Added baseline create/show/diff/reset flow.
- Added SSH, file integrity, user, persistence, process, network, web log, config risk, Docker signal, and Rootkit signal modules.
- Added Telegram, Email SMTP, Webhook, ntfy, Gotify, Bark, and ServerChan notifier implementations.
- Added systemd unit, one-command installer, update script, and documentation.
