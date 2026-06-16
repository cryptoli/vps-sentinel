# Configuration Reference

The default system configuration path is `/etc/vps-sentinel/config.toml`. A user-level path can be placed at `~/.config/vps-sentinel/config.toml`.

## Sections

- `[agent]`: host ID, hostname, human-readable `display_name`, scan intervals, data directory, log level. Notification subjects use `display_name`, then `hostname`, then `host_id`, then `local-host`.
- `[privacy]`: upload and masking controls. Upload is disabled by default.
- `[storage]`: SQLite path and retention.
- `[ssh]`: auth log paths and SSH login thresholds.
- `[file_integrity]`: monitored paths, scan depth, and max file size.
- `[web]`: web roots and access log paths.
- `[process]`: process scan thresholds and suspicious directories. `PROC-003` profiles `/proc/<pid>/cmdline` argv and requires high-confidence network command-execution bridge behavior, not traffic-forwarding tool names alone. `PROC-004` is a known-tool indicator rule that matches miner/scanner names at token or executable-basename boundaries instead of arbitrary substrings.
- `[network]`: listening port policy. `expected_public_ports` suppresses ordinary exposed-service noise but still allows process-risk and baseline-owner checks, `high_risk_public_ports` controls ports that are risky when public, and `alert_on_new_listening_port` reports ordinary new listeners only when they appear relative to the stored baseline. `public_listen_allowlist` is kept as a legacy alias for expected public ports; use `[allowlist].listening_ports` to suppress all network findings for a port.
- `[persistence]`: cron, systemd, shell profile, and preload monitoring.
- `[docker]`: Docker risk flags.
- `[notifications]`: shared notification options such as request timeout, message language, timestamp zone, and technical-field visibility. `language` accepts `en` or `zh_cn`; `time_zone` accepts `local` or `utc`; `include_technical_fields` controls rule ID, event ID, and dedup key display.
- `[notifications.telegram]`: Telegram bot token, chat ID, and minimum severity.
- `[notifications.email]`: SMTP host, port, TLS mode, optional credentials, sender, recipients, subject prefix, and minimum severity. `tls_mode` accepts `start_tls`, `tls`, or `none`; plaintext mode is only valid without SMTP credentials.
- `[notifications.webhook]`: generic HTTP webhook URL, optional shared secret header, and minimum severity.
- `[notifications.ntfy]`: ntfy server, topic, optional bearer token, and minimum severity.
- `[notifications.gotify]`: Gotify server, app token, and minimum severity.
- `[notifications.bark]`: Bark server, device key, and minimum severity.
- `[notifications.serverchan]`: ServerChan send key and minimum severity.
- `[noise_control]`: dedup and alert volume controls.
- `[allowlist]`: trusted users, IPs, paths, ports, and specific process command fragments. Use `process_command_contains` for known-good long-running commands whose full path is not stable enough for `process_paths`.

`noise_control.quiet_hours` entries use local server time in `HH:MM-HH:MM` format. Time windows may wrap across midnight, for example `["22:00-07:00"]`. During quiet hours, non-critical notifications are suppressed while critical findings still notify.

`noise_control.max_alerts_per_hour` limits notification delivery attempts across enabled channels. Attempts are counted from local SQLite notification logs.

See [config/config.example.toml](../config/config.example.toml) for a complete example.
