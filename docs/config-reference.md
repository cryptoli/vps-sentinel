# Configuration Reference

The default system configuration path is `/etc/vps-sentinel/config.toml`. A user-level path can be placed at `~/.config/vps-sentinel/config.toml`.

## Sections

- `[agent]`: host ID, hostname, human-readable `display_name`, scan intervals, data directory, log level. Notification subjects use `display_name`, then `hostname`, then `host_id`, then `local-host`.
- `[privacy]`: upload and masking controls. Upload is disabled by default.
- `[storage]`: SQLite path and retention.
- `[ssh]`: auth log paths and SSH login thresholds. `alert_on_root_login`, `alert_on_password_login`, and `alert_on_successful_login` control which successful logins become findings; ordinary successful-login alerts are not limited to unfamiliar IP addresses. Ordinary successful logins are `Info`; root login remains `High`, and password login remains `Medium`. SSH login deduplication uses user plus source IP, while session port remains evidence. SSH brute-force deduplication uses source IP, not volatile failure counts. `auth_log_lookback_seconds` limits how far back auth logs are considered on each scan. When configured auth log files are absent, the SSH collector falls back to `journalctl` for `ssh.service` and `sshd.service`.
- `[file_integrity]`: monitored paths, scan depth, and max file size.
- `[web]`: web roots and access log paths.
- `[process]`: process scan thresholds and suspicious directories. `deleted_executable_min_score` controls when `PROC-002` is emitted; deleted executable state must combine with suspicious traits such as temporary paths, memfd or anonymous backing, hidden non-standard paths, network execution bridges, or known bad tool identity. `PROC-003` profiles `/proc/<pid>/cmdline` argv and requires high-confidence network command-execution bridge behavior, not traffic-forwarding tool names alone. `PROC-004` is a known-tool indicator rule that matches miner/scanner names against process identity fields such as executable path, process name, and structured `argv[0]`; legacy events without structured identity fall back to command token basename matching.
- `[network]`: listening port policy. `expected_public_ports` suppresses ordinary exposed-service noise but still allows process-risk and baseline-owner checks, `high_risk_public_ports` controls ports that are risky when public, and `alert_on_new_listening_port` reports ordinary new listeners only when they appear relative to the stored baseline. `public_listen_allowlist` is kept as a legacy alias for expected public ports; use `[allowlist].listening_ports` to suppress all network findings for a port.
- `[persistence]`: cron, systemd, shell profile, and preload monitoring. `suspicious_command_min_score` controls when `PERSIST-002` is emitted; startup lines are scored by combined traits such as download-to-shell, temporary-path autostart payloads, encoded shell payloads, and network execution bridges.
- `[docker]`: Docker risk flags.
- `[notifications]`: shared notification options such as request timeout, message language, timestamp zone, and technical-field visibility. `language` accepts `en` or `zh_cn`; `time_zone` accepts `local` or `utc`; `include_technical_fields` controls rule ID, event ID, and dedup key display.
- `[notifications.telegram]`: Telegram bot token, chat ID, and minimum severity.
- `[notifications.email]`: SMTP host, port, TLS mode, optional credentials, sender, recipients, subject prefix, and minimum severity. `tls_mode` accepts `start_tls`, `tls`, or `none`; plaintext mode is only valid without SMTP credentials.
- `[notifications.webhook]`: generic HTTP webhook URL, optional shared secret header, and minimum severity.
- `[notifications.ntfy]`: ntfy server, topic, optional bearer token, and minimum severity.
- `[notifications.gotify]`: Gotify server, app token, and minimum severity.
- `[notifications.bark]`: Bark server, device key, and minimum severity.
- `[notifications.serverchan]`: ServerChan send key and minimum severity.
- `[noise_control]`: dedup and alert volume controls. `rate_limit_bypass_min_severity` defaults to `High`, so high-value alerts bypass the hourly budget.
- `[allowlist]`: trusted users, IPs, paths, ports, and specific process command fragments. Use `process_command_contains` for known-good long-running commands whose full path is not stable enough for `process_paths`.

`noise_control.quiet_hours` entries use local server time in `HH:MM-HH:MM` format. Time windows may wrap across midnight, for example `["22:00-07:00"]`. During quiet hours, non-critical notifications are suppressed while critical findings still notify.

`noise_control.dedup_window_seconds` defaults to 3600 seconds and suppresses repeated findings with the same stable dedup key. `noise_control.max_alerts_per_hour` limits notification delivery attempts below `rate_limit_bypass_min_severity` across enabled channels. Attempts are counted from local SQLite notification logs.

See [config/config.example.toml](../config/config.example.toml) for a complete example.
