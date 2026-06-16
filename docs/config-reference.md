# Configuration Reference

The default system configuration path is `/etc/vps-sentinel/config.toml`. A user-level path can be placed at `~/.config/vps-sentinel/config.toml`.

## Sections

- `[agent]`: host ID, hostname, scan intervals, data directory, log level.
- `[privacy]`: upload and masking controls. Upload is disabled by default.
- `[storage]`: SQLite path and retention.
- `[ssh]`: auth log paths and SSH login thresholds.
- `[file_integrity]`: monitored paths, scan depth, and max file size.
- `[web]`: web roots and access log paths.
- `[process]`: process scan thresholds and suspicious directories.
- `[network]`: listening port policy.
- `[persistence]`: cron, systemd, shell profile, and preload monitoring.
- `[docker]`: Docker risk flags.
- `[notifications]`: shared notification options such as HTTP request timeout.
- `[notifications.*]`: channel-specific credentials and minimum severity.
- `[noise_control]`: dedup and alert volume controls.
- `[allowlist]`: trusted users, IPs, paths, and ports.

See [config/config.example.toml](../config/config.example.toml) for a complete example.
