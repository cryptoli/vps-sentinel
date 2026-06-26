# Privacy

vps-sentinel is local-first.

## Defaults

- No log upload.
- No cloud dependency.
- SQLite local storage.
- Notification channels disabled until configured.

## Data Stored

The database stores raw event summaries, findings, scan runs, baseline snapshots, notification logs, and rule state. It does not store large auth or web log files.

## Panel Telemetry

Panel upload is disabled until `[panel].enabled = true`. In strict privacy mode, the agent removes node IDs, host IDs, public server IPs, raw logs, raw evidence, file paths, command lines, private network fields, and sensitive config values before upload. The panel receiver applies another redaction pass before storage.

Safe display fields are different from privacy-sensitive fields. A human-readable node name, a sanitized hostname that is not an IP address, and country/region/city metadata can be uploaded so the dashboard is usable. Node location detection reads the public IP from a trusted HTTPS endpoint only to derive display geography; that IP is discarded and is not sent to the panel.

Confirmed external attacker IPs may appear on the public blocklist when active-response evidence supports it. Public blocklist rows do not reveal the protected node name, hostname, paths, commands, raw evidence, or sensitive configuration.

## Content Scanning

File content scanning is bounded by `file_integrity.max_file_size_mb` and only extracts risk markers. It does not upload file bodies.

## Secrets

Notification tokens, SMTP passwords, and webhook secrets must not be printed in logs. Debug output should never include full environment variables or private keys.
