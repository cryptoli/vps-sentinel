# Privacy

vps-sentinel is local-first.

## Defaults

- No log upload.
- No cloud dependency.
- SQLite local storage.
- Notification channels disabled until configured.

## Data Stored

The database stores raw event summaries, findings, scan runs, baseline snapshots, notification logs, and rule state. It does not store large auth or web log files.

## Content Scanning

File content scanning is bounded by `file_integrity.max_file_size_mb` and only extracts risk markers. It does not upload file bodies.

## Secrets

Notification tokens, SMTP passwords, and webhook secrets must not be printed in logs. Debug output should never include full environment variables or private keys.
