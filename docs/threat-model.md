# Threat Model

vps-sentinel focuses on early detection of host compromise signals on small Linux VPS hosts.

## Protected Assets

- SSH access and authorized keys.
- Local users, groups, sudo configuration, and UID 0 accounts.
- cron, systemd, shell profile, and dynamic linker persistence points.
- Running processes and public listening ports.
- Web roots and web access logs.
- Local event history in SQLite.

## In Scope

- Detecting suspicious SSH authentication patterns.
- Detecting baseline drift in key files, users, startup entries, and listening ports.
- Detecting suspicious process command lines and temporary-path executables.
- Detecting WebShell-like file markers under configured size limits.
- Sending local-summary notifications through explicitly configured channels.
- Optional TTL-based firewall blocking for strict, high-confidence public-source Web and SSH brute-force findings when `[active_response].enabled = true`.

## Out of Scope

- Exploit development or vulnerability scanning of third-party hosts.
- Password brute force or credential collection.
- Kernel-level Rootkit certainty.
- Default destructive remediation; active response is disabled unless explicitly configured.
- Mandatory cloud upload.

## Trust Boundaries

The agent reads local host metadata and stores summaries in SQLite. Notification providers are external trust boundaries and must be explicitly enabled by configuration.
