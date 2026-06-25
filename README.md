# vps-sentinel

Lightweight Rust intrusion-signal monitoring and fleet security dashboard for Linux VPS hosts.

[中文说明](README.zh-CN.md)

![CI](https://github.com/cryptoli/vps-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Positioning

`vps-sentinel` is a defensive monitoring tool. It aims to detect suspicious host activity early, show evidence, and suggest operator actions.

It is not antivirus software, an exploit framework, a brute-force tool, a third-party scanner, a C2/backdoor, or a guarantee that a server is clean.

## Highlights

| Area | Capabilities |
| --- | --- |
| SSH and accounts | Successful SSH logins, password logins, brute force, brute force followed by success, `authorized_keys` drift, unsafe key-file state, new users, UID 0 users, and privilege-relevant changes. |
| Baseline drift | Stateful baselines for users, SSH keys, critical files, persistence entries, listeners, and service identities; semantic drift scoring reduces package-upgrade and dynamic-port noise. |
| Process and GPU behavior | Procfs process context, parent chain, systemd identity, package ownership, executable hash/owner, outbound profile, behavior-profile drift, known miner/scanner identity, and NVIDIA/ROCm GPU compute signals. |
| Network and web probes | Public listener ownership, firewall context, trusted-proxy client-IP recovery, Web probe family classification, exploit-path aggregation, error bursts, and source-IP response candidates. |
| Active response | Optional nftables/iptables source-IP blocking for high-confidence SSH and Web attack sources, temporary/permanent escalation, allowlists, trusted-proxy safety, and CLI unblock commands. |
| Attack fingerprints | Method-based fingerprints using exact hashes plus SimHash-style similarity, so repeated attack methods can be grouped even when source IPs rotate. |
| Reports and notifications | Daily reports and alert messages through Telegram, Email SMTP, webhook, ntfy, Gotify, Bark, and ServerChan; Chinese is the default notification language. |
| Fleet panel | Push-mode Rust or Cloudflare Worker/D1 panel with public/private access, privacy redaction, node metrics, blocklist attribution, review flows, WebSocket refresh on self-hosted panel, and theme extension hooks. |
| Resource control | Bounded log parsing, event budgets, SQLite retention, database size limits, raw-evidence reduction, and small daemon RSS on VPS-class hosts. |

## Deployment

Detailed agent and panel deployment guides:

- Agent deployment: [docs/deployment.md](docs/deployment.md) / [docs/deployment.zh-CN.md](docs/deployment.zh-CN.md)
- Panel deployment: [docs/panel-deployment.md](docs/panel-deployment.md) / [docs/panel-deployment.zh-CN.md](docs/panel-deployment.zh-CN.md)
- Panel architecture: [docs/panel-architecture.md](docs/panel-architecture.md)
- Panel theme extensions: [docs/panel-themes.md](docs/panel-themes.md)

Recommended full agent install:

```bash
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<telegram-bot-token>" \
  TELEGRAM_CHAT_ID="<telegram-chat-id>" \
  PANEL_URL="https://your-panel.example.com/api/v1/ingest" \
  PANEL_SHARED_SECRET="<panel-shared-secret>" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="yes" \
  STORAGE_MAX_DATABASE_SIZE_MB="256" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

The shorter `curl ... | sudo sh` form is still supported, but it installs a local-only daemon without Telegram or panel upload. Use the deployment guide when installing a real node.

Quick update:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sudo sh
```

The installer and updater preserve existing `/etc/vps-sentinel/config.toml` unless you explicitly edit it.

## Common Commands

| Command | Meaning |
| --- | --- |
| `vs doctor` | Check runtime visibility, config validity, dependencies, and service context. |
| `vs scan` | Run one local scan and print findings without waiting for the daemon loop. |
| `vs reload` | Validate config and reload the daemon. |
| `vs baseline create` | Create the first local baseline. |
| `vs baseline diff` | Compare current host state with the baseline. |
| `vs blocks list` | Show active response blocks. |
| `vs blocks unblock <ip>` | Remove one temporary or permanent source-IP block. |
| `vs fingerprints explain <id>` | Explain an attack fingerprint cluster. |
| `vs report send` | Send the default daily report through configured notification channels. |
| `vs panel push` | Push one signed telemetry snapshot to the configured panel. |
| `vs config validate` | Validate the config file. |
| `vs config migrate` | Apply compatible config migrations. |

## Token Types

`vps-sentinel` keeps the panel token model small:

| Token or secret | Used by | Purpose | Required? |
| --- | --- | --- | --- |
| `panel.secret` / `PANEL_SHARED_SECRET` | Agent and panel | HMAC signing for `POST /api/v1/ingest`. | Required when panel upload is enabled. |
| `PANEL_NODE_SECRETS` | Panel | Optional per-node ingest secrets keyed by non-sensitive node name. | Optional. |
| `PANEL_TOKEN` | Browser and panel | Single private access token for details, reviews, audit logs, and management pages. | Required for private panel workflows. |
| Notification tokens | Agent and notification provider | Telegram/Gotify/ntfy/Bark/ServerChan/webhook/email credentials. | Only required for enabled channels. |

Deployment scripts migrate old `PANEL_ADMIN_TOKEN`, `PANEL_OPERATOR_TOKEN`, or `PANEL_VIEW_TOKEN` values into `PANEL_TOKEN` when an existing credential file is reused.

## Compatibility

The agent targets common systemd Linux VPS distributions including Debian, Ubuntu, Alma/Rocky/RHEL-family, Fedora, Alpine, Arch, and similar hosts. It degrades when platform tools are missing instead of crashing. Some collectors need root-level visibility; `vs doctor` reports reduced visibility when the daemon lacks permissions.

Runtime footprint depends on enabled collectors, log volume, and file-integrity scope. On the current validation VPS set, the daemon process normally stays in the single-digit to low-tens MiB RSS range; systemd cgroup memory can be higher because Linux may charge recently touched file cache to the service.

## Privacy

Defaults are local-first: no panel upload unless `[panel].enabled = true`, no notification channel unless configured, bounded file scanning, and local SQLite storage. Panel telemetry removes node IDs, host IDs, public server IPs, raw evidence, paths, command lines, and general internal network fields before remote storage. Safe display fields such as node name, sanitized hostname, country, region, and city may be uploaded for dashboard use. Confirmed external attacker IPs can be shown on the public blocklist when active-response evidence supports it, but public blocklist rows do not expose node names.

Secrets belong in local config files, Worker secrets, or systemd environment files. Repository files only contain placeholder examples for tokens, passwords, webhook secrets, SMTP credentials, Cloudflare API tokens, and panel shared secrets.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=cryptoli/vps-sentinel&type=Date)](https://www.star-history.com/#cryptoli/vps-sentinel&Date)

## License

MIT License. See [LICENSE](LICENSE) and [docs/open-source-license.md](docs/open-source-license.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New rules must be defensive, explainable, evidence-backed, and safe by default.

## Security

Please report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
