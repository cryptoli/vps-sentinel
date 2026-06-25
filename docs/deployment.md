# Agent Deployment

This guide covers installing and operating the `vps-sentinel` agent on Linux VPS hosts. For fleet panel deployment, see [panel-deployment.md](panel-deployment.md).

## Requirements

- Linux VPS with root or sudo access.
- systemd is recommended. Non-systemd hosts can still run `vps-sentinel scan` manually.
- `curl` and CA certificates are required for one-command installs.
- Rust is only required when the installer cannot use a compatible release binary and falls back to source builds.
- Optional tools improve visibility: `journalctl`, `ss`, `nft`, `iptables`, `dpkg`/`rpm`/`apk`/`pacman`, `nvidia-smi`, `rocm-smi`, `auditd`, and `bpftrace`.

## Basic Install

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sudo sh
```

The installer will:

- install `vps-sentinel` and the shorter `vs` command;
- install compatible dependencies for Debian/Ubuntu, RHEL-family, Fedora, Alpine, and Arch-family hosts;
- use a release artifact when it can run on the current host, otherwise build from source;
- create `/etc/vps-sentinel/config.toml` only if it does not already exist;
- validate config, migrate compatible old config keys, sync new default keys, bootstrap the first baseline, and run a no-notification warm-up scan;
- install and start the systemd service when systemd is available;
- preserve existing config, SQLite state, baselines, notification credentials, panel secrets, and block history on reinstall.

## Install With Telegram Enabled

Use this form when you want Telegram ready immediately:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o /tmp/vps-sentinel-install.sh
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<your-bot-token>" \
  TELEGRAM_CHAT_ID="<your-chat-id>" \
  TELEGRAM_MIN_SEVERITY="Medium" \
  sh /tmp/vps-sentinel-install.sh
```

Equivalent one-liner:

```bash
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<your-bot-token>" \
  TELEGRAM_CHAT_ID="<your-chat-id>" \
  TELEGRAM_MIN_SEVERITY="Medium" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

Variable meanings:

| Variable | Meaning | Required |
| --- | --- | --- |
| `VPS_NAME` | Display name used in alerts, reports, and panel nodes. Do not use an IP address or sensitive hostname. | Recommended |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token from BotFather. | Required if Telegram is enabled |
| `TELEGRAM_CHAT_ID` | Telegram target chat ID. | Required if Telegram is enabled |
| `TELEGRAM_MIN_SEVERITY` | Minimum severity sent to Telegram: `Low`, `Medium`, `High`, or `Critical`. | Optional, default `Medium` |

If only one of `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` is set, the installer stops instead of writing a broken notification config.

## Useful Install Options

```bash
sudo BRANCH="main" \
  INSTALL_METHOD="auto" \
  INSTALL_DEPS="yes" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD="4" \
  ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD="25" \
  ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="yes" \
  STORAGE_MAX_DATABASE_SIZE_MB="256" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

Common variables:

| Variable | Meaning |
| --- | --- |
| `BRANCH` | Git branch used when source checkout is needed. Default: `main`. |
| `REPO_URL` | Git repository URL. Default: official GitHub repository. |
| `INSTALL_METHOD` | `auto`, `release`, or `source`. `auto` validates release binaries first and falls back to source. |
| `INSTALL_DEPS` | `yes` or `no`. Installs dependencies through the host package manager when enabled. |
| `INSTALL_SYSTEMD` | `auto`, `yes`, or `no`. Controls systemd service installation. |
| `ENABLE_SERVICE` | `yes` or `no`. Starts/enables the service after install. |
| `RUN_DOCTOR` | `yes` or `no`. Runs `vs doctor` after installation. |
| `RUN_FIRST_SCAN` | `yes` or `no`. Runs the warm-up scan without notifications. |
| `RUN_NOTIFY_TEST` | `auto`, `yes`, or `no`. Sends a Telegram test only when Telegram values are provided and testing is enabled. |
| `MIGRATE_CONFIG` | `yes` or `no`. Applies compatible config migrations. |
| `SYNC_CONFIG_DEFAULTS` | `yes` or `no`. Adds new default config keys without overwriting custom values. |
| `CONFIG_DIR` | Config directory. Default: `/etc/vps-sentinel`. |
| `DATA_DIR` | Local state directory. Default: `/var/lib/vps-sentinel`. |
| `LOG_DIR` | Log directory. Default: `/var/log/vps-sentinel`. |

Active response variables map to `[active_response]` in `/etc/vps-sentinel/config.toml`. Use allowlists before enabling blocking on production jump hosts, monitoring systems, VPN egress, or office IPs.

## Update

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sudo sh
```

The updater preserves existing config and state. It validates the target binary before replacing the current one. If the binary is not compatible with the host, it builds from source and ensures Rust has a default stable toolchain.

Useful update variables:

```bash
sudo BRANCH="main" \
  INSTALL_METHOD="auto" \
  VALIDATE_CONFIG="yes" \
  MIGRATE_CONFIG="yes" \
  SYNC_CONFIG_DEFAULTS="yes" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sh'
```

## Service Operations

```bash
sudo vs doctor
sudo vs scan
sudo vs reload
sudo systemctl status vps-sentinel --no-pager
sudo systemctl stop vps-sentinel
sudo systemctl start vps-sentinel
```

`vs reload` validates config before reloading the daemon.

## Notification Config

Edit `/etc/vps-sentinel/config.toml`:

```toml
[notifications]
language = "zh_cn" # zh_cn or en
time_zone = "local"

[notifications.telegram]
enabled = true
bot_token = "<bot-token>"
chat_id = "<chat-id>"
min_severity = "Medium"
```

Supported channels: Telegram, Email SMTP, webhook, ntfy, Gotify, Bark, and ServerChan.

## Panel Upload

After deploying a panel, configure each agent:

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_name = "prod-sg-1"
secret = "same-long-secret-as-panel"
privacy_mode = "strict"
```

Then verify:

```bash
sudo vs config validate
sudo vs panel push
sudo vs panel outbox
sudo vs reload
```

Use non-sensitive `node_name` values. Do not use public IPs, private hostnames, provider instance IDs, or secrets as node names. The panel receiver automatically adds non-sensitive country/city display metadata when trusted reverse-proxy headers such as Cloudflare geolocation are available.

## Active Response

```toml
[active_response]
enabled = true
strategy = "balanced" # observe, balanced, strict
firewall_backend = "auto"
ssh_failed_login_block_threshold = 4
web_probe_block_threshold = 25
permanent_block_enabled = true
permanent_block_threshold = 3
```

Commands:

```bash
sudo vs blocks list
sudo vs blocks unblock <ip>
sudo vs blocks unblock-all --yes
sudo vs blocks cleanup
```

## Baseline Review

```bash
sudo vs baseline create
sudo vs baseline diff
sudo vs baseline approve <approval-key>
```

Package upgrades and planned maintenance can create legitimate drift. Review evidence before refreshing a baseline.

## Troubleshooting

```bash
sudo vs doctor
sudo journalctl -u vps-sentinel -n 100 --no-pager
sudo vs config validate
sudo vs storage stats
```

If the daemon runs without enough privileges, some collectors degrade. `vs doctor` explains which modules lose visibility.
