# Agent Deployment

This guide covers installing and operating the `vps-sentinel` agent on Linux VPS hosts. For the fleet panel, see [panel-deployment.md](panel-deployment.md).

## Requirements

- Linux VPS with root or sudo access.
- systemd is recommended; non-systemd hosts can still run `vps-sentinel scan` manually.
- Rust is only needed when the installer falls back to source builds.
- Optional tools improve visibility: `journalctl`, `ss`, `nft`, `iptables`, `dpkg`/`rpm`/`apk`/`pacman`, `nvidia-smi`, `rocm-smi`, `auditd`, and `bpftrace`.

## One-Command Install

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sudo sh
```

Useful install variables:

```bash
sudo VPS_NAME="prod-sg-1" \
  TELEGRAM_BOT_TOKEN="<bot-token>" \
  TELEGRAM_CHAT_ID="<chat-id>" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

The installer:

- installs `vps-sentinel` and the `vs` shorthand;
- creates `/etc/vps-sentinel/config.toml` only when it does not exist;
- validates config, bootstraps the first baseline, and runs a no-notify warm-up scan;
- installs and starts the systemd service when systemd is available;
- preserves existing config on reinstall.

## Update

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sudo sh
```

The updater validates a release binary before installing it. If the binary is not compatible with the host, it falls back to a local source build. Existing config, SQLite state, baselines, notification credentials, and panel secrets are preserved.

## Service Operations

```bash
sudo vs doctor
sudo vs scan
sudo vs reload
sudo systemctl status vps-sentinel --no-pager
sudo systemctl stop vps-sentinel
sudo systemctl start vps-sentinel
```

`vs reload` validates the config before reloading the daemon.

## Configure Notifications

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

## Configure Panel Upload

After a panel is deployed, configure each agent:

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_name = "prod-sg-1"
secret = "same-long-secret-as-panel"
privacy_mode = "strict"

[panel.location]
country_code = "SG"
country = "Singapore"
city = "Singapore"
```

Then verify:

```bash
sudo vs config validate
sudo vs panel push
sudo vs panel outbox
sudo vs reload
```

Use non-sensitive `node_name` values. Do not use public IPs, private hostnames, provider instance IDs, or secrets as node names.

## Active Response

Active response writes source-IP blocks only after high-confidence SSH/Web evidence and safety checks:

```toml
[active_response]
enabled = true
strategy = "balanced" # observe, balanced, strict
firewall_backend = "auto"
ssh_failed_login_block_threshold = 6
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

Always put your own jump hosts, monitoring systems, VPN egress, and trusted office IPs in `[allowlist].ips`.

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
