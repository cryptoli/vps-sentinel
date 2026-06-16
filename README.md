# vps-sentinel

Lightweight Rust intrusion-signal monitoring for Linux VPS hosts.

`vps-sentinel` helps VPS owners discover suspicious SSH logins, changed `authorized_keys`, unexpected users, privilege changes, startup persistence, suspicious processes, new public listening ports, WebShell-like files, web probing, and common risky configuration. It is local-first, transparent, and designed for small servers instead of heavyweight SIEM/EDR deployments.

[Chinese README](README.zh-CN.md)

![CI](https://github.com/cryptoli/vps-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## What It Is

vps-sentinel is a defensive monitoring agent. It gives you evidence and suggested next steps when a VPS shows compromise signals.

It is not:

- an antivirus engine;
- an exploit framework;
- a password brute-force tool;
- a third-party network scanner;
- a C2, backdoor, or stealth tool;
- a guarantee that a host is clean.

## Supported Features

| Area | What vps-sentinel supports |
| --- | --- |
| SSH monitoring | Parses Debian/Ubuntu and RHEL-family auth logs; detects root SSH login, password login, brute-force patterns, new login source IPs, and `authorized_keys` drift. |
| Baseline drift | Creates local baselines for users, SSH keys, critical files, persistence entries, and listeners; compares future scans against the stored baseline. |
| User and privilege checks | Detects new users, UID 0 users, and privilege-relevant user changes. |
| File integrity | Watches configured critical paths and web roots; hashes bounded file content; detects modified files, executable scripts in web roots, and WebShell-style markers. |
| Persistence checks | Monitors cron, systemd, shell profile, and preload-related locations for new or suspicious startup entries. |
| Process checks | Reads procfs to flag temporary-path executables, deleted executables still running, reverse-shell fragments, miners, and scanner-like commands. |
| Network checks | Reads listening sockets and owning processes; flags new public listeners, non-allowlisted ports, and high-risk public service ports. |
| Web log checks | Parses common access log lines and detects common automated probing paths. |
| Rootkit signals | Collects lightweight local indicators for hidden process and suspicious procfs behavior. |
| Docker context | Detects Docker availability and emits initial container-surface context; deeper inspection is planned for later releases. |
| Storage | Stores raw events, findings, baselines, and notification logs in local SQLite. |
| Noise control | Uses allowlists, minimum severity, finding deduplication, and configurable retention windows. |
| Notifications | Sends alerts through Telegram, Email SMTP, generic webhook, ntfy, Gotify, Bark, and ServerChan. |
| Operations | Provides a single CLI binary, JSON logs, systemd unit, one-command installer, and update script. |

## Notification Channels

All notification channels are disabled by default. Enable only the channels you need in `config.toml`.

| Channel | Config section | Required fields | Typical use |
| --- | --- | --- | --- |
| Telegram | `[notifications.telegram]` | `enabled`, `bot_token`, `chat_id` | Personal or team security alerts through a Telegram bot. |
| Email SMTP | `[notifications.email]` | `enabled`, `smtp_host`, `smtp_port`, `from`, `to` | Traditional mailbox alerts for operations teams. Supports STARTTLS, implicit TLS, and local plaintext relays. |
| Webhook | `[notifications.webhook]` | `enabled`, `url` | Custom HTTP receivers, automation platforms, or self-hosted alert routers. |
| ntfy | `[notifications.ntfy]` | `enabled`, `server`, `topic` | Push notifications through ntfy.sh or self-hosted ntfy. |
| Gotify | `[notifications.gotify]` | `enabled`, `server`, `token` | Self-hosted push notifications. |
| Bark | `[notifications.bark]` | `enabled`, `server`, `device_key` | iOS push notifications through Bark. |
| ServerChan | `[notifications.serverchan]` | `enabled`, `send_key` | WeChat-style notifications through ServerChan. |

Each channel supports `min_severity`, so low-priority findings can be kept local while higher-risk findings are sent out. HTTP-based channels share `notifications.request_timeout_seconds`, which defaults to 15 seconds. Email alerts are sent as multipart messages with plain-text and HTML bodies; other human-facing channels use the same normalized alert title and body renderer.

Telegram example:

```toml
[notifications.telegram]
enabled = true
bot_token = "<telegram-bot-token>"
chat_id = "<telegram-chat-id>"
min_severity = "Medium"
```

Email example:

```toml
[notifications.email]
enabled = true
smtp_host = "smtp.example.com"
smtp_port = 587
tls_mode = "start_tls" # start_tls, tls, or none
username = "smtp-user"
password = "smtp-password"
from = "vps-sentinel@example.com"
to = ["ops@example.com"]
subject_prefix = "[vps-sentinel]"
min_severity = "High"
```

For unauthenticated local SMTP relays, use `tls_mode = "none"` and leave `username` and `password` empty. Credentials are intentionally rejected with plaintext SMTP.

Webhook example:

```toml
[notifications.webhook]
enabled = true
url = "https://example.com/security-webhook"
secret = ""
min_severity = "Medium"
```

## Architecture

```text
vps-sentinel/
  crates/
    sentinel-core/   # config, errors, severity, RawEvent, Finding
    sentinel-agent/  # collectors, detectors, baseline, SQLite, notifiers, daemon
    sentinel-cli/    # vps-sentinel command line
  config/            # example configuration
  packaging/         # systemd unit template and package-time install helper
  docs/              # deployment, privacy, rule and notifier guides
```

Collectors gather facts. Detectors convert facts into findings. Storage and notifications consume the unified `Finding` model, so new rules and channels can be added without coupling modules together.

## Quick Install

Review the script before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o install.sh
sudo sh install.sh
```

The installer:

- detects apt, dnf, yum, apk, or pacman;
- installs build dependencies if needed;
- installs Rust with rustup when `cargo` is missing;
- clones this repository to `/opt/vps-sentinel-src` by default;
- builds `vps-sentinel` in release mode;
- installs the binary to `/usr/local/bin/vps-sentinel`;
- creates `/etc/vps-sentinel/config.toml` only if it does not already exist;
- installs and enables the systemd service when systemd is available.

Configuration can be customized through environment variables:

```bash
sudo REPO_URL=https://github.com/cryptoli/vps-sentinel.git \
  BRANCH=main \
  WORK_DIR=/opt/vps-sentinel-src \
  PREFIX=/usr/local \
  sh install.sh
```

Useful installer switches:

| Variable | Default | Meaning |
| --- | --- | --- |
| `REPO_URL` | `https://github.com/cryptoli/vps-sentinel.git` | Git repository to clone. |
| `BRANCH` | `main` | Git branch to install. |
| `WORK_DIR` | `/opt/vps-sentinel-src` | Source checkout directory. |
| `PREFIX` | `/usr/local` | Binary installation prefix. |
| `CONFIG_DIR` | `/etc/vps-sentinel` | Directory for `config.toml`. |
| `DATA_DIR` | `/var/lib/vps-sentinel` | SQLite data directory. |
| `LOG_DIR` | `/var/log/vps-sentinel` | Runtime log directory. |
| `INSTALL_DEPS` | `yes` | Set to `no` to skip package manager dependency installation. |
| `INSTALL_SYSTEMD` | `auto` | `auto`, `yes`, or `no` for systemd unit installation. |
| `ENABLE_SERVICE` | `yes` | Set to `no` to install the unit without starting it. |
| `SERVICE_NAME` | `vps-sentinel` | systemd service name. |
| `SERVICE_PATH` | `/etc/systemd/system/<SERVICE_NAME>.service` | systemd unit path. |

## Update

Review and run:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

The update script pulls the selected branch, rebuilds the binary, preserves the existing config, refreshes the systemd unit when available, and restarts the service if it is enabled.

Useful update switches:

| Variable | Default | Meaning |
| --- | --- | --- |
| `REPO_URL` | `https://github.com/cryptoli/vps-sentinel.git` | Git repository to update from. |
| `BRANCH` | `main` | Git branch to update. |
| `WORK_DIR` | `/opt/vps-sentinel-src` | Existing or new source checkout directory. |
| `PREFIX` | `/usr/local` | Binary installation prefix. |
| `CONFIG_DIR` | `/etc/vps-sentinel` | Existing config directory. |
| `DATA_DIR` | `/var/lib/vps-sentinel` | SQLite data directory for the generated unit. |
| `LOG_DIR` | `/var/log/vps-sentinel` | Log directory for the generated unit. |
| `INSTALL_SYSTEMD` | `auto` | Set to `no` to skip unit refresh. |
| `RESTART_SERVICE` | `auto` | `auto`, `yes`, or `no` for restart behavior. |

## Manual Build

```bash
git clone https://github.com/cryptoli/vps-sentinel.git
cd vps-sentinel
cargo build --release --locked
sudo install -m 0755 target/release/vps-sentinel /usr/local/bin/vps-sentinel
```

## First Run

```bash
sudo vps-sentinel init --path /etc/vps-sentinel/config.toml
sudo vps-sentinel config validate --config /etc/vps-sentinel/config.toml
sudo vps-sentinel doctor --config /etc/vps-sentinel/config.toml
sudo vps-sentinel baseline create --config /etc/vps-sentinel/config.toml
sudo vps-sentinel scan --config /etc/vps-sentinel/config.toml
```

Start the daemon:

```bash
sudo systemctl enable --now vps-sentinel
sudo journalctl -u vps-sentinel -f
```

## CLI Commands

Global options:

| Option | Meaning |
| --- | --- |
| `--config <path>` | Use a specific TOML config file. If omitted, vps-sentinel checks `config.toml`, `~/.config/vps-sentinel/config.toml`, then `/etc/vps-sentinel/config.toml`. |
| `--log-level <level>` | Set log level when `RUST_LOG` is not set. Default: `info`. |
| `--version` | Print the installed version. |
| `--help` | Show command help. |

Commands:

| Command | Meaning |
| --- | --- |
| `vps-sentinel init --path <path>` | Write a default configuration file. Fails if the file exists unless `--force` is used. |
| `vps-sentinel init --path <path> --force` | Rewrite the target config file with default content. Review before using on a tuned production config. |
| `vps-sentinel config validate --config <path>` | Parse and validate configuration without running collectors. Use after editing `config.toml`. |
| `vps-sentinel doctor --config <path>` | Check runtime readiness: root visibility, Unix target support, storage directory writability, and configured auth log visibility. |
| `vps-sentinel check --config <path>` | Run collectors and detectors once without persisting results or sending notifications. Good for quick inspection and CI-style smoke tests. |
| `vps-sentinel scan --config <path>` | Run one full scan, persist raw events/findings, update notification logs, apply deduplication, and send enabled notifications. |
| `vps-sentinel scan --no-notify --config <path>` | Persist scan results but suppress notification delivery. Useful before enabling channels. |
| `vps-sentinel daemon --config <path>` | Run continuous scans using `agent.scan_interval_seconds`; intended for systemd. |
| `vps-sentinel baseline create --config <path>` | Capture the current known-good local state into SQLite. Run after installation and after approved system changes. |
| `vps-sentinel baseline show --config <path>` | Print the stored baseline snapshot. |
| `vps-sentinel baseline diff --config <path>` | Compare current local state against the stored baseline and print drift. |
| `vps-sentinel baseline reset --config <path>` | Clear stored baselines. Run `baseline create` afterwards to capture a new trusted state. |
| `vps-sentinel events list --config <path>` | List recent stored findings; use `--limit <n>` to control the count. |
| `vps-sentinel events show <event_id> --config <path>` | Show one stored finding by ID as JSON. |
| `vps-sentinel rules list` | List built-in detection rules, severity, and descriptions. |
| `vps-sentinel rules test <rule_id>` | Verify that a built-in rule ID exists and can be loaded. |
| `vps-sentinel notify test --config <path>` | Send a synthetic Info finding through enabled notification channels. Use this to verify credentials and routing. |

## Configuration

Example: [config/config.example.toml](config/config.example.toml)

Default system path:

```text
/etc/vps-sentinel/config.toml
```

User-level path:

```text
~/.config/vps-sentinel/config.toml
```

SQLite is used by default:

```toml
[storage]
type = "sqlite"
path = "/var/lib/vps-sentinel/sentinel.db"
retention_days = 30
```

Allowlist example:

```toml
[allowlist]
users = ["deploy"]
ips = ["203.0.113.10"]
listening_ports = [22, 80, 443, 8080]
process_paths = ["/usr/local/bin/my-service"]
file_paths = ["/etc/systemd/system/my-service.service"]
```

## Alert Format

Every alert includes:

- event ID;
- host ID;
- timestamp;
- module/category;
- rule ID;
- severity;
- subject;
- evidence;
- impact;
- recommendations;
- dedup key.

Example rules:

- `SSH-001`: Root SSH login detected.
- `SSH-003`: SSH brute-force pattern detected.
- `SSH-005`: `authorized_keys` changed relative to baseline.
- `USER-002`: UID 0 user added or changed.
- `PERSIST-002`: Suspicious startup command detected.
- `PROC-003`: Reverse shell command pattern detected.
- `NET-001`: Public listening port detected.
- `FILE-002`: WebShell-like file content detected.
- `CONFIG-003`: High-risk public service port exposed.

## Deployment Notes

Some collectors need root-level visibility. If the agent runs without root permissions, `doctor` reports reduced visibility and affected modules degrade instead of crashing.

The systemd unit uses:

- `NoNewPrivileges=true`
- `ProtectSystem=full`
- `ProtectHome=read-only`
- explicit writable paths for the configured data and log directories

See [docs/deployment.md](docs/deployment.md).

## Privacy

Defaults:

- no cloud upload;
- no large log body storage;
- local SQLite only;
- notification channels disabled;
- bounded file-content scanning;
- no default destructive remediation.

Secrets such as tokens, passwords, and webhook keys belong in local config files and should not be committed.

See [docs/privacy.md](docs/privacy.md).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=cryptoli/vps-sentinel&type=Date)](https://www.star-history.com/#cryptoli/vps-sentinel&Date)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) and [docs/open-source-license.md](docs/open-source-license.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New rules must be defensive, explainable, evidence-backed, and safe by default.

## Security

Please report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Roadmap

- v0.1: CLI, config, SQLite, baseline, SSH/file/user/persistence/process/network/web-log detection, notifications, systemd.
- v0.2: deeper Docker inspection, improved dedup/aggregation, Prometheus metrics, richer rule engine.
- v0.3: local HTTP API, simple dashboard, optional dry-run active response, quarantine workflow.
