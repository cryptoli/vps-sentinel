# vps-sentinel

Lightweight Rust intrusion-signal monitoring for Linux VPS hosts.

`vps-sentinel` helps VPS owners discover suspicious SSH logins, changed `authorized_keys`, unexpected users, privilege changes, startup persistence, suspicious processes, new public listening ports, WebShell-like files, web probing, and common risky configuration. It is local-first, transparent, and designed for small servers instead of heavyweight SIEM/EDR deployments.

[中文说明](README.zh-CN.md)

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

## Features

- Single Rust CLI binary: `vps-sentinel`.
- Local SQLite storage.
- TOML configuration.
- JSON structured logging.
- Baseline create/show/diff/reset.
- SSH auth log parsing for Debian/Ubuntu and RHEL-family logs.
- `authorized_keys`, user, cron, systemd, shell profile, and file integrity drift detection.
- Process anomaly checks for temporary-path executables, deleted executables, reverse-shell patterns, miners, and scanners.
- Network listener checks for public ports and risky service ports.
- Web access log checks for common vulnerability probes.
- WebShell-like file marker detection with bounded content scanning.
- Unified `Finding` model with severity, rule ID, evidence, impact, recommendations, and dedup key.
- Pluggable notifier trait with Telegram, Email SMTP, Webhook, ntfy, Gotify, Bark, and ServerChan implementations.
- systemd unit, one-command installer, and update script.

## Architecture

```text
vps-sentinel/
  crates/
    sentinel-core/   # config, errors, severity, RawEvent, Finding
    sentinel-agent/  # collectors, detectors, baseline, SQLite, notifiers, daemon
    sentinel-cli/    # vps-sentinel command line
  config/            # example configuration
  packaging/         # systemd unit and package-time install helper
  docs/              # deployment, privacy, rule and notifier guides
```

Collectors gather facts. Detectors convert facts into findings. Storage and notifications only consume the unified `Finding` model, so new rules and channels can be added without coupling modules together.

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

## Update

Review and run:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

The update script pulls the selected branch, rebuilds the binary, preserves the existing config, and restarts the service if it is enabled.

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

## CLI

```bash
vps-sentinel --version
vps-sentinel init
vps-sentinel check
vps-sentinel scan
vps-sentinel daemon
vps-sentinel baseline create
vps-sentinel baseline show
vps-sentinel baseline diff
vps-sentinel baseline reset
vps-sentinel events list
vps-sentinel events show <event_id>
vps-sentinel rules list
vps-sentinel rules test <rule_id>
vps-sentinel notify test
vps-sentinel config validate
vps-sentinel doctor
```

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

Webhook notification example:

```toml
[notifications.webhook]
enabled = true
url = "https://example.com/security-webhook"
secret = ""
min_severity = "Medium"
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
- explicit writable paths for `/var/lib/vps-sentinel` and `/var/log/vps-sentinel`

See [docs/deployment.md](docs/deployment.md).

## Privacy

Defaults:

- no cloud upload;
- no large log body storage;
- local SQLite only;
- notification channels disabled;
- bounded file-content scanning;
- no default destructive remediation.

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
