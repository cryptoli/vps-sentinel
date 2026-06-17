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
| SSH monitoring | Parses Debian/Ubuntu and RHEL-family auth logs; detects root SSH login, password login, ordinary successful login, brute-force patterns, and `authorized_keys`/`authorized_keys2` drift. |
| Baseline drift | Creates local baselines for users, SSH keys, critical files, persistence entries, and listeners; compares future scans against the stored baseline and adds package-manager context when recent software updates may explain drift. |
| User and privilege checks | Detects new users, UID 0 users, and privilege-relevant user changes. |
| File integrity | Watches configured critical paths and web roots; hashes bounded file content; detects modified files, executable scripts in web roots, and risk-scored WebShell-style marker combinations. |
| Persistence checks | Monitors cron, systemd, shell profile, and preload-related locations for new or risk-scored suspicious startup entries. |
| Process checks | Reads procfs argv, parent process, executable path, cwd, UID context, socket-FD count, CPU lifetime metrics, procfs start-time drift, cgroup/container hints, systemd unit/ExecStart, executable owner/size/hash, package ownership, and outbound connection profile to flag temporary-path executables, risk-scored deleted executables, network command-execution bridges, suspicious behavior clusters, and known miner/scanner identities. |
| Network checks | Reads listening sockets and owning process details; attaches process context and firewall state; flags high-risk public services, suspicious listener processes, baseline owner drift, and ordinary new public listeners. Expected web/SSH ports such as 22, 80, and 443 reduce noise but are not blindly trusted. |
| Web log checks | Parses common access log lines, classifies automated probing into attack families, and aggregates similar paths from the same source to avoid path-by-path alert floods. |
| Rootkit signals | Collects lightweight local indicators for hidden process and suspicious procfs behavior. |
| Docker context | Detects Docker availability and emits initial container-surface context without requiring Docker-specific write access. |
| Storage | Stores raw events, findings, baselines, and notification logs in local SQLite; repeated raw facts use stable storage keys and a configurable database size cap to prevent unbounded growth. |
| Noise control | Uses allowlists, minimum severity, finding deduplication, and configurable retention windows. |
| Active response | Optionally blocks strict, high-confidence public-source web probes and SSH brute-force sources through nftables or iptables with TTL-based expiry. Disabled by default. |
| Notifications | Sends alerts through Telegram, Email SMTP, generic webhook, ntfy, Gotify, Bark, and ServerChan. |
| Operations | Provides a single CLI binary, `vs` shorthand, JSON logs, systemd unit, one-command installer, update script, built-in reload command, and stop helper. |

## Detection Model

The command-execution rules are behavior-profile rules, not simple tool-name or port-name rules. vps-sentinel keeps argv as structured data from `/proc/<pid>/cmdline`, builds a small command profile, and only raises `PROC-003`/`NET-003` when high-risk features combine, such as network channels bridged into shell targets, `SYSTEM:` command runners, fd duplication, inline socket code, or TTY allocation.

Known miner/scanner detection is intentionally narrower: `PROC-004` matches known tool names such as `xmrig`, `masscan`, and `zmap` against process identity fields such as executable path, process name, and structured `argv[0]`, including `.exe` suffixes. It does not treat arbitrary substrings or ordinary command arguments as a hit when structured process identity is available. When procfs CPU data is available, alerts include lifetime average CPU, process age, and total CPU seconds; sustained high CPU strengthens the finding but high CPU alone is not enough to alert.

Deleted-executable and persistence-startup alerts are also scored. `PROC-002` requires additional suspicious traits such as a temporary executable path, memfd or anonymous backing, a hidden non-standard executable, a network execution bridge, or a known miner/scanner identity. A package-upgrade residue such as `systemd`, `dockerd`, or `python3` running from a deleted standard system path is treated as maintenance context unless other risk traits are present. `PERSIST-002` scores startup lines for combinations such as download-to-shell, temporary-path autostart payloads, base64 decode-to-shell, and network-to-shell execution bridges; a plain `bash -c` service wrapper is not enough by itself.

File and persistence baseline drift is not suppressed just because package-manager activity exists. Instead, the agent collects recent apt/dpkg/yum/dnf/pacman/apk log activity and attaches that context to `FILE-001`, `PERSIST-001`, and `PERSIST-003` recommendations. This keeps real drift visible while making legitimate package updates easier to confirm before refreshing the baseline.

WebShell content detection is risk-scored instead of marker-only. A single marker such as `eval` in a legitimate admin script is below the default threshold. Combinations such as command execution in a script-like web path, dynamic execution plus encoded payload markers, command execution plus encoding, or large encoded payloads in script-like web paths raise `FILE-002`.

`PROC-005` covers renamed or lightly disguised processes that may not expose a known tool name, temporary executable path, or obvious network shell bridge. It combines weaker behavior signals such as kernel-thread masquerading, execution from configured web roots, hidden executable names, suspicious working directories, socket-FD activity, sustained high CPU, procfs start-time drift for the same process identity, and effective-root privilege context. No single weak signal is enough at the default threshold, and start-time drift only contributes after other suspicious context already exists.

Process and listener findings now include a broader evidence chain when the host exposes it: parent process name, systemd unit, systemd `ExecStart`, executable UID/GID, executable size, bounded BLAKE3 hash, dpkg/rpm/pacman/apk package ownership, cgroup/container context, procfs start-time drift, outbound connection counts, public outbound count, and remote port profile. Package ownership queries and firewall probes are bounded by short command timeouts and per-scan caching, so missing or slow platform tools degrade to absent evidence instead of blocking a scan. These fields are used as supporting evidence or weak signals. For example, a systemd `ExecStart` mismatch does not alert by itself, but it can upgrade an already changed listener owner into a suspicious-listener finding.

Firewall state is auxiliary context, not the source of truth. Socket exposure still comes from `/proc/net/*`; `ufw`, `firewalld`, `nftables`, and `iptables` status are attached so operators can decide whether a public listener is actually reachable through local policy.

## Notification Channels

All notification channels are disabled by default. Enable only the channels you need in `config.toml`.

| Channel | Config section | Required fields | Typical use |
| --- | --- | --- | --- |
| Telegram | `[notifications.telegram]` | `enabled`, `bot_token`, `chat_id` | Personal or team security alerts through a Telegram bot. |
| Email SMTP | `[notifications.email]` | `enabled`, `smtp_host`, `smtp_port`, `from`, `to` | Traditional mailbox alerts for operations teams. Supports STARTTLS, implicit TLS, and local plaintext relays. |
| Webhook | `[notifications.webhook]` | `enabled`, `url` | Custom HTTP receivers, automation platforms, or self-hosted alert routers. Sends raw `Finding` JSON plus `X-Vps-Sentinel-Vps-Name`. |
| ntfy | `[notifications.ntfy]` | `enabled`, `server`, `topic` | Push notifications through ntfy.sh or self-hosted ntfy. |
| Gotify | `[notifications.gotify]` | `enabled`, `server`, `token` | Self-hosted push notifications. |
| Bark | `[notifications.bark]` | `enabled`, `server`, `device_key` | iOS push notifications through Bark. |
| ServerChan | `[notifications.serverchan]` | `enabled`, `send_key` | WeChat-style notifications through ServerChan. |

Each channel supports `min_severity`, so low-priority findings can be kept local while higher-risk findings are sent out. HTTP-based channels share `notifications.request_timeout_seconds`, which defaults to 15 seconds. Human-facing channels use a template strategy: Telegram uses Telegram-compatible HTML, Email sends multipart plain-text plus full HTML, ServerChan and Gotify use Markdown, and ntfy/Bark use plain text for maximum client compatibility.

Notification text supports English and Simplified Chinese:

```toml
[notifications]
request_timeout_seconds = 15
language = "en" # en or zh_cn
time_zone = "local" # local or utc
include_technical_fields = false
```

The selected language controls field labels and built-in rule content such as alert titles, descriptions, impact, and recommendations. Timestamps are rendered consistently as `YYYY-MM-DD HH:MM:SS +08:00` for local time or `YYYY-MM-DD HH:MM:SS UTC` for UTC. Technical identifiers such as rule ID, event ID, and dedup key are hidden by default; set `include_technical_fields = true` when you need them for support or automation.

Alert subjects include the configured VPS name so multi-server deployments are easy to scan:

```toml
[agent]
display_name = "prod-web-1"
hostname = "prod-web-1.example.com"
host_id = "prod-web-1"
```

`display_name` is the human-readable VPS name used in notification titles. `host_id` stays the stable technical identifier used in findings, storage, and deduplication. If `display_name` is empty, vps-sentinel falls back to `hostname`, then `host_id`, then `local-host`.

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

## Linux Compatibility

vps-sentinel targets Linux VPS hosts with `/proc`, a POSIX shell, and root-level visibility. It builds from source with Rust 1.76+ and uses rustls plus bundled SQLite, so it does not require system OpenSSL or a system SQLite development package.

| Environment | Compatibility |
| --- | --- |
| Debian / Ubuntu | First-class. Installer uses `apt-get`; SSH auth logs usually come from `/var/log/auth.log`, with `journalctl` fallback on systemd hosts. |
| RHEL family, Rocky, AlmaLinux, CentOS, Amazon Linux | First-class. Installer uses `dnf` or `yum`; SSH auth logs usually come from `/var/log/secure`. |
| Fedora | First-class through `dnf` and systemd. |
| Arch / Manjaro | Supported through `pacman`; package activity context reads `/var/log/pacman.log`. |
| Alpine | Best-effort supported through `apk`. The binary can run on musl targets, but systemd service installation is skipped unless systemd is actually present. Use another supervisor or run `vps-sentinel daemon --config ...` manually. |
| Generic Linux | Supported when `curl`, `git`, a C toolchain, `pkg-config`, Rust, and procfs are available. Set `INSTALL_DEPS=no` if the package manager is unsupported. |
| Non-Linux Unix / Windows | Not a runtime target. The code may compile for development, but host monitoring depends on Linux procfs, auth logs, and Linux filesystem layout. |

CI runs the normal Rust test suite on Ubuntu, validates shell scripts, runs a temporary installer smoke test, and runs container compatibility tests on Debian Bookworm and Alpine musl. Release workflow targets are prepared for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, and `aarch64-unknown-linux-musl`.

systemd is optional for installation but required for service reload/start/stop management. Without systemd, the installer still builds the binary and writes configuration; run the daemon under your own init system. Running as non-root degrades visibility instead of crashing, but SSH logs, `/proc/<pid>/fd`, protected files, and persistence paths may be incomplete.

The Docker containers used in CI are build and compatibility test environments only. A normal containerized runtime can only see the container's own process table, filesystem, and logs, so it is not a reliable way to monitor host compromise. For production host intrusion monitoring, install the daemon directly on the VPS host with root visibility, preferably through the provided systemd unit.

## Implementation And Effect

| Feature | Implementation | Practical effect |
| --- | --- | --- |
| SSH login monitoring | Reads configured auth logs and falls back to `journalctl` for `ssh.service`/`sshd.service` when files are absent. | Detects root logins, password logins, ordinary successful logins, and brute-force clusters by source IP. |
| SSH key integrity | Hashes `authorized_keys` and `authorized_keys2` independently of the broader file-integrity switch. | Detects SSH persistence changes even when general file integrity is disabled. |
| File and persistence drift | Builds a local SQLite baseline, diffs later snapshots, coalesces related file/persistence findings for the same path, and attaches package-manager context. | Finds real drift while reducing confusion during legitimate package updates; baseline is refreshed only by explicit command. |
| WebShell content | Scans bounded file content for risk markers and scores marker combinations plus web-path context. | Avoids alerting on one weak marker, while catching classic web command execution and encoded payload patterns. |
| Web probing | Groups `WEB-001` by source IP, probe family, and response profile. Missing/rejected probes such as 404 PHPUnit directory sweeps are Low context; successful sensitive-file responses or protected exploit paths are raised. | A scanner hitting many path variants creates one readable finding instead of dozens of Telegram messages. |
| Process risk | Reads procfs argv, parent, executable, cwd, UID/EUID, deleted state, socket-FD count, lifetime CPU metrics, start-time drift, cgroup/container hints, systemd unit/ExecStart, executable metadata/hash, package owner, and outbound connection profile; uses rule-specific scoring, allowlists, rule-state storage, and same-PID signal coalescing. `PROC-005` requires a primary evasion/location signal before socket, outbound, restart, or root-context signals can alert. | Detects temp-path executables, suspicious deleted executables, network shell bridges, known miner/scanner identities, and renamed behavior clusters while avoiding duplicate messages caused by volatile PID/CPU/connection counters or normal high-connection services. |
| Network listeners | Parses `/proc/net/tcp*` and `/proc/net/udp*`, resolves owning processes through `/proc/<pid>/fd`, compares listener owners with baseline, attaches process/firewall context, and prioritizes suspicious owner behavior over generic port exposure. | Expected 22/80/443 ports reduce generic noise but still produce findings when the owning process changes or looks suspicious; high-risk ports keep their service and firewall profile as evidence. |
| Notifications | Renders one `Finding` model through channel-specific templates: Telegram HTML, Email HTML/plain text, Markdown-aware channels, or plain text. | Messages include the configured VPS name, normalized time, localized labels, evidence, impact, and recommendations. |
| Noise control | Applies scan-level deduplication, persisted dedup windows, state reminder intervals, quiet hours, and hourly notification budgets. | Reduces repeat messages while keeping high-value alerts visible. |
| Active response | Evaluates current findings after scan-level coalescing/deduplication and before persisted notification deduplication; only public IPs outside `[allowlist].ips` can be blocked. Web blocks require successful sensitive responses, repeated exploit-family probes, or high-volume probe/error bursts; SSH blocks require a stricter failed-login threshold than the alert rule. | Lets operators turn noisy, obvious scanners into temporary firewall drops without making every alert destructive. |

## Quick Install

Review the script before running it:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o install.sh
sudo sh install.sh
```

The installer:

- detects apt, dnf, yum, apk, or pacman;
- installs build dependencies if needed;
- tries to install a release artifact by default and falls back to a source build when the artifact is unavailable or cannot execute on the host;
- installs Rust with rustup when a source build is needed and `cargo` is missing;
- clones this repository to `/opt/vps-sentinel-src` only for source builds;
- builds `vps-sentinel` in release mode when source fallback is used;
- installs the binary to `/usr/local/bin/vps-sentinel` and the shorthand symlink `/usr/local/bin/vs`;
- installs `vps-sentinel-install`, `vps-sentinel-update`, and `vps-sentinel-stop` helper commands when the package or source tree contains them;
- tests a downloaded release binary with `--version` before installing it; if it cannot run on the host, the installer falls back to a source build;
- creates `/etc/vps-sentinel/config.toml` only if it does not already exist;
- optionally writes Telegram settings from environment variables;
- installs the systemd unit before baseline bootstrap when systemd is available;
- removes deprecated config keys after writing a `.bak` backup, unless `MIGRATE_CONFIG=no`;
- validates config, runs `doctor`, creates the first baseline when missing, and runs one no-notify warm-up scan;
- enables the systemd service after the baseline includes the installed unit.

Configuration can be customized through environment variables:

```bash
sudo REPO_URL=https://github.com/cryptoli/vps-sentinel.git \
  BRANCH=main \
  WORK_DIR=/opt/vps-sentinel-src \
  PREFIX=/usr/local \
  sh install.sh
```

Install with Telegram enabled in one command:

```bash
sudo TELEGRAM_BOT_TOKEN="<telegram-bot-token>" \
  TELEGRAM_CHAT_ID="<telegram-chat-id>" \
  TELEGRAM_MIN_SEVERITY=Medium \
  VPS_NAME=prod-web-1 \
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
| `INSTALL_METHOD` | `auto` | `auto` and `release` try a release artifact first and fall back to source if the artifact is missing or cannot execute on the host; `source` always builds locally. |
| `RELEASE_VERSION` | `latest` | Release tag to download when `INSTALL_METHOD` is `auto` or `release`. |
| `RELEASE_ARTIFACT_URL` | empty | Override the release artifact URL. Useful for mirrors, local artifact testing, and CI smoke tests. |
| `TARGET_TRIPLE` | auto-detected | Override release artifact target, for example `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-musl`. |
| `INSTALL_SYSTEMD` | `auto` | `auto`, `yes`, or `no` for systemd unit installation. |
| `ENABLE_SERVICE` | `yes` | Set to `no` to install the unit without starting it. |
| `RUN_DOCTOR` | `yes` | Run runtime environment checks during install. |
| `MIGRATE_CONFIG` | `yes` | Remove deprecated config keys after writing a `.bak` backup. Set to `no` to skip. |
| `BOOTSTRAP_BASELINE` | `yes` | Create the first baseline if no baseline exists. |
| `RUN_FIRST_SCAN` | `yes` | Run one `scan --no-notify` and write full output to `<LOG_DIR>/first-scan.log`. |
| `VPS_NAME` | empty | Optional human-readable VPS name written to `agent.display_name`; shown in notification subjects. |
| `TELEGRAM_BOT_TOKEN` | empty | Telegram bot token to write into local config. |
| `TELEGRAM_CHAT_ID` | empty | Telegram chat ID to write into local config. |
| `TELEGRAM_MIN_SEVERITY` | `Medium` | Minimum severity for Telegram notifications. |
| `RUN_NOTIFY_TEST` | `auto` | `auto`, `yes`, or `no`; `auto` sends a test when Telegram env vars are provided. |
| `STORAGE_MAX_DATABASE_SIZE_MB` | empty | Optional override for `[storage].max_database_size_mb`. Existing configs are changed only when this variable is set. |
| `ACTIVE_RESPONSE_ENABLED` | empty | Set to `yes` to write `active_response.enabled = true`; active response is disabled unless explicitly enabled. |
| `ACTIVE_RESPONSE_FIREWALL_BACKEND` | empty | Optional `auto`, `nftables`, or `iptables` backend override. |
| `ACTIVE_RESPONSE_BLOCK_TTL_SECONDS` | empty | Optional temporary block TTL override. |
| `ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN` | empty | Optional cap for new blocks in one scan. |
| `ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD` | empty | Optional high-volume Web probe block threshold. |
| `ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD` | empty | Optional repeated exploit-family Web probe block threshold. |
| `ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD` | empty | Optional SSH brute-force block threshold. |
| `SERVICE_NAME` | `vps-sentinel` | systemd service name. |
| `SERVICE_PATH` | `/etc/systemd/system/<SERVICE_NAME>.service` | systemd unit path. |

## Update

Review and run:

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

The update script pulls the selected branch, rebuilds the binary, preserves the existing config, removes deprecated config keys after writing a `.bak` backup, validates it, refreshes the systemd unit when available, updates the `vs` shorthand, and restarts an active or enabled service so the new binary is actually running. It does not refresh an existing baseline by default, so unreviewed host drift such as `authorized_keys` changes is not silently trusted during an update. Unchanged systemd unit content is not rewritten, so routine updates do not churn unit file mtimes. Use `vps-sentinel reload` or `vs reload` for config-only changes that do not replace the binary.

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
| `RESTART_SERVICE` | `auto` | `auto`, `yes`, or `no` for reload/restart behavior. |
| `VALIDATE_CONFIG` | `yes` | Validate existing config before service reload/restart. |
| `MIGRATE_CONFIG` | `yes` | Remove deprecated config keys after writing a `.bak` backup. Set to `no` to skip. |
| `REFRESH_BASELINE` | `no` | Set to `yes` only after you have reviewed current drift and want the update to refresh the existing baseline. |

## Reload Configuration

After editing `/etc/vps-sentinel/config.toml`, reload safely:

```bash
sudo vps-sentinel reload
sudo vs reload
```

Equivalent systemd command:

```bash
sudo systemctl reload vps-sentinel
```

The reload path validates the TOML first, then asks systemd to reload the running service. If validation fails, the daemon keeps the previous in-memory configuration.

## Stop Service

Stop the daemon without deleting configuration, baselines, logs, or the binary:

```bash
sudo vps-sentinel-stop
```

Equivalent systemd command:

```bash
sudo systemctl stop vps-sentinel
```

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

Installed shorthand:

| Command | Meaning |
| --- | --- |
| `vs ...` | Short alias for `vps-sentinel ...`, installed as a symlink by `install.sh`, `update.sh`, and release packages. |

Commands:

| Command | Meaning |
| --- | --- |
| `vps-sentinel init --path <path>` | Write a default configuration file. Fails if the file exists unless `--force` is used. |
| `vps-sentinel init --path <path> --force` | Rewrite the target config file with default content. Review before using on a tuned production config. |
| `vps-sentinel config validate --config <path>` | Parse and validate configuration without running collectors. Use after editing `config.toml`. |
| `vps-sentinel config print-default` | Print the built-in default configuration as TOML. |
| `vps-sentinel config diff-default --config <path>` | Compare a config file with current defaults and list missing, unknown, and deprecated keys. |
| `vps-sentinel config migrate --config <path>` | Remove deprecated keys after writing a `.bak` backup and validating the migrated config. |
| `vps-sentinel config migrate --dry-run --config <path>` | Show deprecated keys that would be removed without changing the file. |
| `vps-sentinel reload --config <path>` | Validate the config and reload the running systemd service. Use `vs reload` after installing the shorthand. |
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
| `vps-sentinel-stop` | Stop the running systemd service while keeping config, data, logs, and binaries in place. |

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
max_database_size_mb = 256
```

`retention_days` removes old raw events, findings, notification logs, and scan runs by time. `max_database_size_mb` is an additional disk-safety cap. When the SQLite database plus WAL/SHM sidecars exceed the cap, vps-sentinel prunes the oldest high-volume rows, checkpoints WAL, runs `VACUUM`, and keeps baseline/rule-state tables intact. This protects small VPS disks from historical log growth; choose a larger cap if you need longer local forensics history.

SSH alert policy:

```toml
[ssh]
alert_on_root_login = true
alert_on_password_login = true
alert_on_successful_login = true
auth_log_lookback_seconds = 300
```

`alert_on_successful_login` covers ordinary successful SSH logins that are not already reported by the root-login or password-login rules. It is not limited to unfamiliar IP addresses. Ordinary successful-login findings are `Info`; root login remains `High`, and password login remains `Medium`. SSH login deduplication uses user plus source IP, while the session port is kept as evidence only. SSH brute-force deduplication uses the source IP, so a rising failure count does not create a new notification key every scan. `auth_log_lookback_seconds` limits how far back auth logs are considered on each scan so old login lines do not keep generating notifications. When configured auth log files such as `/var/log/auth.log` and `/var/log/secure` are absent, vps-sentinel falls back to `journalctl` for `ssh.service` and `sshd.service`.

File-integrity scoring:

```toml
[file_integrity]
webshell_min_score = 70
```

`webshell_min_score` controls when `FILE-002` is emitted. The detector scores marker combinations and web-script context instead of alerting on one isolated marker, which reduces false positives in legitimate admin scripts while still catching classic web command execution and encoded command-execution patterns.

Package-manager context:

```toml
[package_manager]
enabled = true
recent_activity_window_seconds = 3600
max_log_tail_bytes = 8192
log_paths = [
  "/var/log/dpkg.log",
  "/var/log/apt/history.log",
  "/var/log/yum.log",
  "/var/log/dnf.log",
  "/var/log/pacman.log",
  "/var/log/apk.log",
]
```

Recent package-manager activity is attached as evidence to file and persistence drift findings. It is not an allowlist and does not refresh the baseline automatically; review the drift against package logs first, then run `baseline create` only after the change is trusted.

VPS identity in alerts:

```toml
[agent]
display_name = "prod-web-1"
hostname = "prod-web-1.example.com"
host_id = "prod-web-1"
```

Network alert policy:

```toml
[network]
alert_on_new_listening_port = true
expected_public_ports = [22, 80, 443]
high_risk_public_ports = [2375, 2376, 3306, 5432, 6379, 9200, 27017]
public_listen_allowlist = [22, 80, 443]
```

- `expected_public_ports` suppresses generic public-listener noise for normal exposed services such as SSH, HTTP, and HTTPS.
- Expected ports are not blindly trusted. vps-sentinel still checks the owning process, executable path, command line, and baseline owner drift, so a suspicious process behind 80/443 can still produce `NET-002` or `NET-003`.
- `high_risk_public_ports` is the configurable high-risk service list. These ports are reported from the current socket state unless explicitly allowlisted in `[allowlist].listening_ports`. If the owning process is also suspicious, `NET-003` takes priority and includes the service profile instead of sending a separate generic `CONFIG-003` alert.
- Public exposure is address-aware: `0.0.0.0`, `::`, and specific routable public addresses are treated as public; loopback, RFC1918 IPv4, IPv6 ULA, and link-local listeners are ignored for public-listener rules.
- `public_listen_allowlist` is treated as a legacy alias for expected public ports. Use `[allowlist].listening_ports` only when you intentionally want to suppress all network findings for a port.
- `NET-001` is emitted only for ordinary TCP/TCP6 public ports that are new relative to the stored baseline, not for every stable listening socket on every scan. Generic UDP high ports are treated as dynamic traffic unless they match a high-risk service port or a suspicious listener process.

Process indicator policy:

```toml
[process]
deleted_executable_min_score = 70
behavior_min_score = 70
high_cpu_threshold_percent = 80.0
high_cpu_duration_seconds = 120
suspicious_socket_fd_threshold = 20
known_bad_tool_names = ["xmrig", "kinsing", "masscan", "zmap"]
```

`deleted_executable_min_score` controls when `PROC-002` is emitted. Deleted executable state is scored with path, process identity, and command-behavior traits; a standard system binary left running after a package upgrade is not enough by itself. `behavior_min_score` controls `PROC-005`, which combines weak process signals such as kernel-thread masquerading, web-root execution, hidden executable names, suspicious cwd, socket-FD activity, sustained high CPU, procfs start-time drift for the same process identity, and effective-root context. Start-time drift is stored in local rule state and only strengthens an already suspicious process; a normal restart does not alert by itself. `high_cpu_threshold_percent` and `high_cpu_duration_seconds` define sustained high CPU using procfs lifetime CPU time and process age; high CPU is a supporting signal, not an alert condition by itself. `suspicious_socket_fd_threshold` defines when socket ownership becomes a stronger behavior signal. `known_bad_tool_names` controls the `PROC-004` known miner/scanner indicator list. Values are matched against process identity fields such as `exe_path`, `executable`, process name, and structured `argv[0]`, with `.exe` suffixes accepted. Legacy events without structured identity fall back to command token basename matching. When several process rules match the same PID, the scanner keeps one highest-value finding and merges the process signals, risk reasons, impact, and recommendations.

Persistence indicator policy:

```toml
[persistence]
suspicious_command_min_score = 70
```

`suspicious_command_min_score` controls when `PERSIST-002` is emitted. Startup commands are scored by combined traits such as download-to-shell, temporary-path autostart payloads, encoded shell payloads, and network execution bridges. Plain shell wrappers used by legitimate systemd units do not cross the default threshold on their own.

Web log policy:

```toml
[web]
error_burst_threshold = 20
```

`WEB-001` is emitted for known probe families such as `.env`, `.git`, PHPUnit `eval-stdin.php`, CGI shell traversal, command injection, SQL injection, phpMyAdmin, WordPress admin, actuator, and server-status probes. Similar path variants are aggregated by source IP, probe family, and response profile. A pure 404/400/301 directory sweep is Low by default; successful responses for sensitive paths are High, while rejected active exploit payloads remain Medium context. `error_burst_threshold` controls when `WEB-002` is emitted for repeated 403/404 responses from one source IP that did not already produce a probe-family finding. Lower it on small private services where any probing matters; raise it on busy public sites that naturally receive high volumes of missing-asset requests.

Active response:

```toml
[active_response]
enabled = false
firewall_backend = "auto"
block_ttl_seconds = 3600
max_blocks_per_scan = 20
web_probe_block_threshold = 25
web_exploit_block_threshold = 5
ssh_failed_login_block_threshold = 20
```

Active response is disabled by default because it changes local firewall policy. When enabled, the scanner applies it after scan-level coalescing/deduplication but before persisted notification deduplication, so an escalating source can still be blocked even when repeated notifications are suppressed. Quiet hours and notification rate limits do not prevent blocking. The backend uses nftables when available and falls back to iptables/ip6tables. Blocks are temporary: nftables uses set timeouts and vps-sentinel also stores block state in SQLite so expired entries can be removed on later scans. Only public routable source IPs are eligible, and `[allowlist].ips` always wins.

Noise control:

```toml
[noise_control]
dedup_window_seconds = 3600
state_reminder_interval_seconds = 86400
max_alerts_per_hour = 30
rate_limit_bypass_min_severity = "High"
quiet_hours_bypass_min_severity = "High"
```

`dedup_window_seconds` suppresses repeated event findings with the same stable dedup key. `state_reminder_interval_seconds` applies to durable state findings such as risky SSH configuration, Docker socket presence, baseline drift, persistent processes, and webshell-like files; the default 24-hour interval prevents unchanged host state from sending the same message after every restart or hourly scan. New subjects, sources, or rule evidence still create distinct findings. `max_alerts_per_hour` limits lower-severity notification volume; findings at or above `rate_limit_bypass_min_severity` bypass that hourly budget so high-value signals such as `SSH-005` are still delivered during noisy periods. When `quiet_hours` is active, findings below `quiet_hours_bypass_min_severity` are suppressed; the default keeps High and Critical alerts visible.

Allowlist example:

```toml
[allowlist]
users = ["deploy"]
ips = ["203.0.113.10"]
listening_ports = [22, 80, 443, 8080]
process_paths = ["/usr/local/bin/my-service"]
process_command_contains = ["trusted-forwarder tcp-listen:8443"]
file_paths = ["/etc/systemd/system/my-service.service"]
```

`process_command_contains` is a substring-based escape hatch for known-good long-running commands. Prefer exact enough fragments that identify your intended command instead of broad process names.

`PROC-003` is not triggered by a forwarding tool name, an IP address, a listening argument, or `/bin/sh -c` by itself. The detector builds a command profile from `/proc/<pid>/cmdline` argv and requires high-confidence behavior combinations such as:

- `/dev/tcp` plus an interactive shell and file-descriptor redirection;
- a network channel bridged directly to a shell target through `-e`, `--exec`, `EXEC:`, or `SHELL:`;
- a network channel bridged to a `SYSTEM:` command runner;
- an inline interpreter using socket APIs, fd duplication, and a shell target;
- a network command allocating a TTY for a shell.

Normal service wrappers such as `/bin/sh -c '/usr/local/bin/app --listen 0.0.0.0:443'` and ordinary TCP/UDP forwarding commands should not trigger `PROC-003`.

## Release Engineering

The repository includes a release workflow but publishing is intentionally tag-driven. A `v*` tag builds Linux tarballs for GNU and musl targets on x86_64/aarch64, validates package contents, generates SHA-256 checksum files, builds `.deb` and `.rpm` packages from the x86_64 GNU artifact, and uploads them to the GitHub release. The installer is prepared to consume these artifacts through `INSTALL_METHOD=auto` or `INSTALL_METHOD=release`, and `RELEASE_ARTIFACT_URL` supports mirrors or local package smoke tests.

Until a release exists, `INSTALL_METHOD=auto` and `INSTALL_METHOD=release` fall back to the existing source build path. Packaged installs still create `/etc/vps-sentinel/config.toml`, install the `vs` shorthand and helper scripts, validate config, bootstrap a baseline, and install systemd when available.

## Alert Format

User-facing alerts include:

- VPS display name;
- host ID;
- normalized timestamp;
- module/category;
- severity;
- subject;
- evidence;
- impact;
- recommendations;

When `notifications.include_technical_fields = true`, alerts also include rule ID, event ID, and dedup key.

Example rules:

- `SSH-001`: Root SSH login detected.
- `SSH-002`: Password-based SSH login detected.
- `SSH-003`: SSH brute-force pattern detected.
- `SSH-004`: SSH login detected.
- `SSH-005`: `authorized_keys` or `authorized_keys2` changed relative to baseline.
- `USER-002`: UID 0 user added or changed.
- `PERSIST-002`: Suspicious startup command detected.
- `PROC-002`: Risk-scored deleted executable still running.
- `PROC-003`: Network command execution bridge detected.
- `PROC-005`: Suspicious process behavior cluster.
- `NET-001`: New public listening port detected relative to baseline.
- `NET-002`: Public listener process changed relative to baseline.
- `NET-003`: Suspicious process behind a public listener.
- `FILE-002`: WebShell-like file content detected.
- `CONFIG-003`: High-risk public service port exposed.

## Deployment Notes

Some collectors need root-level visibility. If the agent runs without root permissions, `doctor` reports reduced visibility and affected modules degrade instead of crashing.

Runtime footprint is intentionally small for a continuously running agent. On the current validation VPS, the daemon process reports about 10-13 MiB RSS during the normal 60-second scan loop. systemd cgroup `MemoryCurrent` can be much higher, from tens of MiB to a few hundred MiB, because Linux may charge recently touched file cache and cgroup memory accounting to the service. Actual memory pressure depends on log tail size, file-integrity path scope, kernel accounting, and enabled notification channels; process RSS is the best steady-state indicator for the daemon itself. Raw event storage uses stable keys for repeated facts, so rescanning the same log tail or unchanged host state replaces rows instead of appending identical data every minute. SQLite storage is additionally bounded by `storage.max_database_size_mb`; when the cap is exceeded, old high-volume rows are pruned and SQLite is vacuumed to reclaim disk space.

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
- no default destructive remediation; firewall blocking runs only when `[active_response].enabled = true`.

When `privacy.mask_ip` or `privacy.mask_command_args` is enabled, stored events, findings, and notification evidence are redacted before persistence and delivery.

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
