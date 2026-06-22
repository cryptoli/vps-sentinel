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
| SSH monitoring | Parses Debian/Ubuntu and RHEL-family auth logs; detects root SSH login, password login, ordinary successful login, brute-force patterns, brute-force followed by success, `authorized_keys`/`authorized_keys2` drift, unsafe key-file permissions, and risky key-file symlinks. |
| Baseline drift | Creates local baselines for users, SSH keys, critical files, persistence entries, and listeners; compares future scans against the stored baseline, exposes approval keys for reviewed drift, and adds package-manager context when recent software updates may explain drift. |
| User and privilege checks | Detects new users, UID 0 users, and privilege-relevant user changes. |
| File integrity | Watches configured critical paths and web roots; hashes bounded file content; detects modified files, executable scripts in web roots, and risk-scored WebShell-style marker combinations. |
| Log integrity | Watches sensitive authentication/login log files for risky symlinks and abrupt size drops that are not explained by recent rotation context. |
| Persistence checks | Monitors cron, systemd, shell profile, and preload-related locations for new or risk-scored suspicious startup entries. |
| Process and GPU checks | Reads procfs argv, parent process, executable path, cwd, UID context, socket-FD count, CPU lifetime metrics, procfs start-time drift, structured cgroup/container context, systemd unit/ExecStart, executable owner/size/hash, package ownership, outbound connection profile, NVIDIA GPU compute-process facts via `nvidia-smi`, and AMD/ROCm GPU process facts via `rocm-smi`. It flags risk-scored suspicious executable paths, deleted executables, network command-execution bridges, suspicious behavior clusters, known miner/scanner identities, and suspicious GPU compute workloads. |
| Network checks | Reads listening sockets and owning process details; attaches process context and firewall state; flags high-risk public services, suspicious listener processes, baseline owner drift, and ordinary new public listeners. Expected web/SSH ports such as 22, 80, and 443 reduce noise but are not blindly trusted. |
| Web log checks | Parses common access logs, JSON access logs, Nginx-style error log request context, and optional `.1` rotated logs; classifies automated probing into attack families and aggregates similar paths from the same source to avoid path-by-path alert floods. |
| Rootkit signals | Collects lightweight local indicators for hidden process and suspicious procfs behavior. |
| Docker context | Detects Docker availability and emits initial container-surface context without requiring Docker-specific write access. |
| Incident correlation | Correlates findings by source IP, path, process, category, and time window into local incidents with timelines. |
| Service profile | Maintains a service-owner profile for listening sockets and reports new services or executable drift on known listeners. |
| Advanced collectors | Reads auditd logs when present and accepts an eBPF JSONL/command bridge when configured. The collectors are enabled by default and safely produce no events when their inputs are absent. |
| External rules | Supports Sigma-like TOML event rules and optional YARA CLI scans for user-supplied defensive rules. The rule engine is enabled by default; it runs only when rule or scan paths are configured. |
| Threat intelligence | Optionally enriches findings with local or remote indicators for IPs, paths, domains, and hashes. Indicator matches are supporting evidence, not standalone block triggers. |
| Fleet view | Exports and ingests lightweight node snapshots so several VPS hosts can be reviewed from one local SQLite store. |
| Maintenance mode | Provides a bounded maintenance window that can suppress low/medium baseline drift during planned upgrades without hiding high-risk activity. |
| Storage | Stores raw events, findings, baselines, and notification logs in local SQLite; repeated raw facts use stable storage keys and a configurable database size cap to prevent unbounded growth. |
| Noise control | Uses allowlists, minimum severity, finding deduplication, and configurable retention windows. |
| Active response | Handles high-confidence public-source web probes and SSH brute-force sources through `observe`, `balanced`, or `strict` strategies; firewall writes use nftables or iptables with TTL-based expiry and public-IP safety checks. Enabled by default for new installs. |
| Notifications | Sends alerts through Telegram, Email SMTP, generic webhook, ntfy, Gotify, Bark, ServerChan, DingTalk, and Feishu. |
| Operations | Provides a single CLI binary, `vs` shorthand, JSON logs, systemd unit, one-command installer, update script, built-in reload command, stop helper, config migration, reports, and advice commands. |

## Detection Model

The command-execution rules are behavior-profile rules, not simple tool-name or port-name rules. vps-sentinel keeps argv as structured data from `/proc/<pid>/cmdline`, builds a small command profile, and only raises `PROC-003`/`NET-003` when high-risk features combine, such as network channels bridged into shell targets, `SYSTEM:` command runners, fd duplication, inline socket code, or TTY allocation.

Known miner/scanner detection is intentionally narrower: `PROC-004` matches known tool names such as `xmrig`, `masscan`, and `zmap` against process identity fields such as executable path, process name, and structured `argv[0]`, including `.exe` suffixes. It does not treat arbitrary substrings or ordinary command arguments as a hit when structured process identity is available. When procfs CPU data is available, alerts include lifetime average CPU, process age, and total CPU seconds; sustained high CPU strengthens the finding but high CPU alone is not enough to alert.

Executable-path, deleted-executable, and persistence-startup alerts are scored. `PROC-001` treats common staging directories as strong evidence but treats runtime-state paths such as `/run` as weak context that must combine with signals such as hidden names, root context, sockets, public outbound activity, network execution bridges, high CPU, or known miner/scanner identity. `PROC-002` requires additional suspicious traits such as a suspicious executable path, memfd or anonymous backing, a hidden non-standard executable, a network execution bridge, or a known miner/scanner identity. A package-upgrade residue such as `systemd`, `dockerd`, or `python3` running from a deleted standard system path is treated as maintenance context unless other risk traits are present. `PERSIST-002` scores startup lines for combinations such as download-to-shell, temporary-path autostart payloads, base64 decode-to-shell, and network-to-shell execution bridges; a plain `bash -c` service wrapper is not enough by itself.

File and persistence baseline drift is not suppressed just because package-manager activity exists. Instead, the agent collects recent apt/dpkg/yum/dnf/pacman/apk log activity and attaches that context to `FILE-001`, `PERSIST-001`, and `PERSIST-003` recommendations. This keeps real drift visible while making legitimate package updates easier to confirm before refreshing the baseline.

SSH key-file state is checked independently from baseline drift. The collector reads default OpenSSH key paths and expands `AuthorizedKeysFile` directives from `sshd_config` and included `sshd_config.d/*.conf` files, so custom key locations are still monitored. A changed `authorized_keys` still reports as persistence drift, while unsafe current state reports separately only when there is concrete filesystem evidence such as group/other-writable permissions or a symlink to a null device, temporary directory, shared memory, or runtime path.

Sensitive auth/login log integrity is stateful. vps-sentinel records the previous file type and size, reports risky symlinks such as `/var/log/auth.log -> /dev/null`, reports abrupt truncation only when the drop is large enough and there is no recently modified rotated sibling such as `auth.log.1`, and reports a configured sensitive log that existed in previous scans but disappears later. Normal log rotation therefore stays quiet, while log clearing or removal after a compromise becomes visible.

WebShell content detection is risk-scored instead of marker-only. A single marker such as `eval` in a legitimate admin script is below the default threshold. Combinations such as command execution in a script-like web path, dynamic execution plus encoded payload markers, command execution plus encoding, or large encoded payloads in script-like web paths raise `FILE-002`.

`PROC-005` covers renamed or lightly disguised processes that may not expose a known tool name, temporary executable path, or obvious network shell bridge. It combines weaker behavior signals such as kernel-thread masquerading, execution from configured web roots, hidden executable names, suspicious working directories, socket-FD activity, sustained high CPU, procfs start-time drift for the same process identity, and effective-root privilege context. No single weak signal is enough at the default threshold, and start-time drift only contributes after other suspicious context already exists.

`PROC-006` adds GPU mining coverage when `nvidia-smi` or `rocm-smi` is visible to the host service. The collector reads current compute apps and joins them with procfs and outbound-connection facts by PID. GPU memory use alone is not an alert because normal CUDA, ROCm, AI, rendering, and transcoding jobs can be heavy; the rule requires stronger evidence such as a known GPU miner identity, configured mining-pool remote port, temporary or deleted executable, anonymous/memfd executable, network execution bridge, or a hidden GPU executable with public outbound activity. Containerized deployments that cannot see host GPU/process namespaces are outside this signal unless the relevant runtime is visible from the host.

Process and listener findings now include a broader evidence chain when the host exposes it: parent process name, systemd unit, systemd `ExecStart`, executable UID/GID, executable size, bounded BLAKE3 hash, dpkg/rpm/pacman/apk package ownership, cgroup/container context, procfs start-time drift, outbound connection counts, public outbound count, and remote port profile. Package ownership queries and firewall probes are bounded by short command timeouts and per-scan caching, so missing or slow platform tools degrade to absent evidence instead of blocking a scan. These fields are used as supporting evidence or weak signals. For example, a systemd `ExecStart` mismatch does not alert by itself, but it can upgrade an already changed listener owner into a suspicious-listener finding.

Firewall state is auxiliary context, not the source of truth. Socket exposure still comes from `/proc/net/*`; `ufw`, `firewalld`, `nftables`, and `iptables` status are attached so operators can decide whether a public listener is actually reachable through local policy.

Every finding is enriched with a unified 0-100 risk score derived from severity, detector confidence, rule-specific scores, active-response context, and optional threat-intel matches. Incidents are generated after scan-level coalescing by grouping related findings within a configured time window, so operators can inspect an attack chain with `vs incidents timeline <incident_id>` instead of reading isolated alerts.

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
| DingTalk | `[notifications.dingtalk]` | `enabled`, `access_token` | DingTalk group robot notifications. |
| Feishu | `[notifications.feishu]` | `enabled`, `webhook_url` | Feishu/Lark group bot notifications. |

Each channel supports `min_severity`, so low-priority findings can be kept local while higher-risk findings are sent out. HTTP-based channels share `notifications.request_timeout_seconds`, which defaults to 15 seconds. Human-facing channels use a template strategy: Telegram uses Telegram-compatible HTML, Email sends multipart plain-text plus full HTML, ServerChan, Gotify, DingTalk, and Feishu use Markdown, and ntfy/Bark use plain text for maximum client compatibility.

Notification text supports Simplified Chinese by default and can be switched to English:

```toml
[notifications]
request_timeout_seconds = 15
language = "zh_cn" # zh_cn or en
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

Active response requires root privileges plus a working nftables or iptables/ip6tables userspace command. On hosts managed by firewalld, ufw, or manual firewall reloads, vps-sentinel re-checks stored blocks against the actual firewall on each scan and removes stale local state when rules disappear.

The Docker containers used in CI are build and compatibility test environments only. A normal containerized runtime can only see the container's own process table, filesystem, and logs, so it is not a reliable way to monitor host compromise. For production host intrusion monitoring, install the daemon directly on the VPS host with root visibility, preferably through the provided systemd unit.

## Implementation And Effect

| Feature | Implementation | Practical effect |
| --- | --- | --- |
| SSH login monitoring | Reads configured auth logs and falls back to `journalctl` for `ssh.service`/`sshd.service` when files are absent. | Detects root logins, password logins, ordinary successful logins, and brute-force clusters by source IP. |
| SSH key integrity | Hashes `authorized_keys` and `authorized_keys2` independently of the broader file-integrity switch; records file type, Unix mode when available, and symlink target. | Detects SSH persistence changes even when general file integrity is disabled, and reports unsafe writable or risky symlink states without relying on baseline history. |
| File and persistence drift | Builds a local SQLite baseline, diffs later snapshots, coalesces related file/persistence findings for the same path, and attaches package-manager context. | Finds real drift while reducing confusion during legitimate package updates; baseline is refreshed only by explicit command. |
| Log tamper signals | Collects sensitive log file snapshots and compares them with stored rule state; risky symlink targets are immediate findings, truncation requires a large configured size drop and no recent rotation sibling, and previously seen configured logs that disappear are reported. | Detects anti-forensics such as redirecting auth logs to `/dev/null`, clearing log files, or removing auth logs, while avoiding normal logrotate noise. |
| WebShell content | Scans bounded file content for risk markers and scores marker combinations plus web-path context. | Avoids alerting on one weak marker, while catching classic web command execution and encoded payload patterns. |
| Web probing | Groups `WEB-001` by source IP, probe family, and response profile. Missing/rejected probes such as 404 PHPUnit directory sweeps are Low context; successful sensitive-file responses or protected exploit paths are raised. | A scanner hitting many path variants creates one readable finding instead of dozens of Telegram messages. |
| Process and GPU risk | Reads procfs argv, parent, executable, cwd, UID/EUID, deleted state, socket-FD count, lifetime CPU metrics, start-time drift, cgroup/container hints, systemd unit/ExecStart, executable metadata/hash, package owner, outbound connection profile, and NVIDIA compute-process state; uses rule-specific scoring, allowlists, rule-state storage, and same-PID signal coalescing. `PROC-001` scores suspicious executable paths instead of trusting or blocking paths blindly; `PROC-005` requires a primary evasion/location signal before socket, outbound, restart, or root-context signals can alert; `PROC-006` requires GPU compute activity plus mining or high-risk runtime evidence. | Detects suspicious executable paths, suspicious deleted executables, network shell bridges, known miner/scanner identities, renamed behavior clusters, and suspicious GPU mining workloads while avoiding duplicate messages caused by volatile PID/CPU/GPU/connection counters or normal high-connection services. |
| Network listeners | Parses `/proc/net/tcp*` and `/proc/net/udp*`, resolves owning processes through `/proc/<pid>/fd`, compares listener owners with baseline, attaches process/firewall context, and prioritizes suspicious owner behavior over generic port exposure. | Expected 22/80/443 ports reduce generic noise but still produce findings when the owning process changes or looks suspicious; high-risk ports keep their service and firewall profile as evidence. |
| Notifications | Renders one `Finding` model through channel-specific templates: Telegram HTML, Email HTML/plain text, Markdown-aware channels, or plain text. | Messages include the configured VPS name, normalized time, localized labels, evidence, impact, and recommendations. |
| Noise control | Applies scan-level deduplication, persisted dedup windows, state reminder intervals, quiet hours, and hourly notification budgets. | Reduces repeat messages while keeping high-value alerts visible. |
| Active response | Evaluates current findings after scan-level coalescing/deduplication and before persisted notification deduplication; only public IPs outside `[allowlist].ips` can be blocked. Web blocks require successful sensitive responses, high-confidence exploit probes, repeated lower-confidence exploit probes, or high-volume probe/error bursts; SSH blocks default to the same failed-login threshold as the SSH brute-force alert. | Lets operators turn noisy, obvious scanners into temporary firewall drops without making every alert destructive. |
| Response policy DSL | Applies configurable response policies after detection candidates are created. Policies match rule IDs or categories and choose observe, temporary block, or permanent block with minimum severity, confidence, and unified score thresholds. | Keeps detection logic separate from response decisions and lets operators tune blocking without code changes. |
| Incidents and timeline | Groups related findings by IP, path, process, category, and time window, stores a bounded incident index, and exposes `incidents list/show/timeline`. | Turns isolated findings into a readable attack-chain view while keeping raw findings available. |
| Service profile | Stores listener owner profiles with address, port, protocol, process name, executable, command line, and exposure classification. | Detects service drift on common ports and new listeners without blindly trusting or blocking 80/443. |
| Advanced evidence | Optional auditd, eBPF JSONL bridge, Sigma-like TOML rules, YARA CLI scans, and threat-intel indicators feed the same RawEvent/Finding model. | Adds deeper host signals when the platform supports them while keeping default installs lightweight and compatible. |
| Maintenance and fleet operations | Stores bounded maintenance state and fleet node snapshots in local rule state. | Suppresses planned low/medium drift during upgrades and lets several VPS node summaries be reviewed locally. |

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
- installs or repairs the Rust toolchain with rustup only when a source build is needed and `cargo` is missing or misconfigured;
- clones this repository to `/opt/vps-sentinel-src` only for source builds;
- builds `vps-sentinel` in release mode when source fallback is used;
- installs the binary to `/usr/local/bin/vps-sentinel` and the shorthand symlink `/usr/local/bin/vs`;
- installs `vps-sentinel-install`, `vps-sentinel-update`, and `vps-sentinel-stop` helper commands when the package or source tree contains them;
- tests a downloaded release binary with `--version` before installing it; if it cannot run on the host, the installer falls back to a source build;
- creates `/etc/vps-sentinel/config.toml` only if it does not already exist;
- optionally writes Telegram settings from environment variables;
- installs the systemd unit before baseline bootstrap when systemd is available;
- removes deprecated config keys after writing a `.bak` backup, unless `MIGRATE_CONFIG=no`;
- appends missing default config keys without overwriting existing values, unless `SYNC_CONFIG_DEFAULTS=no`;
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
| `SYNC_CONFIG_DEFAULTS` | `yes` | Append newly introduced default config keys without overwriting existing values. Set to `no` to skip. |
| `BOOTSTRAP_BASELINE` | `yes` | Create the first baseline if no baseline exists. |
| `RUN_FIRST_SCAN` | `yes` | Run one `scan --no-notify` and write full output to `<LOG_DIR>/first-scan.log`. |
| `VPS_NAME` | empty | Optional human-readable VPS name written to `agent.display_name`; shown in notification subjects. |
| `TELEGRAM_BOT_TOKEN` | empty | Telegram bot token to write into local config. |
| `TELEGRAM_CHAT_ID` | empty | Telegram chat ID to write into local config. |
| `TELEGRAM_MIN_SEVERITY` | `Medium` | Minimum severity for Telegram notifications. |
| `RUN_NOTIFY_TEST` | `auto` | `auto`, `yes`, or `no`; `auto` sends a test when Telegram env vars are provided. |
| `STORAGE_MAX_DATABASE_SIZE_MB` | empty | Optional override for `[storage].max_database_size_mb`. Existing configs are changed only when this variable is set. |
| `ACTIVE_RESPONSE_ENABLED` | empty | Overrides `active_response.enabled`; new default configs enable active response, while existing user configs are preserved on upgrade. Use `no` to force observe-only deployments without firewall writes. |
| `ACTIVE_RESPONSE_FIREWALL_BACKEND` | empty | Optional `auto`, `nftables`, or `iptables` backend override. |
| `ACTIVE_RESPONSE_BLOCK_TTL_SECONDS` | empty | Optional temporary block TTL override. |
| `ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN` | empty | Optional cap for new blocks in one scan. |
| `ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED` | empty | Optional `yes`/`no` override for repeated-source permanent block escalation. |
| `ACTIVE_RESPONSE_PERMANENT_BLOCK_THRESHOLD` | empty | Optional number of repeated block-candidate scans before permanent escalation. |
| `ACTIVE_RESPONSE_PERMANENT_BLOCK_WINDOW_SECONDS` | empty | Optional repeated-source counting window. |
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

The update script tries a release artifact by default, validates the downloaded binary with `--version`, and falls back to a source build only when the artifact is unavailable or cannot execute on the host. The source fallback pulls the selected branch, repairs a missing or misconfigured Rust toolchain when needed, and rebuilds the binary. Both paths preserve the existing config, remove deprecated config keys after writing a `.bak` backup, append missing default config keys without overwriting existing values, validate the final config, refresh the systemd unit when available, update the `vs` shorthand, run a post-update `scan --no-notify` by default to warm duplicate and active-response state, and restart an active or enabled service so the new binary is actually running. It does not refresh an existing baseline by default, so unreviewed host drift such as `authorized_keys` changes is not silently trusted during an update. Unchanged systemd unit content is not rewritten, so routine updates do not churn unit file mtimes. Use `vps-sentinel reload` or `vs reload` for config-only changes that do not replace the binary.

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
| `INSTALL_DEPS` | `yes` | Set to `no` to skip package manager dependency installation. |
| `INSTALL_METHOD` | `auto` | `auto` and `release` try a release artifact first and fall back to source if the artifact is missing or cannot execute on the host; `source` always builds locally. |
| `RELEASE_VERSION` | `latest` | Release tag to download when `INSTALL_METHOD` is `auto` or `release`. |
| `RELEASE_ARTIFACT_URL` | empty | Override the release artifact URL. Useful for mirrors and local artifact validation. |
| `TARGET_TRIPLE` | auto-detected | Override release artifact target, for example `x86_64-unknown-linux-gnu` or `aarch64-unknown-linux-musl`. |
| `INSTALL_SYSTEMD` | `auto` | Set to `no` to skip unit refresh. |
| `RESTART_SERVICE` | `auto` | `auto`, `yes`, or `no` for reload/restart behavior. |
| `VALIDATE_CONFIG` | `yes` | Validate existing config before service reload/restart. |
| `MIGRATE_CONFIG` | `yes` | Remove deprecated config keys after writing a `.bak` backup. Set to `no` to skip. |
| `SYNC_CONFIG_DEFAULTS` | `yes` | Append missing current-version default keys while preserving user-set values. Set to `no` to skip. |
| `REFRESH_BASELINE` | `no` | Set to `yes` only after you have reviewed current drift and want the update to refresh the existing baseline. |
| `POST_UPDATE_SCAN` | `yes` | Run one `scan --no-notify` before service restart to reduce update-time notification bursts. |

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
| `vps-sentinel config sync-defaults --config <path>` | Append missing default keys for the current version, preserve existing values, write a `.bak` backup, and validate the result. |
| `vps-sentinel config sync-defaults --dry-run --config <path>` | Show missing default keys that would be added without changing the file. |
| `vps-sentinel reload --config <path>` | Validate the config and reload the running systemd service. Use `vs reload` after installing the shorthand. |
| `vps-sentinel doctor --config <path>` | Check runtime readiness: root visibility, Unix target support, storage directory writability, and configured auth log visibility. |
| `vps-sentinel check --json --config <path>` | Run collectors and detectors once without persisting results, sending notifications, or applying active response. Omit `--json` for a human-readable summary. |
| `vps-sentinel scan --config <path>` | Run one full scan, persist raw events/findings, update notification logs, apply deduplication, and send enabled notifications. |
| `vps-sentinel scan --no-notify --json --config <path>` | Persist scan results but suppress notification delivery and active response. Useful before enabling channels. Omit `--json` for text output. |
| `vps-sentinel daemon --config <path>` | Run continuous scans using `agent.scan_interval_seconds`; intended for systemd. |
| `vps-sentinel baseline create --config <path>` | Capture the current known-good local state into SQLite. Run after installation and after approved system changes. |
| `vps-sentinel baseline show --config <path>` | Print the stored baseline snapshot. |
| `vps-sentinel baseline diff --json --config <path>` | Compare current local state against the stored baseline and print reviewable drift approval keys. |
| `vps-sentinel baseline approve <key\|all> --config <path>` | Mark one pending baseline drift item, or all current items, as reviewed and approved. |
| `vps-sentinel baseline refresh --config <path>` | Apply only approved baseline drift items to a new baseline snapshot. Use `--all` only when the entire current host state is trusted. |
| `vps-sentinel baseline reset --config <path>` | Clear stored baselines. Run `baseline create` afterwards to capture a new trusted state. |
| `vps-sentinel blocks list --config <path>` | List IPs currently recorded as active-response blocks. By default it verifies whether the firewall rule is still present. |
| `vps-sentinel blocks cleanup --config <path>` | Remove expired block records and stale records whose firewall rule disappeared after firewalld/ufw reloads or manual changes. |
| `vps-sentinel blocks unblock <ip> --config <path>` | Remove one blocked IP from available firewall backends and from local active-response state. |
| `vps-sentinel blocks unblock-all --yes --config <path>` | Remove all recorded active-response blocks. `--yes` is required to avoid accidental mass unblocking. |
| `vps-sentinel events list --config <path>` | List recent stored findings; use `--limit <n>` to control the count. |
| `vps-sentinel events show <event_id> --config <path>` | Show one stored finding by ID as JSON. |
| `vps-sentinel findings list --json --config <path>` | List recent stored findings with severity, confidence, rule ID, and subject. |
| `vps-sentinel findings explain <finding_id> --json --config <path>` | Explain one stored finding with rule metadata, evidence, confidence, impact, and recommendations. |
| `vps-sentinel incidents list --config <path>` | List correlated incidents built from related findings. Add `--json` for structured output. |
| `vps-sentinel incidents show <incident_id> --config <path>` | Show one correlated incident with subjects, categories, rules, and summary. |
| `vps-sentinel incidents timeline <incident_id> --config <path>` | Print the finding timeline for a correlated incident. |
| `vps-sentinel service-profile list --config <path>` | Show the stored listener service profile. Add `--json` for structured output. |
| `vps-sentinel service-profile refresh --config <path>` | Rebuild the service profile from current listener state after reviewed service changes. |
| `vps-sentinel report show --config <path>` | Preview the default today report locally; add `--json` for structured output or `--period last24h` for a rolling 24-hour window. |
| `vps-sentinel report send --config <path>` | Send the default today report through all enabled notification channels, bypassing per-channel minimum severity because this is an explicit report command. |
| `vps-sentinel maintenance start --duration-seconds <n> --config <path>` | Start a bounded maintenance window that can suppress low/medium baseline drift during planned work. |
| `vps-sentinel maintenance status --config <path>` | Show whether maintenance mode is active. |
| `vps-sentinel maintenance end --config <path>` | End a manually started maintenance window. |
| `vps-sentinel fleet export --config <path>` | Export this node's lightweight fleet snapshot to stdout or `fleet.export_path`. |
| `vps-sentinel fleet ingest <path> --config <path>` | Import another node's fleet snapshot into local SQLite. |
| `vps-sentinel fleet list --config <path>` | List imported fleet node snapshots. |
| `vps-sentinel advice finding <finding_id> --config <path>` | Generate finding-specific response guidance. |
| `vps-sentinel advice incident <incident_id> --config <path>` | Generate incident-level response guidance. |
| `vps-sentinel storage stats --config <path>` | Print SQLite row counts and database footprint. |
| `vps-sentinel storage prune --config <path>` | Run the same retention and database-size cleanup used after normal persisted scans. |
| `vps-sentinel storage clear <target> --yes --config <path>` | Manually clear selected history such as `raw-events`, `findings`, `notifications`, `scan-runs`, `baselines`, or `all-history`. |
| `vps-sentinel storage vacuum --config <path>` | Run SQLite checkpoint/VACUUM/optimize without deleting rows. |
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

Automatic cleanup runs after each persisted scan. Manual cleanup uses the same storage layer: `vs storage prune` applies retention plus the configured size cap, `vs storage stats` shows row counts and footprint, `vs storage clear notifications --yes` clears notification delivery history, and `vs storage clear all-history --yes` clears raw events/findings/notification logs/scan runs without deleting baselines or rule state. Clearing `baselines` is intentionally separate because it changes future drift detection.

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

Sensitive log integrity:

```toml
[log_integrity]
enabled = true
paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"]
truncate_drop_percent = 90
truncate_min_drop_bytes = 262144
rotation_grace_seconds = 900
```

`TAMPER-001` detects sensitive log paths redirected to risky targets such as `/dev/null`, `/tmp`, `/var/tmp`, `/dev/shm`, or `/run`. `TAMPER-002` compares the current size with stored rule state and requires both `truncate_drop_percent` and `truncate_min_drop_bytes` to be exceeded. If a recently modified rotated sibling exists within `rotation_grace_seconds`, truncation is treated as normal rotation context and no alert is raised. `TAMPER-003` reports a configured sensitive log only after it has been seen in previous scans and then disappears, so a distribution that never had `/var/log/auth.log` does not alert just because that path is absent.

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
known_bad_tool_names = ["xmrig", "xmr-stak", "kinsing", "masscan", "zmap", "lolminer", "nbminer", "gminer", "t-rex", "trex", "teamredminer", "phoenixminer", "ethminer", "ccminer", "cpuminer", "bminer", "nanominer", "wildrig", "rigel", "bzminer"]
```

`deleted_executable_min_score` controls when `PROC-002` is emitted. Deleted executable state is scored with path, process identity, and command-behavior traits; a standard system binary left running after a package upgrade is not enough by itself. `behavior_min_score` controls `PROC-005`, which combines weak process signals such as kernel-thread masquerading, web-root execution, hidden executable names, suspicious cwd, socket-FD activity, sustained high CPU, procfs start-time drift for the same process identity, and effective-root context. Start-time drift is stored in local rule state and only strengthens an already suspicious process; a normal restart does not alert by itself. `high_cpu_threshold_percent` and `high_cpu_duration_seconds` define sustained high CPU using procfs lifetime CPU time and process age; high CPU is a supporting signal, not an alert condition by itself. `suspicious_socket_fd_threshold` defines when socket ownership becomes a stronger behavior signal. `known_bad_tool_names` controls the `PROC-004` known miner/scanner indicator list. Values are matched against process identity fields such as `exe_path`, `executable`, process name, and structured `argv[0]`, with `.exe` suffixes accepted. Legacy events without structured identity fall back to command token basename matching. When several process rules match the same PID, the scanner keeps one highest-value finding and merges the process signals, risk reasons, impact, and recommendations.

GPU indicator policy:

```toml
[gpu]
enabled = true
nvidia_smi_path = "nvidia-smi"
rocm_smi_path = "rocm-smi"
command_timeout_seconds = 2
min_memory_mb = 256
mining_min_score = 80
mining_pool_ports = [3333, 3334, 3335, 4444, 5555, 7777, 8888, 9999, 14444, 16000, 18081, 18082]
```

`PROC-006` is only available when the service can run `nvidia-smi` or `rocm-smi` and see the host GPU compute process table. GPU memory alone is treated as normal workload context. Alerts require additional evidence such as a configured GPU miner identity, temporary/deleted/anonymous executable, configured mining-pool port, network execution bridge, or hidden GPU executable with public outbound connections. If you run vps-sentinel inside a container, it must have host PID/procfs and GPU runtime visibility to inspect host GPU miners accurately.

Persistence indicator policy:

```toml
[persistence]
suspicious_command_min_score = 70
```

`suspicious_command_min_score` controls when `PERSIST-002` is emitted. Startup commands are scored by combined traits such as download-to-shell, temporary-path autostart payloads, encoded shell payloads, and network execution bridges. Plain shell wrappers used by legitimate systemd units do not cross the default threshold on their own.

Web log policy:

```toml
[web]
max_log_tail_bytes = 1048576
include_rotated = true
error_burst_threshold = 20
```

`WEB-001` is emitted for known probe families such as `.env`, `.git`, PHPUnit `eval-stdin.php`, CGI shell traversal, command injection, PHP config-write payloads, LFI file reads, PHP stream wrappers, JNDI injection, SSRF cloud metadata probes, template injection, SQL injection, deserialization probes, phpMyAdmin, WordPress admin, actuator, and server-status probes. Similar path variants are aggregated by source IP, probe family, and response profile. The collector supports common access logs, JSON access logs, and Nginx-style error logs; `max_log_tail_bytes` bounds per-file reads and `include_rotated` includes `.1` siblings. A pure 404/400/301 directory sweep is Low by default; successful responses for sensitive paths are High, while rejected active exploit payloads remain Medium context. `error_burst_threshold` controls when `WEB-002` is emitted for repeated 403/404 responses from one source IP that did not already produce a probe-family finding.

Active response:

```toml
[active_response]
enabled = true
strategy = "balanced"
firewall_backend = "auto"
block_ttl_seconds = 3600
max_blocks_per_scan = 20
notification_detail_limit = 3
permanent_block_enabled = true
permanent_block_threshold = 3
permanent_block_window_seconds = 86400
web_probe_block_threshold = 25
web_exploit_block_threshold = 5
ssh_failed_login_block_threshold = 6
```

Active response is enabled by default for new installs. Existing configs are not overwritten during upgrade, so a host that explicitly has `active_response.enabled = false` stays disabled until the operator changes it. `strategy = "observe"` records block candidates without writing firewall rules, `balanced` is the default policy, and `strict` requires stronger evidence for rejected Web probes and SSH brute-force sources. The scanner applies active response after scan-level coalescing/deduplication but before persisted notification deduplication, so an escalating source can still be blocked even when repeated notifications are suppressed. SSH blocking requires an `SSH-003` finding and defaults to 6 failed logins in the scan window. Web blocking covers successful sensitive responses, high-confidence RCE-style exploit probes, repeated lower-confidence exploit probes, and high-volume error bursts. Quiet hours and notification limiters do not prevent blocking. The backend uses nftables when available and falls back to iptables/ip6tables. Normal blocks are temporary: nftables uses set timeouts and vps-sentinel also stores block state in SQLite so expired entries can be removed on later scans. If the same public source IP repeatedly becomes a block candidate at least `permanent_block_threshold` times within `permanent_block_window_seconds`, it is escalated to a permanent firewall block with no expiry. Permanent escalation still respects `[allowlist].ips`, `strategy = "observe"`, and `max_blocks_per_scan`, and operators can remove it with `vs blocks unblock <ip>` or `vs blocks unblock-all --yes`. Only public routable source IPs are eligible. When one scan creates at most `notification_detail_limit` new blocks, alerts include the blocked IP and reason; larger block bursts produce one summary alert and operators can inspect details with `vs blocks list --no-verify`.

Every scan synchronizes active-response state with the real firewall before deciding whether a source is already blocked. If a rule expired, was removed by firewalld/ufw reload, or was changed manually, the stale state record is removed and a still-escalating source can be blocked again. The iptables backend checks for an existing rule before inserting, so repeated scans do not create duplicate DROP rules, and manual unblock removes duplicate matching rules if they exist. Use `vs blocks list`, `vs blocks cleanup`, `vs blocks unblock <ip>`, and `vs blocks unblock-all --yes` for operational control.

Response policy:

```toml
[response_policy]
enabled = true

[response_policy.policies.ssh_bruteforce]
enabled = true
rule_ids = ["SSH-003"]
action = "block"
min_severity = "High"
min_confidence = 70
min_unified_score = 70
```

Response policies are evaluated after detectors create active-response candidates. They do not create findings by themselves. Use `action = "observe"` to audit a policy without writing firewall rules, `action = "block"` for TTL-based blocks, and `action = "permanent_block"` only for evidence you intentionally want to block without expiry.

Incident, report, and service-profile settings:

```toml
[incidents]
enabled = true
correlation_window_seconds = 900
max_findings_per_incident = 50

[service_profile]
enabled = true
drift_requires_public_exposure = false

[reports]
scheduled_enabled = true
scheduled_hour = 8
scheduled_period = "today"
```

`incidents` controls local attack-chain grouping. `service_profile` controls listener owner drift detection. Scheduled reports are enabled by default and send the configured daily report from the daemon through enabled notification channels, with `min_interval_seconds` preventing duplicate sends after restarts. If no notification channel is configured, scheduled reports are skipped without building or sending a report.

Advanced collectors and external rules:

```toml
[advanced_collectors]
auditd_enabled = true
ebpf_bridge_enabled = true
ebpf_event_paths = []
ebpf_command = []

[external_rules]
enabled = true
sigma_paths = []
yara_enabled = true
yara_paths = []
yara_scan_roots = []
```

Auditd reads configured audit logs when available. The eBPF bridge expects JSONL events from files or a configured command, which lets operators integrate their own BPF tooling without making kernel probes a hard dependency. Sigma-like rules are TOML files containing structured event field conditions. YARA support calls the configured `yara` binary only when rule paths and scan roots are configured, so the default engine is active but does no YARA work until inputs exist.

Threat intelligence, fleet, and maintenance:

```toml
[threat_intel]
enabled = true
indicator_paths = []
url = ""

[fleet]
enabled = true
node_name = ""
export_path = "/var/lib/vps-sentinel/fleet-node.json"

[maintenance]
enabled = false
suppress_baseline_drift = true
max_duration_seconds = 7200
```

Threat-intel indicators can be plain text or JSON lines with `type` and `value`. Matches are added as evidence and can increase the unified risk score, but they do not trigger standalone alerts or blocks. Fleet snapshots are local JSON summaries for multi-VPS review. Maintenance mode is bounded and only suppresses low/medium baseline drift during planned work.

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

The repository includes a release workflow but publishing is intentionally tag-driven. A `v*` tag builds Linux tarballs for GNU and musl targets on x86_64/aarch64, validates package contents, generates SHA-256 checksum files, builds `.deb` and `.rpm` packages from the x86_64 GNU artifact, and uploads them to the GitHub release. The installer and updater consume these artifacts through `INSTALL_METHOD=auto` or `INSTALL_METHOD=release`, validate the binary with `--version` before installing it, and fall back to source builds when the artifact is missing or incompatible. `RELEASE_ARTIFACT_URL` supports mirrors or local package validation.

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
- `SSH-006`: `authorized_keys` or `authorized_keys2` has unsafe permissions or a risky symlink target.
- `SSH-007`: SSH brute-force failures followed by a successful login from the same source.
- `USER-002`: UID 0 user added or changed.
- `TAMPER-001`: Sensitive auth/login log path is redirected to a risky target.
- `TAMPER-002`: Sensitive auth/login log file was abruptly truncated without rotation context.
- `TAMPER-003`: Previously seen sensitive auth/login log file disappeared.
- `PERSIST-002`: Suspicious startup command detected.
- `PROC-002`: Risk-scored deleted executable still running.
- `PROC-003`: Network command execution bridge detected.
- `PROC-005`: Suspicious process behavior cluster.
- `PROC-006`: Suspicious GPU compute or mining process.
- `NET-001`: New public listening port detected relative to baseline.
- `NET-002`: Public listener process changed relative to baseline.
- `NET-003`: Suspicious process behind a public listener.
- `SERVICE-001`: New service profile entry detected.
- `SERVICE-002`: Service executable drift detected.
- `FILE-002`: WebShell-like file content detected.
- `CONFIG-003`: High-risk public service port exposed.
- `REPORT-001`: Daily security report generated from local scan history.
- `EXT-*`: User-supplied external TOML rule matched.
- `YARA-*`: User-supplied YARA rule matched.

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
