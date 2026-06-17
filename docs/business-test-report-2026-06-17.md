# Business Test Report - 2026-06-17

This report documents the VPS notification review and the simulated business test coverage for the current round.

## Why The User Did Not Receive 28 Test Alerts

The full rule matrix is an offline detector and renderer test. It feeds controlled `RawEvent` inputs into every detector and verifies rendered Telegram HTML, but it does not send the synthetic alerts to the live Telegram chat. This avoids spamming the chat with 28 artificial security alerts.

Live delivery was tested separately with `vps-sentinel notify test`; the Telegram transport returned `ok`.

## Latest 10 Sent Notifications

| Time (UTC) | Rule | Subject | Verdict | Notes |
| --- | --- | --- | --- | --- |
| 2026-06-17 02:12:22 | `SSH-003` | `202.152.204.159` | Correct | 16 SSH failures across many usernames. This matches brute-force behavior. |
| 2026-06-17 01:16:10 | `NET-001` | `:::51659` | Incorrect / noisy | v2ray UDP6 high port looked like dynamic proxy/VPN traffic, not a stable new public service. Fixed by limiting generic `NET-001` to TCP/TCP6. |
| 2026-06-16 23:31:49 | `SSH-003` | `43.157.224.34` | Correct | 17 SSH failures across many usernames. |
| 2026-06-16 23:02:44 | `NET-001` | `:::44524` | Incorrect / noisy | Same UDP6 high-port v2ray pattern. Fixed by the same network-rule change. |
| 2026-06-16 19:56:15 | `SSH-003` | `40.81.16.211` | Correct | 13 SSH failures across many usernames. |
| 2026-06-16 19:08:08 | `SSH-003` | `121.196.227.86` | Correct | 18 SSH failures across many usernames. |
| 2026-06-16 18:56:03 | `DOCKER-001` | `/var/run/docker.sock` | Correct, noisy if Telegram min severity is `Info` | Docker socket exists. This is an informational context finding. The VPS Telegram channel is configured with `min_severity = "Info"`, so Info findings are delivered. |
| 2026-06-16 18:56:03 | `CONFIG-001` | SSH config include file | Correct | `PasswordAuthentication yes` is configured. |
| 2026-06-16 18:56:03 | `CONFIG-004` | SSH config include file | Correct | `PermitRootLogin yes` is configured. |
| 2026-06-16 18:43:27 | `SSH-001` | `root@47.74.5.215` | Correct, expected if this was an administrator login | The SSH journal recorded a successful root public-key login. The rule intentionally reports root logins when enabled. |

Summary: 8/10 were valid detections. 2/10 were network noise caused by generic UDP high-port baseline drift; that root cause is fixed in this round.

## Detection Improvement

Changed `NET-001` so ordinary new public-listener alerts only apply to TCP/TCP6 baseline drift. Generic UDP high ports are treated as dynamic traffic by default. UDP coverage is still retained for:

- `CONFIG-003`: high-risk public service ports, including UDP services such as Memcached;
- `NET-003`: suspicious listener process traits, including UDP sockets owned by temporary-path or command-execution bridge processes.

This keeps the rule useful for real public services while reducing VPN/proxy/QUIC-style UDP high-port false positives.

## Simulated Business Test Matrix

| Module | Test scope | Positive cases | Negative cases | Result |
| --- | --- | --- | --- | --- |
| SSH login | Auth log events | root login, password login, ordinary login | non-root key login does not trigger root/password rules | Passed |
| SSH brute force | Failure aggregation by source IP | 10+ failures from one IP | 9 failures remains below threshold | Passed |
| SSH key integrity | Baseline drift | `.ssh/authorized_keys` hash change | unrelated `/tmp/authorized_keys` drift | Passed |
| Critical files | Baseline drift | `/etc/passwd` modified | application config outside critical paths | Passed |
| WebShell file | File snapshot markers | PHP-like file with webshell markers | clean web file | Passed |
| Web executable | Web root file metadata | executable/script file in web root | executable outside web root | Passed |
| Users | User baseline drift | new user, UID 0 user, privilege-relevant change | current user snapshot without drift | Passed |
| Persistence | Startup locations and command scoring | systemd/cron drift, ld preload drift, download-to-shell startup command | ordinary persistence snapshot, cloud-init shell wrapper | Passed |
| Process | Process path and command behavior | temporary executable, deleted suspicious executable, network shell bridge, miner identity | standard system process, package-upgrade residue, plain traffic forwarder, tool name only in argument | Passed |
| Network TCP | Public socket baseline drift | new TCP public port | stable current generic public port without baseline drift | Passed |
| Network UDP | Public socket baseline drift and risk exceptions | high-risk UDP port, suspicious UDP listener process | generic v2ray-like UDP6 high port | Passed |
| Network owner drift | Baseline owner comparison | public listener owner changed | private listener owner changed | Passed |
| SSH config risk | Parsed sshd options | `PasswordAuthentication yes`, `PermitRootLogin yes` | both options set to `no` | Passed |
| High-risk service exposure | Public port policy | Redis/Memcached-style risky public ports | ordinary public HTTPS port | Passed |
| Web logs | Access log events | `/.env` probe, 20 repeated 404s from one IP | ordinary asset request, 19 errors below threshold | Passed |
| Docker context | Docker socket event | Docker socket exists | no Docker event | Passed |
| Rootkit signal | ld preload event | active `ld.so.preload` entry | empty preload entries | Passed |
| Notification rendering | Alert templates | VPS name, Chinese text, Telegram HTML, technical fields when enabled | no full HTML document in Telegram body, no technical fields by default | Passed |
| Noise control | Duplicate suppression | durable state duplicates use 24-hour reminder interval | SSH login events still use the normal event window | Passed |
| Scripts | Shell syntax | install, update, reload, stop, packaging install | n/a | Passed |

## Commands Used For Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p sentinel-agent network_rules
cargo test -p sentinel-agent rule_matrix
cargo test -p sentinel-agent scanner
cargo test --workspace --all-targets
cargo build --release --locked
bash -n install.sh update.sh reload.sh stop.sh packaging/install.sh
git diff --check
```

