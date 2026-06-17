# Risk Rule Test Report

Date: 2026-06-17

Scope:

- All 29 built-in rules returned by `vps-sentinel rules list`.
- Positive detector cases: each rule must fire for a controlled malicious or risky input.
- Negative detector cases: each rule must stay silent for a realistic benign or below-threshold input.
- Notification rendering: every positive finding is rendered through the same alert renderer used before Telegram, Email, Markdown, and plain-text delivery.
- VPS smoke test: service deployment, config validation, service restart, `scan --no-notify`, and one live notification channel check.

Transport note: the matrix verifies every rule's rendered Telegram HTML payload without sending 28 synthetic alerts to the live Telegram chat. Live channel reachability was verified separately with one `vps-sentinel notify test` run; the Telegram transport returned `ok`.

## Result Summary

| Area | Result |
| --- | --- |
| Rule count | 29 built-in rules |
| Positive rule coverage | Passed |
| Negative rule coverage | Passed |
| Telegram HTML rendering | Passed |
| Chinese message rendering | Passed |
| Technical fields hidden by default | Passed |
| Technical fields shown when enabled | Passed |
| Rule ID uniqueness and format | Passed |
| Rust formatting | Passed |
| Clippy with warnings denied | Passed |
| Workspace tests | Passed: 114 tests |
| Locked release build | Passed |
| Installer/update/reload/stop script syntax | Passed |
| Secret scan for provided Telegram credentials | Passed |
| Static scan for panic/unwrap/expect/debug leftovers | Passed |
| VPS config validation | Passed |
| VPS dry scan | Passed: 0 findings, 0 notifications |
| Live Telegram test notification | Passed |

## Rule Matrix

| Rule | Positive case | Negative case |
| --- | --- | --- |
| `SSH-001` | root public-key SSH success | non-root SSH success |
| `SSH-002` | non-root password SSH success | non-root public-key SSH success |
| `SSH-003` | 10 failed SSH attempts from one IP | 9 failed SSH attempts from one IP |
| `SSH-004` | ordinary non-root public-key SSH success | root login, which is classified as `SSH-001` |
| `SSH-005` | `.ssh/authorized_keys` baseline hash drift | unrelated `/tmp/authorized_keys` drift |
| `FILE-001` | `/etc/passwd` baseline drift | non-critical application file drift |
| `FILE-002` | command-execution marker in a script-like web file or encoded dynamic execution markers | clean web file snapshot and single weak marker below threshold |
| `FILE-003` | executable file in configured web path | executable outside web path |
| `USER-001` | new non-root local user | UID 0 user, which is classified as `USER-002` |
| `USER-002` | non-root account with UID 0 | normal UID user |
| `USER-003` | user account modified relative to baseline | current user snapshot without baseline drift |
| `PERSIST-001` | new or changed systemd persistence file | current persistence snapshot |
| `PERSIST-002` | startup command downloads data and pipes it to shell | cloud-init style plain `bash -c` wrapper |
| `PERSIST-003` | `ld.so.preload` baseline drift | ordinary systemd persistence drift |
| `PROC-001` | process executable under `/tmp` | standard `/usr/sbin/sshd` process |
| `PROC-002` | deleted executable under `/dev/shm` | standard systemd deleted-executable package-upgrade residue |
| `PROC-003` | `/dev/tcp` interactive shell bridge | plain traffic forwarding command |
| `PROC-004` | known miner identity in executable/process name | known tool name appears only as a regular argument |
| `PROC-005` | renamed web-path process with kernel-thread masquerade and socket activity | normal nginx worker with many sockets |
| `NET-001` | new public listener from baseline drift | current unbaselined listener without baseline drift |
| `NET-002` | public listener owner changed from baseline | private listener owner changed |
| `NET-003` | public listener owned by suspicious temp executable | ordinary public web listener |
| `CONFIG-003` | high-risk public Redis port | ordinary public HTTPS port |
| `WEB-001` | request for `/.env` probe path | ordinary static asset request |
| `WEB-002` | 20 web 404 responses from one IP | 19 web 404 responses from one IP |
| `CONFIG-001` | `PasswordAuthentication yes` | `PasswordAuthentication no` |
| `CONFIG-004` | `PermitRootLogin yes` | `PermitRootLogin no` |
| `DOCKER-001` | Docker socket event present | no Docker socket event |
| `ROOTKIT-003` | active `ld.so.preload` entries | empty `ld.so.preload` entries |

## Message Checks

For every positive finding, the automated matrix verifies:

- Subject contains the configured VPS name.
- Telegram HTML body contains the configured VPS name.
- Telegram HTML body is not a full HTML document.
- Chinese rendering does not contain common mojibake markers.
- Technical fields such as rule ID, event ID, and dedup key are hidden by default.
- Technical fields appear when `include_technical_fields = true`.

## Findings From This Round

No new detector false-positive or false-negative behavior was found by the matrix. The main gap was test coverage: previous tests covered many individual rule families, but not a single full-rule matrix with positive and negative cases for every built-in rule. That gap is now covered by `detectors::rule_matrix_tests::every_builtin_risk_rule_has_positive_and_negative_coverage`.

The VPS notification log review found a noise-control issue: durable state findings such as `CONFIG-001`, `CONFIG-004`, and `DOCKER-001` were correctly detected but could notify again after the one-hour event deduplication window elapsed. Runtime detection was correct, but the reminder policy was too noisy for unchanged host state. This round adds `noise_control.state_reminder_interval_seconds` with a default of 86400 seconds and applies it to durable state findings while leaving event findings, such as SSH logins, on the existing event deduplication window.

The latest-notification review also found two noisy `NET-001` alerts caused by v2ray UDP6 high ports. Generic UDP high ports can represent dynamic VPN, proxy, or QUIC-style traffic rather than stable public services. `NET-001` now applies only to ordinary TCP/TCP6 baseline drift. UDP coverage is retained for high-risk public service ports and suspicious listener processes through `CONFIG-003` and `NET-003`.

The code audit found one business threshold that was still hardcoded in detector logic: the `WEB-002` repeated 403/404 threshold. It is now configurable as `web.error_burst_threshold` with the previous default value of 20, and validation rejects zero.

This round also addresses three detection-science gaps. Package-manager activity is collected as context for file and persistence drift instead of silently trusting drift. WebShell content detection now uses marker-combination scoring so a single admin-script marker is below the default threshold. `PROC-005` adds a process behavior cluster for renamed or lightly disguised processes by combining weak signals such as kernel-thread masquerading, web-root execution, hidden executable names, suspicious cwd, socket-FD activity, and effective-root context.

Existing detector modules already separate collection, rule evaluation, risk scoring, finding coalescing, notification rendering, and delivery concerns. The runtime noise-control policy treats durable state findings differently from event findings, the network detector distinguishes ordinary TCP service exposure from generic UDP high-port dynamic traffic, and the new context collectors feed facts into existing detector boundaries rather than coupling notification logic to collection.

## Commands

The final verification set for this round:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo build --release --locked
bash -n install.sh update.sh reload.sh stop.sh packaging/install.sh
git diff --check
```
