# Rule Writing

Rules convert `RawEvent` facts into `Finding` records.

## Requirements

- Use a stable ID such as `SSH-001`, `PROC-003`, or `CONFIG-003`.
- Keep IDs unique and normalized as `PREFIX-000`; unit tests enforce this for built-in rules.
- Attach specific evidence: file path, user, PID, source IP, port, hash, or log source.
- Pick conservative severity. Do not mark weak signals as `Critical`.
- Include remediation guidance that is safe by default.
- Respect allowlists where applicable.
- Keep collectors factual. A collector may mark candidate lines or facts, but final risk decisions belong in detectors.
- Prefer behavior profiles and risk scores for noisy areas such as process, persistence, and network execution. Do not alert from one weak substring when normal software can produce it.

## Rule Categories

- **Event rules**: direct, high-value events such as SSH login and `authorized_keys` drift.
- **Baseline drift rules**: facts that changed relative to the stored baseline, such as users, files, persistence entries, and listener owners.
- **Risk-scored behavior rules**: noisy signals that must combine multiple traits before alerting, such as deleted executables and startup command payloads. Use the shared detector `RiskAssessment` container so evidence fields remain consistent.
- **Posture rules**: risky configuration states such as password SSH login, direct root SSH login, public admin ports, or Docker socket exposure. These should be phrased as configuration risk, not confirmed intrusion.

## Risk Scoring

Risk-scored rules should expose these evidence keys when they alert:

- `risk_score`
- `risk_reasons`
- `risk_features`

Use stable feature names such as `temporary_path`, `network_execution_bridge`, `download_to_shell`, or `anonymous_deleted_executable`. Add regression tests for both malicious examples and realistic benign examples from package updates, cloud-init, systemd wrappers, traffic forwarders, and admin tooling.

## Finding Shape

Every finding includes:

- `id`
- `host_id`
- `title`
- `description`
- `severity`
- `category`
- `rule_id`
- `subject`
- `evidence`
- `impact`
- `recommendations`
- `dedup_key`

Collectors should not make risk judgments. Add a collector field first, then add a detector rule that interprets it.
