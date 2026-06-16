# Rule Writing

Rules convert `RawEvent` facts into `Finding` records.

## Requirements

- Use a stable ID such as `SSH-001`, `PROC-003`, or `CONFIG-003`.
- Attach specific evidence: file path, user, PID, source IP, port, hash, or log source.
- Pick conservative severity. Do not mark weak signals as `Critical`.
- Include remediation guidance that is safe by default.
- Respect allowlists where applicable.

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
