# False Positive Handling

Security monitoring should be useful without waking users for expected operations.

## Common Sources

- Package upgrades changing systemd units or config files.
- Admin-created users and SSH keys.
- Public ports intentionally exposed for services.
- Framework files containing strings that resemble shell helpers.
- Web vulnerability probes that never succeeded.

## Mitigation

- Add expected users, IPs, ports, file paths, or process paths to `[allowlist]`.
- For legitimate forwarding or tunneling commands, prefer `allowlist.process_paths`; use `allowlist.process_command_contains` only with a precise identifying fragment.
- For known miner/scanner findings, confirm the executable basename first. The rule matches known tool names at token or basename boundaries, so longer unrelated names should not be treated as matches.
- Put normal public service ports such as HTTP/HTTPS in `network.expected_public_ports`; they still receive process-risk and baseline-owner checks. Use `allowlist.listening_ports` only when a port should suppress all network findings, including high-risk exposure findings.
- Keep baselines fresh after planned maintenance. The installer writes its own systemd unit before baseline bootstrap, and the updater can refresh an existing baseline after trusted updates.
- Route noisy rules at `Low` or `Medium`.
- Investigate correlations before taking destructive action.

## Safe Response

Do not delete files or kill processes solely from one finding. Preserve evidence first, then validate from a trusted session.
