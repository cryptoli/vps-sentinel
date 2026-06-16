# Contributing

Thanks for helping improve vps-sentinel.

## Development

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Rule Contributions

Rules must:

- be defensive;
- have a stable `rule_id`;
- produce a unified `Finding`;
- include evidence and recommendations;
- choose severity conservatively;
- respect allowlists where relevant;
- avoid destructive actions.

## Notifier Contributions

Notifier implementations must:

- implement the shared `Notifier` trait;
- avoid logging tokens, passwords, or secrets;
- return structured errors for missing configuration;
- use the standard finding renderer unless a provider requires a specific format.

## Code Style

- Keep modules focused and cohesive.
- Prefer existing project patterns.
- Avoid hardcoded machine-specific paths.
- Do not add attack, brute-force, stealth, or third-party scanning capabilities.
