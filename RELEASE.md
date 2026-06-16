# Release Guide

## Local Release Build

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
```

## Suggested Artifacts

- `target/release/vps-sentinel`
- `config/config.example.toml`
- `install.sh`
- `update.sh`
- `packaging/systemd/vps-sentinel.service`
- `README.md`
- `README.zh-CN.md`
- `LICENSE`

## Linux Install Smoke Test

```bash
sudo ./target/release/vps-sentinel config validate --config config/config.example.toml
sudo ./target/release/vps-sentinel doctor --config config/config.example.toml
```

Create a baseline before enabling daemon mode on a real server:

```bash
sudo vps-sentinel baseline create --config /etc/vps-sentinel/config.toml
sudo systemctl enable --now vps-sentinel
```
