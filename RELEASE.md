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

## GitHub Release Workflow

Publishing is tag-driven. Push a `v*` tag to run `.github/workflows/release.yml`.

The workflow is prepared to build:

- `vps-sentinel-x86_64-unknown-linux-gnu.tar.gz`
- `vps-sentinel-aarch64-unknown-linux-gnu.tar.gz`
- `vps-sentinel-x86_64-unknown-linux-musl.tar.gz`
- `vps-sentinel-aarch64-unknown-linux-musl.tar.gz`
- SHA-256 checksum files
- x86_64 GNU `.deb` and `.rpm` packages

The installer defaults to `INSTALL_METHOD=auto`, which tries the matching release tarball first and falls back to a source build when no artifact exists.

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
