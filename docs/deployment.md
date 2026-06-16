# Deployment

## Build

```bash
cargo build --release
```

## Install

```bash
sudo sh packaging/install.sh
sudo systemctl enable --now vps-sentinel
```

The installer copies the binary, creates data/log/config directories, installs the systemd unit, and keeps an existing config file untouched.

## First Run

```bash
sudo vps-sentinel doctor --config /etc/vps-sentinel/config.toml
sudo vps-sentinel baseline create --config /etc/vps-sentinel/config.toml
sudo vps-sentinel scan --config /etc/vps-sentinel/config.toml
```

## Release Build Notes

Release artifacts should include:

- `vps-sentinel` binary.
- `config/config.example.toml`.
- `packaging/systemd/vps-sentinel.service`.
- `packaging/install.sh`.
- README and docs.
