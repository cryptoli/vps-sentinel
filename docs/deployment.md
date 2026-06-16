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

The package-time installer copies the binary, creates data/log/config directories, installs the systemd unit when available, and keeps an existing config file untouched.

Useful variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `BIN_PATH` | `target/release/vps-sentinel` | Binary to install. |
| `PREFIX` | `/usr/local` | Binary installation prefix. |
| `CONFIG_DIR` | `/etc/vps-sentinel` | Directory for `config.toml`. |
| `DATA_DIR` | `/var/lib/vps-sentinel` | SQLite data directory. |
| `LOG_DIR` | `/var/log/vps-sentinel` | Log directory. |
| `INSTALL_SYSTEMD` | `auto` | `auto`, `yes`, or `no` for systemd unit installation. |
| `ENABLE_SERVICE` | `no` | Set to `yes` to enable and start the service. |

For one-command source installs, use the repository root `install.sh`; for rebuilding an existing install, use `update.sh`.

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
- `install.sh` and `update.sh`.
- README and docs.
