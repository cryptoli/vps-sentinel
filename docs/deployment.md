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
It writes the systemd unit before baseline bootstrap, validates the config, creates the first baseline when missing, runs a no-notify warm-up scan, creates the `vs` shorthand symlink, and installs `vps-sentinel-stop` when the helper script is present.

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
| `RUN_DOCTOR` | `yes` | Run runtime checks during install. |
| `BOOTSTRAP_BASELINE` | `yes` | Create the initial baseline if none exists. |
| `RUN_FIRST_SCAN` | `yes` | Run one no-notify scan and write full output to `<LOG_DIR>/first-scan.log`. |
| `VPS_NAME` | empty | Optional human-readable VPS name written to `agent.display_name` by the root `install.sh`. |

For one-command source installs, use the repository root `install.sh`; for rebuilding an existing install, use `update.sh`.

## Reload Config

```bash
sudo vps-sentinel reload
sudo vs reload
```

or:

```bash
sudo systemctl reload vps-sentinel
```

Both paths validate the config before sending SIGHUP to the daemon.

## Stop Service

```bash
sudo vps-sentinel-stop
```

or:

```bash
sudo systemctl stop vps-sentinel
```

Stopping the service does not remove `/etc/vps-sentinel`, `/var/lib/vps-sentinel`, logs, or binaries.

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
- `install.sh`, `update.sh`, and `stop.sh`.
- README and docs.
