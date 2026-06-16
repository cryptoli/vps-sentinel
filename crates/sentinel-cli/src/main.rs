mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{
    baseline::{run_baseline, BaselineCommand},
    config::{run_config, ConfigCommand},
    doctor::run_doctor,
    events::{run_events, EventsCommand},
    init::run_init,
    notify::{run_notify, NotifyCommand},
    rules::{run_rules, RulesCommand},
    scan::{run_check, run_scan_command},
};
use sentinel_core::SentinelConfig;
use std::io;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "vps-sentinel",
    version,
    about = "Lightweight Linux VPS intrusion-signal monitor"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    Check,
    Scan {
        #[arg(long)]
        no_notify: bool,
    },
    Daemon,
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    Notify {
        #[command(subcommand)]
        command: NotifyCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Doctor,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_level)?;

    match cli.command {
        Command::Init { path, force } => run_init(path, force),
        Command::Check => run_check(load_config(cli.config.as_deref())?).await,
        Command::Scan { no_notify } => {
            run_scan_command(load_config(cli.config.as_deref())?, !no_notify).await
        }
        Command::Daemon => {
            let (config, path) = load_config_with_path(cli.config.as_deref())?;
            sentinel_agent::daemon::run_daemon(config, path)
                .await
                .map_err(Into::into)
        }
        Command::Baseline { command } => {
            run_baseline(load_config(cli.config.as_deref())?, command).await
        }
        Command::Events { command } => run_events(load_config(cli.config.as_deref())?, command),
        Command::Rules { command } => run_rules(command),
        Command::Notify { command } => {
            run_notify(load_config(cli.config.as_deref())?, command).await
        }
        Command::Config { command } => run_config(cli.config.as_deref(), command),
        Command::Doctor => run_doctor(load_config(cli.config.as_deref())?),
    }
}

fn init_logging(log_level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(log_level))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .json()
        .try_init()
        .map_err(|err| anyhow::anyhow!("failed to initialize logging: {err}"))?;
    Ok(())
}

fn load_config(path: Option<&Path>) -> Result<SentinelConfig> {
    Ok(load_config_with_path(path)?.0)
}

fn load_config_with_path(path: Option<&Path>) -> Result<(SentinelConfig, Option<PathBuf>)> {
    if let Some(path) = path {
        return Ok((SentinelConfig::load(path)?, Some(path.to_path_buf())));
    }
    for candidate in default_config_candidates() {
        if candidate.exists() {
            return Ok((SentinelConfig::load(&candidate)?, Some(candidate)));
        }
    }
    let config = SentinelConfig::default();
    config.validate()?;
    Ok((config, None))
}

fn default_config_candidates() -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from("config.toml")];
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".config/vps-sentinel/config.toml"));
    }
    candidates.push(PathBuf::from("/etc/vps-sentinel/config.toml"));
    candidates
}
