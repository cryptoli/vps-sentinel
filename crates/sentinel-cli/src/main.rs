mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{
    advice::{run_advice, AdviceCommand},
    baseline::{run_baseline, BaselineCommand},
    blocks::{run_blocks, BlocksCommand},
    config::{run_config, ConfigCommand},
    doctor::run_doctor,
    ebpf::{run_ebpf, EbpfCommand},
    events::{run_events, EventsCommand},
    findings::{run_findings, FindingsCommand},
    fingerprints::{run_fingerprints, FingerprintsCommand},
    fleet::{run_fleet, FleetCommand},
    incidents::{run_incidents, IncidentsCommand},
    init::run_init,
    maintenance::{run_maintenance, MaintenanceCommand},
    notify::{run_notify, NotifyCommand},
    panel::{run_panel, PanelCommand},
    reload::run_reload,
    report::{run_report, ReportCommand},
    rules::{run_rules, RulesCommand},
    scan::{run_check, run_scan_command},
    service_profile::{run_service_profile, ServiceProfileCommand},
    status::run_status,
    storage::{run_storage, StorageCommand},
    wizard::run_wizard,
};
use sentinel_core::SentinelConfig;
use std::io;
use std::panic;
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
    Advice {
        #[command(subcommand)]
        command: AdviceCommand,
    },
    Init {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    Check {
        #[arg(long)]
        json: bool,
    },
    Scan {
        #[arg(long)]
        no_notify: bool,
        #[arg(long)]
        json: bool,
    },
    Daemon,
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Blocks {
        #[command(subcommand)]
        command: BlocksCommand,
    },
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    Fleet {
        #[command(subcommand)]
        command: FleetCommand,
    },
    Findings {
        #[command(subcommand)]
        command: FindingsCommand,
    },
    Fingerprints {
        #[command(subcommand)]
        command: FingerprintsCommand,
    },
    Incidents {
        #[command(subcommand)]
        command: IncidentsCommand,
    },
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    Notify {
        #[command(subcommand)]
        command: NotifyCommand,
    },
    Panel {
        #[command(subcommand)]
        command: PanelCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    ServiceProfile {
        #[command(subcommand)]
        command: ServiceProfileCommand,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    Ebpf {
        #[command(subcommand)]
        command: EbpfCommand,
    },
    Status {
        #[arg(long)]
        json: bool,
    },
    Reload {
        #[arg(long, default_value = "vps-sentinel")]
        service_name: String,
    },
    Doctor,
    Wizard {
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    install_broken_pipe_panic_hook();
    let cli = Cli::parse();
    init_logging(&cli.log_level)?;

    match cli.command {
        Command::Advice { command } => run_advice(load_config(cli.config.as_deref())?, command),
        Command::Init { path, force } => run_init(path, force),
        Command::Check { json } => run_check(load_config(cli.config.as_deref())?, json).await,
        Command::Scan { no_notify, json } => {
            run_scan_command(load_config(cli.config.as_deref())?, !no_notify, json).await
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
        Command::Blocks { command } => run_blocks(load_config(cli.config.as_deref())?, command),
        Command::Events { command } => run_events(load_config(cli.config.as_deref())?, command),
        Command::Fleet { command } => run_fleet(load_config(cli.config.as_deref())?, command),
        Command::Findings { command } => run_findings(load_config(cli.config.as_deref())?, command),
        Command::Fingerprints { command } => {
            run_fingerprints(load_config(cli.config.as_deref())?, command)
        }
        Command::Incidents { command } => {
            run_incidents(load_config(cli.config.as_deref())?, command)
        }
        Command::Maintenance { command } => {
            run_maintenance(load_config(cli.config.as_deref())?, command)
        }
        Command::Rules { command } => run_rules(command),
        Command::Notify { command } => {
            run_notify(load_config(cli.config.as_deref())?, command).await
        }
        Command::Panel { command } => run_panel(load_config(cli.config.as_deref())?, command).await,
        Command::Report { command } => {
            run_report(load_config(cli.config.as_deref())?, command).await
        }
        Command::ServiceProfile { command } => {
            run_service_profile(load_config(cli.config.as_deref())?, command).await
        }
        Command::Config { command } => run_config(cli.config.as_deref(), command),
        Command::Storage { command } => run_storage(load_config(cli.config.as_deref())?, command),
        Command::Ebpf { command } => run_ebpf(load_config(cli.config.as_deref())?, command),
        Command::Status { json } => run_status(load_config(cli.config.as_deref())?, json),
        Command::Reload { service_name } => {
            let (_, path) = load_config_with_path(cli.config.as_deref())?;
            run_reload(path, &service_name)
        }
        Command::Doctor => run_doctor(load_config(cli.config.as_deref())?),
        Command::Wizard { json } => run_wizard(load_config(cli.config.as_deref())?, json),
    }
}

fn install_broken_pipe_panic_hook() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let message = if let Some(message) = info.payload().downcast_ref::<&str>() {
            (*message).to_string()
        } else if let Some(message) = info.payload().downcast_ref::<String>() {
            message.clone()
        } else {
            info.to_string()
        };
        if message.contains("failed printing to stdout")
            && (message.contains("Broken pipe") || message.contains("os error 32"))
        {
            std::process::exit(0);
        }
        default_hook(info);
    }));
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
