use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::maintenance::{end_maintenance, maintenance_state, start_maintenance};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum MaintenanceCommand {
    Start {
        #[arg(long)]
        duration_seconds: Option<u64>,
        #[arg(long, default_value = "manual maintenance")]
        reason: String,
    },
    End,
    Status {
        #[arg(long)]
        json: bool,
    },
}

pub fn run_maintenance(config: SentinelConfig, command: MaintenanceCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        MaintenanceCommand::Start {
            duration_seconds,
            reason,
        } => {
            let state = start_maintenance(&store, &config, duration_seconds, reason)?;
            println!(
                "maintenance started: expires_at={}",
                state
                    .expires_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
        MaintenanceCommand::End => {
            end_maintenance(&store)?;
            println!("maintenance ended");
        }
        MaintenanceCommand::Status { json } => {
            let state = maintenance_state(&store)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&state)?);
                return Ok(());
            }
            match state {
                Some(state) => println!(
                    "maintenance active: started_at={} expires_at={} reason={}",
                    state
                        .started_at
                        .map(|value| value.to_rfc3339())
                        .unwrap_or_else(|| "unknown".to_string()),
                    state
                        .expires_at
                        .map(|value| value.to_rfc3339())
                        .unwrap_or_else(|| "unknown".to_string()),
                    state.reason
                ),
                None => println!("maintenance inactive"),
            }
        }
    }
    Ok(())
}
