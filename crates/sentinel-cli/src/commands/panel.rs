use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::panel::{flush_outbox, outbox_summary, push_snapshot};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum PanelCommand {
    Push,
    Flush,
    Outbox,
}

pub async fn run_panel(config: SentinelConfig, command: PanelCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    let summary = match command {
        PanelCommand::Push => push_snapshot(&config, &store).await?,
        PanelCommand::Flush => flush_outbox(&config, &store).await?,
        PanelCommand::Outbox => outbox_summary(&store)?,
    };
    println!("pending={}", summary.pending);
    if let Some(value) = summary.oldest_created_at {
        println!("oldest_created_at={}", value.to_rfc3339());
    }
    if let Some(value) = summary.newest_created_at {
        println!("newest_created_at={}", value.to_rfc3339());
    }
    if let Some(value) = summary.last_success_at {
        println!("last_success_at={}", value.to_rfc3339());
    }
    if let Some(value) = summary.last_attempt_at {
        println!("last_attempt_at={}", value.to_rfc3339());
    }
    Ok(())
}
