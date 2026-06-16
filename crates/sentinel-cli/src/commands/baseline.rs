use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::baseline::diff_snapshots;
use sentinel_agent::scanner::create_baseline_snapshot;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum BaselineCommand {
    Create,
    Show,
    Diff,
    Reset,
}

pub async fn run_baseline(config: SentinelConfig, command: BaselineCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        BaselineCommand::Create => {
            let snapshot = create_baseline_snapshot(config, PathBuf::from("/")).await?;
            store.save_baseline_snapshot(&snapshot)?;
            println!("baseline created: {}", snapshot.id);
        }
        BaselineCommand::Show => {
            let snapshot = store.latest_baseline_snapshot()?;
            match snapshot {
                Some(snapshot) => println!("{}", serde_json::to_string_pretty(&snapshot)?),
                None => bail!("no baseline snapshot found"),
            }
        }
        BaselineCommand::Diff => {
            let Some(previous) = store.latest_baseline_snapshot()? else {
                bail!("no baseline snapshot found");
            };
            let current = create_baseline_snapshot(config, PathBuf::from("/")).await?;
            let diff = diff_snapshots(&previous, &current);
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        BaselineCommand::Reset => {
            store.clear_baselines()?;
            println!("baseline snapshots cleared");
        }
    }
    Ok(())
}
