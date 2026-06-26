use anyhow::{bail, Result};
use clap::{Subcommand, ValueEnum};
use sentinel_agent::storage::{SqliteStore, StorageClearTarget};
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum StorageCommand {
    Stats,
    Prune {
        #[arg(long)]
        retention_days: Option<u32>,
        #[arg(long)]
        skip_size_limit: bool,
    },
    Clear {
        target: StorageTarget,
        #[arg(long)]
        yes: bool,
    },
    Vacuum,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum StorageTarget {
    RawEvents,
    Findings,
    Notifications,
    ScanRuns,
    Baselines,
    AllHistory,
}

pub fn run_storage(config: SentinelConfig, command: StorageCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        StorageCommand::Stats => {
            let stats = store.stats()?;
            println!("database_bytes={}", stats.database_bytes);
            println!("raw_events={}", stats.raw_events);
            println!("findings={}", stats.findings);
            println!("notification_logs={}", stats.notification_logs);
            println!("attack_fingerprints={}", stats.attack_fingerprints);
            println!("attack_observations={}", stats.attack_observations);
            println!("finding_dedup_states={}", stats.finding_dedup_states);
            println!("scan_runs={}", stats.scan_runs);
            println!("baseline_snapshots={}", stats.baseline_snapshots);
            println!("rule_states={}", stats.rule_states);
        }
        StorageCommand::Prune {
            retention_days,
            skip_size_limit,
        } => {
            let retention_days = retention_days.unwrap_or(config.storage.retention_days);
            let deleted = store.prune_older_than(retention_days)?;
            println!("retention_deleted_rows={deleted}");
            let fingerprint_deleted =
                store.prune_attack_fingerprints(config.attack_fingerprints.retention_days)?;
            println!("attack_fingerprint_deleted_rows={fingerprint_deleted}");
            if !skip_size_limit {
                match store.enforce_size_limit(config.storage.max_database_size_mb)? {
                    Some(report) => {
                        println!("size_before_bytes={}", report.size_before_bytes);
                        println!("size_after_bytes={}", report.size_after_bytes);
                        println!("size_deleted_rows={}", report.deleted_rows);
                        println!("vacuumed={}", report.vacuumed);
                    }
                    None => println!("size_limit_cleanup=not_needed"),
                }
            }
        }
        StorageCommand::Clear { target, yes } => {
            if !yes {
                bail!("refusing to clear storage without --yes");
            }
            let deleted = store.clear_storage(target.into())?;
            println!("clear_deleted_rows={deleted}");
        }
        StorageCommand::Vacuum => {
            store.vacuum()?;
            println!("vacuum complete");
        }
    }
    Ok(())
}

impl From<StorageTarget> for StorageClearTarget {
    fn from(value: StorageTarget) -> Self {
        match value {
            StorageTarget::RawEvents => Self::RawEvents,
            StorageTarget::Findings => Self::Findings,
            StorageTarget::Notifications => Self::NotificationLogs,
            StorageTarget::ScanRuns => Self::ScanRuns,
            StorageTarget::Baselines => Self::BaselineSnapshots,
            StorageTarget::AllHistory => Self::AllHistory,
        }
    }
}
