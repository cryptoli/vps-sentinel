use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::active_response::{
    cleanup_active_blocks, list_active_blocks, unblock_active_ip, unblock_all_active_blocks,
};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use std::net::IpAddr;

#[derive(Debug, Subcommand)]
pub enum BlocksCommand {
    List {
        #[arg(long)]
        no_verify: bool,
    },
    Cleanup,
    Unblock {
        ip: IpAddr,
    },
    UnblockAll {
        #[arg(long)]
        yes: bool,
    },
}

pub fn run_blocks(config: SentinelConfig, command: BlocksCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        BlocksCommand::List { no_verify } => {
            let entries = list_active_blocks(&config, &store, !no_verify)?;
            if entries.is_empty() {
                println!("no active-response blocks recorded");
                return Ok(());
            }
            for entry in entries {
                let firewall = match entry.firewall_present {
                    Some(true) => "present",
                    Some(false) => "missing",
                    None => "not_checked",
                };
                let expires_at = entry
                    .expires_at
                    .map(|timestamp| timestamp.to_rfc3339())
                    .unwrap_or_else(|| "permanent".to_string());
                println!(
                    "{} backend={} firewall={} expires_at={} rule={} reason={}",
                    entry.ip, entry.backend, firewall, expires_at, entry.rule_id, entry.reason
                );
            }
        }
        BlocksCommand::Cleanup => {
            let report = cleanup_active_blocks(&config, &store)?;
            println!(
                "cleanup complete: expired={} stale={} failed_expirations={} failed_state_checks={}",
                report.expired_blocks,
                report.stale_blocks,
                report.failed_expirations,
                report.failed_state_checks
            );
        }
        BlocksCommand::Unblock { ip } => {
            let report = unblock_active_ip(&config, &store, ip)?;
            println!(
                "unblock complete: requested={} state_removed={} firewall_removed={} failed={}",
                report.requested_blocks,
                report.state_removed,
                report.firewall_removed,
                report.failed_blocks
            );
        }
        BlocksCommand::UnblockAll { yes } => {
            if !yes {
                bail!("refusing to unblock all without --yes");
            }
            let report = unblock_all_active_blocks(&config, &store)?;
            println!(
                "unblock all complete: requested={} state_removed={} firewall_removed={} failed={}",
                report.requested_blocks,
                report.state_removed,
                report.firewall_removed,
                report.failed_blocks
            );
        }
    }
    Ok(())
}
