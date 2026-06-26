use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::active_response::{
    cleanup_active_blocks, list_active_blocks, unblock_active_ip, unblock_all_active_blocks,
};
use sentinel_agent::rules::engine::find_rule;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::Finding;
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
    Why {
        ip: IpAddr,
        #[arg(long)]
        no_verify: bool,
        #[arg(long)]
        json: bool,
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
                "cleanup complete: expired={} stale={} legacy_port_guards_removed={} failed_expirations={} failed_state_checks={} failed_legacy_port_guard_cleanups={}",
                report.expired_blocks,
                report.stale_blocks,
                report.legacy_port_guards_removed,
                report.failed_expirations,
                report.failed_state_checks,
                report.failed_legacy_port_guard_cleanups
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
        BlocksCommand::Why {
            ip,
            no_verify,
            json,
        } => {
            let entries = list_active_blocks(&config, &store, !no_verify)?;
            let Some(entry) = entries.into_iter().find(|entry| entry.ip == ip.to_string()) else {
                println!("no active-response block recorded for {ip}");
                return Ok(());
            };
            let finding = store.get_finding(&entry.finding_id)?;
            if json {
                let rule = find_rule(&entry.rule_id);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "block": entry,
                        "finding": finding,
                        "rule": rule.map(|rule| serde_json::json!({
                            "id": rule.id,
                            "title": rule.title,
                            "category": rule.category.to_string(),
                            "default_severity": rule.default_severity.to_string(),
                            "description": rule.description,
                        })),
                    }))?
                );
            } else {
                print_block_explanation(&entry, finding.as_ref());
            }
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

fn print_block_explanation(
    entry: &sentinel_agent::active_response::BlockEntry,
    finding: Option<&Finding>,
) {
    let firewall = match entry.firewall_present {
        Some(true) => "present",
        Some(false) => "missing",
        None => "not_checked",
    };
    let expires_at = entry
        .expires_at
        .map(|timestamp| timestamp.to_rfc3339())
        .unwrap_or_else(|| "permanent".to_string());
    println!("ip={}", entry.ip);
    println!("status=blocked");
    println!("backend={}", entry.backend);
    println!("firewall={firewall}");
    println!("blocked_at={}", entry.blocked_at.to_rfc3339());
    println!("expires_at={expires_at}");
    println!("rule={}", entry.rule_id);
    println!("finding_id={}", entry.finding_id);
    println!("reason={}", entry.reason);
    if let Some(rule) = find_rule(&entry.rule_id) {
        println!("rule_title={}", rule.title);
        println!("rule_description={}", rule.description);
    }
    if let Some(finding) = finding {
        println!("finding_title={}", finding.title);
        println!("severity={}", finding.severity);
        println!("confidence={}", finding.confidence);
        println!("subject={}", finding.subject);
        if !finding.evidence.is_empty() {
            println!("evidence:");
            for item in &finding.evidence {
                println!("- {}={}", item.key, item.value);
            }
        }
    } else {
        println!("finding=not_found");
    }
}
