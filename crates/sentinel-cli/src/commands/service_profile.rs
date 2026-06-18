use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::collectors::{default_collectors, CollectContext};
use sentinel_agent::service_profile::{load_service_profile, refresh_service_profile};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::{RawEvent, SentinelConfig};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Subcommand)]
pub enum ServiceProfileCommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Refresh {
        #[arg(long, default_value = "/")]
        scan_root: PathBuf,
    },
}

pub async fn run_service_profile(
    config: SentinelConfig,
    command: ServiceProfileCommand,
) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        ServiceProfileCommand::List { json } => {
            let profile = load_service_profile(&store)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
                return Ok(());
            }
            let Some(profile) = profile else {
                println!("service profile baseline not found");
                return Ok(());
            };
            println!(
                "updated_at={}",
                profile
                    .updated_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            for service in profile.services.values() {
                println!(
                    "{} {}:{} process={} executable={} public={}",
                    service.protocol,
                    service.local_addr,
                    service.local_port,
                    service.process_name,
                    service.executable,
                    service.public_exposure
                );
            }
        }
        ServiceProfileCommand::Refresh { scan_root } => {
            let events = collect_network_events(config, scan_root).await?;
            let count = refresh_service_profile(&events, &store)?;
            println!("service profile refreshed: {count} service(s)");
        }
    }
    Ok(())
}

async fn collect_network_events(
    config: SentinelConfig,
    scan_root: PathBuf,
) -> Result<Vec<RawEvent>> {
    let ctx = CollectContext::new(Arc::new(config)).with_scan_root(scan_root);
    let mut events = Vec::new();
    for collector in default_collectors()
        .into_iter()
        .filter(|collector| collector.name() == "network")
    {
        events.extend(collector.collect(&ctx).await?);
    }
    Ok(events)
}
