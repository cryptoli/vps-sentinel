use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::fleet::{
    build_local_snapshot, get_fleet_node, list_fleet_nodes, save_fleet_snapshot, FleetNodeSnapshot,
};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum FleetCommand {
    Export {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Ingest {
        path: PathBuf,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Show {
        node_id: String,
        #[arg(long)]
        json: bool,
    },
}

pub fn run_fleet(config: SentinelConfig, command: FleetCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        FleetCommand::Export { output } => {
            let snapshot = build_local_snapshot(&config, &store, env!("CARGO_PKG_VERSION"))?;
            save_fleet_snapshot(&store, snapshot.clone())?;
            let text = serde_json::to_string_pretty(&snapshot)?;
            if let Some(path) = output.or_else(|| {
                config
                    .fleet
                    .enabled
                    .then(|| config.fleet.export_path.clone())
            }) {
                fs::write(&path, &text)?;
                println!("fleet snapshot exported: {}", path.display());
            } else {
                println!("{text}");
            }
        }
        FleetCommand::Ingest { path } => {
            let text = fs::read_to_string(&path)?;
            let snapshot = serde_json::from_str::<FleetNodeSnapshot>(&text)?;
            save_fleet_snapshot(&store, snapshot)?;
            println!("fleet snapshot ingested: {}", path.display());
        }
        FleetCommand::List { json } => {
            let nodes = list_fleet_nodes(&store)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&nodes)?);
                return Ok(());
            }
            for node in nodes {
                println!(
                    "{} name={} version={} exported_at={} high_or_critical={} findings={}",
                    node.node_id,
                    node.display_name,
                    node.agent_version,
                    node.exported_at,
                    node.high_or_critical_findings,
                    node.finding_count
                );
            }
        }
        FleetCommand::Show { node_id, json } => {
            let Some(node) = get_fleet_node(&store, &node_id)? else {
                println!("fleet node not found: {node_id}");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&node)?);
            } else {
                println!(
                    "{} name={} version={} exported_at={} database_bytes={} findings={} high_or_critical={} last_scan_at={}",
                    node.node_id,
                    node.display_name,
                    node.agent_version,
                    node.exported_at,
                    node.database_bytes,
                    node.finding_count,
                    node.high_or_critical_findings,
                    node.last_scan_at
                        .map(|value| value.to_rfc3339())
                        .unwrap_or_else(|| "unknown".to_string())
                );
            }
        }
    }
    Ok(())
}
