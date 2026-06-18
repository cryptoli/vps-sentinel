use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::advice::{advice_for_finding, advice_for_incident, Advice};
use sentinel_agent::incident::get_incident;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum AdviceCommand {
    Finding {
        finding_id: String,
        #[arg(long)]
        json: bool,
    },
    Incident {
        incident_id: String,
        #[arg(long)]
        json: bool,
    },
}

pub fn run_advice(config: SentinelConfig, command: AdviceCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path)?;
    match command {
        AdviceCommand::Finding { finding_id, json } => {
            let Some(finding) = store.get_finding(&finding_id)? else {
                println!("finding not found: {finding_id}");
                return Ok(());
            };
            print_advice(advice_for_finding(&finding), json)?;
        }
        AdviceCommand::Incident { incident_id, json } => {
            let Some(incident) = get_incident(&store, &incident_id)? else {
                println!("incident not found: {incident_id}");
                return Ok(());
            };
            print_advice(advice_for_incident(&incident), json)?;
        }
    }
    Ok(())
}

fn print_advice(advice: Advice, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&advice)?);
        return Ok(());
    }
    println!("{} [{}]", advice.title, advice.priority);
    for (index, step) in advice.steps.iter().enumerate() {
        println!("{}. {}", index + 1, step);
    }
    Ok(())
}
