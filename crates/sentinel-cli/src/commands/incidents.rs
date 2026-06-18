use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::incident::{get_incident, list_incidents, Incident};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum IncidentsCommand {
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Show {
        incident_id: String,
        #[arg(long)]
        json: bool,
    },
    Timeline {
        incident_id: String,
        #[arg(long)]
        json: bool,
    },
}

pub fn run_incidents(config: SentinelConfig, command: IncidentsCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path)?;
    match command {
        IncidentsCommand::List { limit, json } => {
            let incidents = list_incidents(&store, limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&incidents)?);
                return Ok(());
            }
            for incident in incidents {
                print_incident_summary(&incident);
            }
        }
        IncidentsCommand::Show { incident_id, json } => {
            let Some(incident) = get_incident(&store, &incident_id)? else {
                println!("incident not found: {incident_id}");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&incident)?);
            } else {
                print_incident_detail(&incident);
            }
        }
        IncidentsCommand::Timeline { incident_id, json } => {
            let Some(incident) = get_incident(&store, &incident_id)? else {
                println!("incident not found: {incident_id}");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&incident.timeline)?);
            } else {
                for item in &incident.timeline {
                    println!(
                        "{} [{}] {} {} subject={} finding={}",
                        item.timestamp,
                        item.severity,
                        item.rule_id,
                        item.title,
                        item.subject,
                        item.finding_id
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_incident_summary(incident: &Incident) {
    println!(
        "{} [{} score={}] findings={} first={} last={} {}",
        incident.id,
        incident.severity,
        incident.score,
        incident.finding_ids.len(),
        incident.first_seen,
        incident.last_seen,
        incident.title
    );
}

fn print_incident_detail(incident: &Incident) {
    print_incident_summary(incident);
    println!("correlation_key: {}", incident.correlation_key);
    println!("summary: {}", incident.summary);
    if !incident.subjects.is_empty() {
        println!("subjects: {}", incident.subjects.join(", "));
    }
    if !incident.categories.is_empty() {
        println!("categories: {}", incident.categories.join(", "));
    }
    if !incident.rules.is_empty() {
        println!("rules: {}", incident.rules.join(", "));
    }
    if !incident.timeline.is_empty() {
        println!("timeline:");
        for item in &incident.timeline {
            println!(
                "- {} [{}] {} {} subject={} finding={}",
                item.timestamp,
                item.severity,
                item.rule_id,
                item.title,
                item.subject,
                item.finding_id
            );
        }
    }
}
