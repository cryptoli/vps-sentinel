use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    Show {
        event_id: String,
    },
}

pub fn run_events(config: SentinelConfig, command: EventsCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path)?;
    match command {
        EventsCommand::List { limit } => {
            for finding in store.list_findings(limit)? {
                println!(
                    "{} [{}] {} {} subject={}",
                    finding.id, finding.severity, finding.rule_id, finding.title, finding.subject
                );
            }
        }
        EventsCommand::Show { event_id } => match store.get_finding(&event_id)? {
            Some(finding) => println!("{}", serde_json::to_string_pretty(&finding)?),
            None => println!("event not found: {event_id}"),
        },
    }
    Ok(())
}
