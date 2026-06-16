use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::rules::engine::{builtin_rules, find_rule};

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    List,
    Test { rule_id: String },
}

pub fn run_rules(command: RulesCommand) -> Result<()> {
    match command {
        RulesCommand::List => {
            for rule in builtin_rules() {
                println!(
                    "{} [{}] {} - {}",
                    rule.id, rule.default_severity, rule.title, rule.description
                );
            }
        }
        RulesCommand::Test { rule_id } => {
            let Some(rule) = find_rule(&rule_id) else {
                bail!("unknown rule id: {rule_id}");
            };
            println!(
                "{} [{}] {} - {}",
                rule.id, rule.default_severity, rule.title, rule.description
            );
        }
    }
    Ok(())
}
