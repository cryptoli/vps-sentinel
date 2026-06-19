use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::rules::engine::{builtin_rules, find_rule};

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    List,
    Matrix {
        #[arg(long)]
        json: bool,
    },
    Test {
        rule_id: String,
    },
}

pub fn run_rules(command: RulesCommand) -> Result<()> {
    match command {
        RulesCommand::List => {
            for rule in builtin_rules() {
                println!(
                    "{} [{} owner={} scope={}] {} - {}",
                    rule.id,
                    rule.default_severity,
                    rule.owner,
                    rule.response_scope,
                    rule.title,
                    rule.description
                );
            }
        }
        RulesCommand::Matrix { json } => {
            let rules = builtin_rules();
            if json {
                println!("{}", serde_json::to_string_pretty(&rules)?);
            } else {
                for rule in rules {
                    println!(
                        "{} owner={} category={} scope={} evidence={}",
                        rule.id,
                        rule.owner,
                        rule.category,
                        rule.response_scope,
                        rule.evidence_keys.join(",")
                    );
                }
            }
        }
        RulesCommand::Test { rule_id } => {
            let Some(rule) = find_rule(&rule_id) else {
                bail!("unknown rule id: {rule_id}");
            };
            println!(
                "{} [{} owner={} scope={}] {} - {}",
                rule.id,
                rule.default_severity,
                rule.owner,
                rule.response_scope,
                rule.title,
                rule.description
            );
        }
    }
    Ok(())
}
