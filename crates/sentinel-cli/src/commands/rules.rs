use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::detectors::external_rules::{
    validate_external_rule_paths, ExternalRuleValidationReport,
};
use sentinel_agent::rules::engine::{builtin_rules, find_rule};
use sentinel_agent::rules::packs::list_rule_packs;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    List,
    Matrix {
        #[arg(long)]
        json: bool,
    },
    Packs {
        #[arg(long)]
        json: bool,
    },
    Test {
        rule_id: String,
    },
    ValidateExternal {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
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
        RulesCommand::Packs { json } => {
            let packs = list_rule_packs();
            if json {
                println!("{}", serde_json::to_string_pretty(&packs)?);
            } else {
                for pack in packs {
                    println!(
                        "{} version={} source={} rules={}",
                        pack.id, pack.version, pack.source, pack.rule_count
                    );
                    for owner in pack.owners {
                        println!(
                            "- owner={} rules={} ids={}",
                            owner.owner,
                            owner.rule_count,
                            owner.rules.join(",")
                        );
                    }
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
        RulesCommand::ValidateExternal { paths, json } => {
            let report = validate_external_rule_paths(&paths);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_external_rule_validation(&report);
            }
            if !report.is_valid() {
                bail!("external rule validation failed");
            }
        }
    }
    Ok(())
}

fn print_external_rule_validation(report: &ExternalRuleValidationReport) {
    println!(
        "external_rules files={} rules={} valid={} invalid={}",
        report.files, report.rules, report.valid_rules, report.invalid_rules
    );
    if report.issues.is_empty() {
        println!("status=ok");
        return;
    }
    println!("issues:");
    for issue in &report.issues {
        let rule = if issue.rule_id.is_empty() {
            "-"
        } else {
            issue.rule_id.as_str()
        };
        println!("- path={} rule={} {}", issue.path, rule, issue.message);
    }
}
