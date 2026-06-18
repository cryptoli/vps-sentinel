use anyhow::Result;
use clap::Subcommand;
use sentinel_agent::rules::engine::find_rule;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::{Finding, SentinelConfig};
use serde_json::json;

#[derive(Debug, Subcommand)]
pub enum FindingsCommand {
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Show {
        finding_id: String,
        #[arg(long)]
        json: bool,
    },
    Explain {
        finding_id: String,
        #[arg(long)]
        json: bool,
    },
}

pub fn run_findings(config: SentinelConfig, command: FindingsCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path)?;
    match command {
        FindingsCommand::List { limit, json } => {
            let findings = store.list_findings(limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
                return Ok(());
            }
            for finding in findings {
                print_finding_summary(&finding);
            }
        }
        FindingsCommand::Show { finding_id, json } => {
            let Some(finding) = store.get_finding(&finding_id)? else {
                println!("finding not found: {finding_id}");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&finding)?);
            } else {
                print_finding_detail(&finding);
            }
        }
        FindingsCommand::Explain { finding_id, json } => {
            let Some(finding) = store.get_finding(&finding_id)? else {
                println!("finding not found: {finding_id}");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&explain_json(&finding))?);
            } else {
                print_explanation(&finding);
            }
        }
    }
    Ok(())
}

fn print_finding_summary(finding: &Finding) {
    println!(
        "{} [{} confidence={}] {} {} subject={}",
        finding.id,
        finding.severity,
        finding.confidence,
        finding.rule_id,
        finding.title,
        finding.subject
    );
}

fn print_finding_detail(finding: &Finding) {
    print_finding_summary(finding);
    println!("description: {}", finding.description);
    println!("dedup_key: {}", finding.dedup_key);
    if !finding.evidence.is_empty() {
        println!("evidence:");
        for item in &finding.evidence {
            println!("- {}={}", item.key, item.value);
        }
    }
}

fn print_explanation(finding: &Finding) {
    print_finding_detail(finding);
    if let Some(rule) = find_rule(&finding.rule_id) {
        println!("rule:");
        println!("- title: {}", rule.title);
        println!("- category: {}", rule.category);
        println!("- default_severity: {}", rule.default_severity);
        println!("- description: {}", rule.description);
    } else {
        println!("rule: built-in metadata not found");
    }
    if !finding.impact.is_empty() {
        println!("impact:");
        for item in &finding.impact {
            println!("- {item}");
        }
    }
    if !finding.recommendations.is_empty() {
        println!("recommendations:");
        for item in &finding.recommendations {
            println!("- {item}");
        }
    }
}

fn explain_json(finding: &Finding) -> serde_json::Value {
    let rule = find_rule(&finding.rule_id).map(|rule| {
        json!({
            "id": rule.id,
            "title": rule.title,
            "category": rule.category.to_string(),
            "default_severity": rule.default_severity.to_string(),
            "description": rule.description,
        })
    });
    json!({
        "finding": finding,
        "rule": rule,
        "explanation": {
            "confidence": finding.confidence.to_string(),
            "dedup_key": &finding.dedup_key,
            "evidence_count": finding.evidence.len(),
            "impact": &finding.impact,
            "recommendations": &finding.recommendations,
        }
    })
}
