use anyhow::Result;
use sentinel_agent::security_wizard::{evaluate_config, WizardStatus};
use sentinel_core::SentinelConfig;

pub fn run_wizard(config: SentinelConfig, json_output: bool) -> Result<()> {
    let report = evaluate_config(&config);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("status={}", status_label(report.status));
    if report.checks.is_empty() {
        println!("checks=ok");
        return Ok(());
    }
    for check in report.checks {
        println!(
            "- [{}] {} status={} id={}",
            check.severity, check.title, check.status, check.id
        );
        println!("  detail: {}", check.detail);
        println!("  recommendation: {}", check.recommendation);
    }
    Ok(())
}

fn status_label(status: WizardStatus) -> &'static str {
    match status {
        WizardStatus::Ready => "ready",
        WizardStatus::NeedsReview => "needs_review",
        WizardStatus::Risky => "risky",
    }
}
