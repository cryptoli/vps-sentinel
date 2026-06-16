use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::notify::{NotificationManager, NotifyContext};
use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};
use std::sync::Arc;

#[derive(Debug, Subcommand)]
pub enum NotifyCommand {
    Test,
}

pub async fn run_notify(config: SentinelConfig, command: NotifyCommand) -> Result<()> {
    match command {
        NotifyCommand::Test => {
            let finding = Finding::new(
                config.host_id(),
                "VPS Sentinel test notification",
                "This is a configured notification channel test.",
                Severity::Info,
                Category::System,
                "SYSTEM-TEST",
                "notify-test",
            )
            .with_evidence(vec![Evidence::new("command", "notify test")])
            .with_recommendations(vec![
                "If you received this message, the notification channel is reachable.".to_string(),
            ]);
            let manager = NotificationManager::from_config(&config);
            if manager.enabled_count() == 0 {
                println!("no notification channels are enabled");
                return Ok(());
            }
            let ctx = NotifyContext {
                config: Arc::new(config),
            };
            let results = manager.notify_test(&finding, &ctx).await;
            let mut failures = 0;
            for (_finding_id, channel, result) in results {
                match result {
                    Ok(()) => println!("{channel}: ok"),
                    Err(err) => {
                        failures += 1;
                        println!("{channel}: failed: {err}");
                    }
                }
            }
            if failures > 0 {
                bail!("{failures} notification channel(s) failed");
            }
        }
    }
    Ok(())
}
