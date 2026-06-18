use anyhow::{bail, Result};
use clap::{Subcommand, ValueEnum};
use sentinel_agent::notify::{render_alert_for_config, NotificationManager, NotifyContext};
use sentinel_agent::report::{build_report_finding, build_security_report, ReportPeriod};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use std::sync::Arc;

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    Show {
        #[arg(long, value_enum, default_value_t = ReportPeriodArg::Today)]
        period: ReportPeriodArg,
        #[arg(long)]
        json: bool,
    },
    Send {
        #[arg(long, value_enum, default_value_t = ReportPeriodArg::Today)]
        period: ReportPeriodArg,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ReportPeriodArg {
    Today,
    Last24h,
}

impl From<ReportPeriodArg> for ReportPeriod {
    fn from(value: ReportPeriodArg) -> Self {
        match value {
            ReportPeriodArg::Today => Self::Today,
            ReportPeriodArg::Last24h => Self::Last24h,
        }
    }
}

pub async fn run_report(config: SentinelConfig, command: ReportCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        ReportCommand::Show { period, json } => {
            if json {
                let report = build_security_report(&config, &store, period.into())?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }
            let finding = build_report_finding(&config, &store, period.into())?;
            let rendered = render_alert_for_config(&finding, &config);
            println!("{}", rendered.plain_text);
        }
        ReportCommand::Send { period } => {
            let finding = build_report_finding(&config, &store, period.into())?;
            let manager = NotificationManager::from_config(&config);
            if manager.enabled_count() == 0 {
                println!("no notification channels are enabled");
                return Ok(());
            }
            let ctx = NotifyContext {
                config: Arc::new(config),
            };
            let results = manager.notify_all_channels(&finding, &ctx).await;
            let mut failures = 0usize;
            let mut delivered = 0usize;
            for (_finding_id, channel, result) in results {
                match result {
                    Ok(()) => {
                        delivered += 1;
                        store.record_notification_log(&finding.id, &channel, "ok", "")?;
                        println!("{channel}: ok");
                    }
                    Err(err) => {
                        failures += 1;
                        let error = err.to_string();
                        store.record_notification_log(&finding.id, &channel, "error", &error)?;
                        println!("{channel}: failed: {error}");
                    }
                }
            }
            if failures > 0 {
                bail!("{failures} report notification channel(s) failed");
            }
            println!("report sent to {delivered} channel(s)");
        }
    }
    Ok(())
}
