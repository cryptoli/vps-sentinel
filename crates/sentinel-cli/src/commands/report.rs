use anyhow::{bail, Result};
use clap::{Subcommand, ValueEnum};
use sentinel_agent::notify::render_alert_for_config;
use sentinel_agent::report::{
    build_report_finding, build_security_report, send_report_finding, ReportPeriod,
};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

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
            let delivery = send_report_finding(&config, &store, &finding).await?;
            if delivery.enabled_channels == 0 {
                println!("no notification channels are enabled");
                return Ok(());
            }
            for outcome in &delivery.outcomes {
                if outcome.status == "ok" {
                    println!("{}: ok", outcome.channel);
                } else {
                    println!("{}: failed: {}", outcome.channel, outcome.error);
                }
            }
            if delivery.failed > 0 {
                bail!("{} report notification channel(s) failed", delivery.failed);
            }
            println!("report sent to {} channel(s)", delivery.delivered);
        }
    }
    Ok(())
}
