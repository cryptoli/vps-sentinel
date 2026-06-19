use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Subcommand;
use sentinel_agent::maintenance::{
    end_maintenance, maintenance_state, start_maintenance, MaintenanceState,
};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;

#[derive(Debug, Subcommand)]
pub enum MaintenanceCommand {
    Start {
        #[arg(long)]
        duration_seconds: Option<u64>,
        #[arg(long, default_value = "manual maintenance")]
        reason: String,
    },
    End,
    Status {
        #[arg(long)]
        json: bool,
    },
}

pub fn run_maintenance(config: SentinelConfig, command: MaintenanceCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        MaintenanceCommand::Start {
            duration_seconds,
            reason,
        } => {
            let state = start_maintenance(&store, &config, duration_seconds, reason)?;
            println!(
                "maintenance started: expires_at={}",
                state
                    .expires_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
        MaintenanceCommand::End => {
            end_maintenance(&store)?;
            println!("maintenance ended");
        }
        MaintenanceCommand::Status { json } => {
            let state = maintenance_state(&store)?;
            let now = Utc::now();
            if json {
                println!("{}", serde_json::to_string_pretty(&state)?);
                return Ok(());
            }
            println!("{}", maintenance_status_line(state.as_ref(), now));
        }
    }
    Ok(())
}

fn maintenance_status_line(state: Option<&MaintenanceState>, now: DateTime<Utc>) -> String {
    match state {
        Some(state) if state.is_active_at(now) => format!(
            "maintenance active: started_at={} expires_at={} reason={}",
            format_time(state.started_at),
            format_time(state.expires_at),
            state.reason
        ),
        Some(state) => format!(
            "maintenance inactive: expired_at={} reason={}",
            format_time(state.expires_at),
            state.reason
        ),
        None => "maintenance inactive".to_string(),
    }
}

fn format_time(value: Option<DateTime<Utc>>) -> String {
    value
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::maintenance_status_line;
    use chrono::{Duration, TimeZone, Utc};
    use sentinel_agent::maintenance::MaintenanceState;

    #[test]
    fn status_line_reports_expired_window_as_inactive() {
        let now = Utc.with_ymd_and_hms(2026, 6, 19, 12, 0, 0).unwrap();
        let state = MaintenanceState {
            started_at: Some(now - Duration::minutes(20)),
            expires_at: Some(now - Duration::minutes(10)),
            reason: "update".to_string(),
        };

        let line = maintenance_status_line(Some(&state), now);

        assert!(line.starts_with("maintenance inactive: expired_at="));
        assert!(line.contains("reason=update"));
    }

    #[test]
    fn status_line_reports_unexpired_window_as_active() {
        let now = Utc.with_ymd_and_hms(2026, 6, 19, 12, 0, 0).unwrap();
        let state = MaintenanceState {
            started_at: Some(now - Duration::minutes(1)),
            expires_at: Some(now + Duration::minutes(9)),
            reason: "update".to_string(),
        };

        let line = maintenance_status_line(Some(&state), now);

        assert!(line.starts_with("maintenance active: started_at="));
        assert!(line.contains("reason=update"));
    }
}
