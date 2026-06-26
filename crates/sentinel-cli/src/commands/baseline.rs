use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::baseline::{
    apply_approved_changes, approval_items_with_config, approve_keys, BaselineApprovalItem,
    BaselineApprovalState, BASELINE_APPROVAL_STATE_ID,
};
use sentinel_agent::scanner::create_baseline_snapshot;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum BaselineCommand {
    Create,
    Show,
    Diff {
        #[arg(long)]
        json: bool,
    },
    Approve {
        keys: Vec<String>,
        #[arg(long)]
        note: Option<String>,
    },
    Refresh {
        #[arg(long)]
        all: bool,
    },
    Reset,
}

pub async fn run_baseline(config: SentinelConfig, command: BaselineCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    match command {
        BaselineCommand::Create => {
            let snapshot = create_baseline_snapshot(config, PathBuf::from("/")).await?;
            store.save_baseline_snapshot(&snapshot)?;
            println!("baseline created: {}", snapshot.id);
        }
        BaselineCommand::Show => {
            let snapshot = store.latest_baseline_snapshot()?;
            match snapshot {
                Some(snapshot) => println!("{}", serde_json::to_string_pretty(&snapshot)?),
                None => bail!("no baseline snapshot found"),
            }
        }
        BaselineCommand::Diff { json } => {
            let items = current_approval_items(&store, config).await?;
            print_approval_items(&items, json)?;
        }
        BaselineCommand::Approve { keys, note } => {
            if keys.is_empty() {
                bail!("at least one approval key is required; use `all` to approve every pending change");
            }
            let items = current_approval_items(&store, config).await?;
            let mut state = store
                .load_rule_state::<BaselineApprovalState>(BASELINE_APPROVAL_STATE_ID)?
                .unwrap_or_default();
            let approved = approve_keys(&mut state, &items, &keys, note);
            if approved.is_empty() {
                bail!("no pending baseline changes matched the requested key(s)");
            }
            store.save_rule_state(BASELINE_APPROVAL_STATE_ID, &state)?;
            println!("approved {} baseline change(s)", approved.len());
            for key in approved {
                println!("- {key}");
            }
        }
        BaselineCommand::Refresh { all } => {
            let current = create_baseline_snapshot(config, PathBuf::from("/")).await?;
            if all {
                store.save_baseline_snapshot(&current)?;
                println!(
                    "baseline refreshed with all current host facts: {}",
                    current.id
                );
            } else {
                let Some(previous) = store.latest_baseline_snapshot()? else {
                    bail!("no baseline snapshot found");
                };
                let mut state = store
                    .load_rule_state::<BaselineApprovalState>(BASELINE_APPROVAL_STATE_ID)?
                    .unwrap_or_default();
                let (refreshed, report) = apply_approved_changes(&previous, &current, &mut state);
                if report.approved_changes == 0 {
                    bail!("no approved baseline changes found; run `vs baseline diff` and `vs baseline approve <key>` first");
                }
                store.save_baseline_snapshot(&refreshed)?;
                store.save_rule_state(BASELINE_APPROVAL_STATE_ID, &state)?;
                println!(
                    "baseline refreshed: {} approved_change(s), {} remaining_change(s), snapshot={}",
                    report.approved_changes, report.remaining_changes, report.snapshot_id
                );
            }
        }
        BaselineCommand::Reset => {
            store.clear_baselines()?;
            println!("baseline snapshots cleared");
        }
    }
    Ok(())
}

async fn current_approval_items(
    store: &SqliteStore,
    config: SentinelConfig,
) -> Result<Vec<BaselineApprovalItem>> {
    let Some(previous) = store.latest_baseline_snapshot()? else {
        bail!("no baseline snapshot found");
    };
    let current = create_baseline_snapshot(config.clone(), PathBuf::from("/")).await?;
    Ok(approval_items_with_config(&previous, &current, &config))
}

fn print_approval_items(items: &[BaselineApprovalItem], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("no pending baseline changes");
        return Ok(());
    }
    for item in items {
        println!(
            "{} {} subject={} action={} risk={} tier={} score={} review={}",
            item.key,
            item.kind,
            item.subject,
            item.action,
            item.risk_hint,
            item.risk_tier,
            item.risk_score,
            item.review_action
        );
        if !item.reasons.is_empty() {
            println!("  reasons={}", item.reasons.join("; "));
        }
    }
    Ok(())
}
