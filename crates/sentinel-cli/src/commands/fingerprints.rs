use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_agent::attack_fingerprint::{
    redact_fingerprint, redact_observation, valid_verdict, AttackFingerprint, AttackObservation,
};
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use serde_json::json;

#[derive(Debug, Subcommand)]
pub enum FingerprintsCommand {
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    Show {
        fingerprint_id: String,
        #[arg(long)]
        json: bool,
    },
    Timeline {
        fingerprint_id: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    MarkBenign {
        fingerprint_id: String,
    },
    MarkMalicious {
        fingerprint_id: String,
    },
    MarkUnknown {
        fingerprint_id: String,
    },
    Export {
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        redacted: bool,
    },
}

pub fn run_fingerprints(config: SentinelConfig, command: FingerprintsCommand) -> Result<()> {
    let store = SqliteStore::open(config.storage.path)?;
    match command {
        FingerprintsCommand::List { limit, json } => {
            let fingerprints = store.list_attack_fingerprints(limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&fingerprints)?);
                return Ok(());
            }
            for fingerprint in fingerprints {
                print_fingerprint_summary(&fingerprint);
            }
        }
        FingerprintsCommand::Show {
            fingerprint_id,
            json,
        } => {
            let Some(fingerprint) = store.get_attack_fingerprint(&fingerprint_id)? else {
                println!("fingerprint not found: {fingerprint_id}");
                return Ok(());
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&fingerprint)?);
            } else {
                print_fingerprint_detail(&fingerprint);
            }
        }
        FingerprintsCommand::Timeline {
            fingerprint_id,
            limit,
            json,
        } => {
            let observations = store.list_attack_observations(&fingerprint_id, limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&observations)?);
            } else {
                for observation in observations {
                    print_observation(&observation);
                }
            }
        }
        FingerprintsCommand::MarkBenign { fingerprint_id } => {
            set_verdict(&store, &fingerprint_id, "benign")?;
        }
        FingerprintsCommand::MarkMalicious { fingerprint_id } => {
            set_verdict(&store, &fingerprint_id, "malicious")?;
        }
        FingerprintsCommand::MarkUnknown { fingerprint_id } => {
            set_verdict(&store, &fingerprint_id, "unknown")?;
        }
        FingerprintsCommand::Export { limit, redacted } => {
            let mut fingerprints = store.list_attack_fingerprints(limit)?;
            let mut observations = Vec::new();
            for fingerprint in &fingerprints {
                observations.extend(store.list_attack_observations(&fingerprint.id, 20)?);
            }
            if redacted {
                for fingerprint in &mut fingerprints {
                    redact_fingerprint(fingerprint);
                }
                for observation in &mut observations {
                    redact_observation(observation);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "fingerprints": fingerprints,
                    "observations": observations,
                    "redacted": redacted,
                }))?
            );
        }
    }
    Ok(())
}

fn set_verdict(store: &SqliteStore, fingerprint_id: &str, verdict: &str) -> Result<()> {
    if !valid_verdict(verdict) {
        bail!("invalid verdict: {verdict}");
    }
    if store.set_attack_fingerprint_verdict(fingerprint_id, verdict)? {
        println!("fingerprint {fingerprint_id} verdict set to {verdict}");
    } else {
        println!("fingerprint not found: {fingerprint_id}");
    }
    Ok(())
}

fn print_fingerprint_summary(fingerprint: &AttackFingerprint) {
    println!(
        "{} [{} score={} confidence={} seen={} ips={} hosts={} verdict={}] {}",
        fingerprint.id,
        fingerprint.kind,
        fingerprint.score,
        fingerprint.confidence,
        fingerprint.seen_count,
        fingerprint.source_ips.len(),
        fingerprint.hosts.len(),
        fingerprint.verdict,
        fingerprint.summary
    );
}

fn print_fingerprint_detail(fingerprint: &AttackFingerprint) {
    print_fingerprint_summary(fingerprint);
    println!("first_seen: {}", fingerprint.first_seen_at);
    println!("last_seen: {}", fingerprint.last_seen_at);
    println!("exact_hash: {}", fingerprint.exact_hash);
    println!("simhash: {}", fingerprint.simhash);
    if !fingerprint.source_ips.is_empty() {
        println!("source_ips: {}", fingerprint.source_ips.join(", "));
    }
    if !fingerprint.rule_ids.is_empty() {
        println!("rules: {}", fingerprint.rule_ids.join(", "));
    }
    if !fingerprint.features.is_empty() {
        println!("features:");
        for feature in &fingerprint.features {
            println!("- {}={}", feature.key, feature.value);
        }
    }
}

fn print_observation(observation: &AttackObservation) {
    println!(
        "{} rule={} host={} ip={} finding={} {}",
        observation.observed_at,
        observation.rule_id,
        observation.host_id,
        empty_as_dash(&observation.source_ip),
        observation.finding_id,
        observation.evidence_summary
    );
}

fn empty_as_dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}
