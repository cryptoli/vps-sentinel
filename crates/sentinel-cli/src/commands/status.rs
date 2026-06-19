use anyhow::Result;
use chrono::{Duration, Utc};
use sentinel_agent::active_response::list_active_blocks;
use sentinel_agent::storage::SqliteStore;
use sentinel_core::SentinelConfig;
use serde_json::json;

pub fn run_status(config: SentinelConfig, json_output: bool) -> Result<()> {
    let store = SqliteStore::open(config.storage.path.clone())?;
    let stats = store.stats()?;
    let now = Utc::now();
    let scan_summary = store.scan_run_summary_between(now - Duration::hours(24), now)?;
    let active_blocks = list_active_blocks(&config, &store, false)?;
    let notification_channels = enabled_notification_channels(&config);
    let enabled_features = enabled_features(&config);

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "host_id": config.host_id(),
                "display_name": config.display_name(),
                "storage": {
                    "path": config.storage.path.display().to_string(),
                    "database_bytes": stats.database_bytes,
                    "raw_events": stats.raw_events,
                    "findings": stats.findings,
                    "notifications": stats.notification_logs,
                    "scan_runs": stats.scan_runs,
                    "attack_fingerprints": stats.attack_fingerprints,
                    "attack_observations": stats.attack_observations,
                    "baseline_snapshots": stats.baseline_snapshots,
                },
                "last_24h": {
                    "scan_runs": scan_summary.total,
                    "failed_scan_runs": scan_summary.failed,
                    "last_finished_at": scan_summary.last_finished_at,
                },
                "features": enabled_features,
                "notification_channels": notification_channels,
                "active_response": {
                    "enabled": config.active_response.enabled,
                    "strategy": config.active_response.strategy,
                    "backend": config.active_response.firewall_backend,
                    "active_blocks": active_blocks.len(),
                    "permanent_blocks": active_blocks.iter().filter(|entry| entry.expires_at.is_none()).count(),
                }
            }))?
        );
        return Ok(());
    }

    println!("host_id={}", config.host_id());
    println!("display_name={}", config.display_name());
    println!("storage_path={}", config.storage.path.display());
    println!("database_bytes={}", stats.database_bytes);
    println!("raw_events={}", stats.raw_events);
    println!("findings={}", stats.findings);
    println!("scan_runs_24h={}", scan_summary.total);
    println!("failed_scan_runs_24h={}", scan_summary.failed);
    println!(
        "last_scan_finished_at={}",
        scan_summary
            .last_finished_at
            .map(|timestamp| timestamp.to_rfc3339())
            .unwrap_or_else(|| "none".to_string())
    );
    println!("enabled_features={}", enabled_features.join(","));
    println!("notification_channels={}", notification_channels.join(","));
    println!("active_response_enabled={}", config.active_response.enabled);
    println!(
        "active_response_strategy={}",
        config.active_response.strategy
    );
    println!(
        "active_response_backend={}",
        config.active_response.firewall_backend
    );
    println!("active_blocks={}", active_blocks.len());
    println!(
        "permanent_blocks={}",
        active_blocks
            .iter()
            .filter(|entry| entry.expires_at.is_none())
            .count()
    );
    Ok(())
}

fn enabled_features(config: &SentinelConfig) -> Vec<&'static str> {
    let mut features = Vec::new();
    push_enabled(&mut features, config.ssh.enabled, "ssh");
    push_enabled(&mut features, config.web.enabled, "web");
    push_enabled(&mut features, config.process.enabled, "process");
    push_enabled(&mut features, config.gpu.enabled, "gpu");
    push_enabled(&mut features, config.network.enabled, "network");
    push_enabled(&mut features, config.persistence.enabled, "persistence");
    push_enabled(&mut features, config.docker.enabled, "docker");
    push_enabled(
        &mut features,
        config.file_integrity.enabled,
        "file_integrity",
    );
    push_enabled(&mut features, config.log_integrity.enabled, "log_integrity");
    push_enabled(
        &mut features,
        config.attack_fingerprints.enabled,
        "attack_fingerprints",
    );
    push_enabled(
        &mut features,
        config.advanced_collectors.auditd_enabled,
        "auditd",
    );
    push_enabled(
        &mut features,
        config.advanced_collectors.ebpf_bridge_enabled,
        "ebpf_bridge",
    );
    push_enabled(
        &mut features,
        config.external_rules.enabled,
        "external_rules",
    );
    push_enabled(&mut features, config.threat_intel.enabled, "threat_intel");
    features
}

fn enabled_notification_channels(config: &SentinelConfig) -> Vec<&'static str> {
    let mut channels = Vec::new();
    push_enabled(
        &mut channels,
        config.notifications.telegram.enabled,
        "telegram",
    );
    push_enabled(&mut channels, config.notifications.email.enabled, "email");
    push_enabled(
        &mut channels,
        config.notifications.webhook.enabled,
        "webhook",
    );
    push_enabled(&mut channels, config.notifications.ntfy.enabled, "ntfy");
    push_enabled(&mut channels, config.notifications.gotify.enabled, "gotify");
    push_enabled(&mut channels, config.notifications.bark.enabled, "bark");
    push_enabled(
        &mut channels,
        config.notifications.serverchan.enabled,
        "serverchan",
    );
    channels
}

fn push_enabled(values: &mut Vec<&'static str>, enabled: bool, value: &'static str) {
    if enabled {
        values.push(value);
    }
}
