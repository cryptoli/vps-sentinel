use crate::storage::SqliteStore;
use crate::utils::memory::current_rss_kb;
use chrono::{DateTime, Utc};
use sentinel_core::SentinelResult;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const STATE_RULE_ID: &str = "panel_node_metrics";
const PROC_ROOT: &str = "/proc";
const LOOPBACK_INTERFACE: &str = "lo";
const BYTES_PER_KIB: u64 = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub sampled_at: DateTime<Utc>,
    pub cpu_cores: Option<u16>,
    pub cpu_percent: Option<f64>,
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_used_percent: Option<f64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub uptime_seconds: Option<u64>,
    pub uptime_days: Option<f64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub network_rx_rate_bps: Option<u64>,
    pub network_tx_rate_bps: Option<u64>,
    pub network_interfaces: Option<u16>,
    pub agent_rss_kb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeMetricsState {
    sampled_at: DateTime<Utc>,
    cpu_total_ticks: Option<u64>,
    cpu_idle_ticks: Option<u64>,
    network_rx_bytes: Option<u64>,
    network_tx_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct RawNodeMetrics {
    cpu_cores: Option<u16>,
    cpu_ticks: Option<CpuTicks>,
    load: Option<LoadAverage>,
    memory: Option<MemoryStats>,
    uptime_seconds: Option<u64>,
    network: Option<NetworkStats>,
    agent_rss_kb: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTicks {
    total: u64,
    idle: u64,
}

#[derive(Debug, Clone, Copy)]
struct LoadAverage {
    one: f64,
    five: f64,
    fifteen: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemoryStats {
    total_bytes: u64,
    used_bytes: u64,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkStats {
    rx_bytes: u64,
    tx_bytes: u64,
    interfaces: u16,
}

pub fn collect_node_metrics(store: &SqliteStore) -> SentinelResult<NodeMetrics> {
    let now = Utc::now();
    let previous = store.load_rule_state::<NodeMetricsState>(STATE_RULE_ID)?;
    let raw = collect_raw_metrics(Path::new(PROC_ROOT));
    let metrics = build_node_metrics(now, &raw, previous.as_ref());
    store.save_rule_state(STATE_RULE_ID, &state_from_raw(now, &raw))?;
    Ok(metrics)
}

fn collect_raw_metrics(proc_root: &Path) -> RawNodeMetrics {
    RawNodeMetrics {
        cpu_cores: cpu_cores(proc_root).or_else(host_parallelism),
        cpu_ticks: read_cpu_ticks(proc_root.join("stat")),
        load: read_load_average(proc_root.join("loadavg")),
        memory: read_memory_stats(proc_root.join("meminfo")),
        uptime_seconds: read_uptime_seconds(proc_root.join("uptime")),
        network: read_network_stats(proc_root.join("net/dev")),
        agent_rss_kb: current_rss_kb(),
    }
}

fn build_node_metrics(
    sampled_at: DateTime<Utc>,
    raw: &RawNodeMetrics,
    previous: Option<&NodeMetricsState>,
) -> NodeMetrics {
    let cpu_percent = raw
        .cpu_ticks
        .and_then(|current| previous.and_then(|state| cpu_percent(current, state)));
    let (network_rx_rate_bps, network_tx_rate_bps) = raw
        .network
        .and_then(|current| previous.and_then(|state| network_rates(current, sampled_at, state)))
        .unwrap_or((None, None));
    NodeMetrics {
        sampled_at,
        cpu_cores: raw.cpu_cores,
        cpu_percent,
        load1: raw.load.map(|load| load.one),
        load5: raw.load.map(|load| load.five),
        load15: raw.load.map(|load| load.fifteen),
        memory_total_bytes: raw.memory.map(|memory| memory.total_bytes),
        memory_used_bytes: raw.memory.map(|memory| memory.used_bytes),
        memory_used_percent: raw.memory.and_then(memory_used_percent),
        swap_total_bytes: raw.memory.map(|memory| memory.swap_total_bytes),
        swap_used_bytes: raw.memory.map(|memory| memory.swap_used_bytes),
        uptime_seconds: raw.uptime_seconds,
        uptime_days: raw
            .uptime_seconds
            .map(|seconds| round2(seconds as f64 / 86_400.0)),
        network_rx_bytes: raw.network.map(|network| network.rx_bytes),
        network_tx_bytes: raw.network.map(|network| network.tx_bytes),
        network_rx_rate_bps,
        network_tx_rate_bps,
        network_interfaces: raw.network.map(|network| network.interfaces),
        agent_rss_kb: raw.agent_rss_kb,
    }
}

fn state_from_raw(sampled_at: DateTime<Utc>, raw: &RawNodeMetrics) -> NodeMetricsState {
    NodeMetricsState {
        sampled_at,
        cpu_total_ticks: raw.cpu_ticks.map(|ticks| ticks.total),
        cpu_idle_ticks: raw.cpu_ticks.map(|ticks| ticks.idle),
        network_rx_bytes: raw.network.map(|network| network.rx_bytes),
        network_tx_bytes: raw.network.map(|network| network.tx_bytes),
    }
}

fn cpu_percent(current: CpuTicks, previous: &NodeMetricsState) -> Option<f64> {
    let previous_total = previous.cpu_total_ticks?;
    let previous_idle = previous.cpu_idle_ticks?;
    let total_delta = current.total.checked_sub(previous_total)?;
    let idle_delta = current.idle.checked_sub(previous_idle)?;
    if total_delta == 0 || idle_delta > total_delta {
        return None;
    }
    Some(round2(
        ((total_delta - idle_delta) as f64 / total_delta as f64) * 100.0,
    ))
}

fn network_rates(
    current: NetworkStats,
    sampled_at: DateTime<Utc>,
    previous: &NodeMetricsState,
) -> Option<(Option<u64>, Option<u64>)> {
    let elapsed = sampled_at
        .signed_duration_since(previous.sampled_at)
        .num_seconds();
    if elapsed <= 0 {
        return None;
    }
    let elapsed = elapsed as u64;
    let rx = previous
        .network_rx_bytes
        .and_then(|previous_rx| current.rx_bytes.checked_sub(previous_rx))
        .map(|delta| bytes_per_second(delta, elapsed));
    let tx = previous
        .network_tx_bytes
        .and_then(|previous_tx| current.tx_bytes.checked_sub(previous_tx))
        .map(|delta| bytes_per_second(delta, elapsed));
    Some((rx, tx))
}

fn bytes_per_second(bytes: u64, seconds: u64) -> u64 {
    if seconds == 0 {
        0
    } else {
        bytes / seconds
    }
}

fn memory_used_percent(memory: MemoryStats) -> Option<f64> {
    if memory.total_bytes == 0 {
        None
    } else {
        Some(round2(
            memory.used_bytes as f64 / memory.total_bytes as f64 * 100.0,
        ))
    }
}

fn read_cpu_ticks(path: impl Into<PathBuf>) -> Option<CpuTicks> {
    let text = fs::read_to_string(path.into()).ok()?;
    parse_cpu_ticks(&text)
}

fn parse_cpu_ticks(stat: &str) -> Option<CpuTicks> {
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let values = line
        .split_whitespace()
        .skip(1)
        .filter_map(|item| item.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if values.len() < 4 {
        return None;
    }
    let idle = values
        .get(3)
        .copied()
        .unwrap_or_default()
        .saturating_add(values.get(4).copied().unwrap_or_default());
    let total = values
        .iter()
        .fold(0u64, |sum, value| sum.saturating_add(*value));
    Some(CpuTicks { total, idle })
}

fn cpu_cores(proc_root: &Path) -> Option<u16> {
    let text = fs::read_to_string(proc_root.join("cpuinfo")).ok()?;
    let count = text
        .lines()
        .filter(|line| line.trim_start().starts_with("processor"))
        .count();
    u16::try_from(count).ok().filter(|count| *count > 0)
}

fn host_parallelism() -> Option<u16> {
    std::thread::available_parallelism()
        .ok()
        .and_then(|value| u16::try_from(value.get()).ok())
}

fn read_load_average(path: impl Into<PathBuf>) -> Option<LoadAverage> {
    let text = fs::read_to_string(path.into()).ok()?;
    let mut parts = text.split_whitespace();
    Some(LoadAverage {
        one: round2(parts.next()?.parse::<f64>().ok()?),
        five: round2(parts.next()?.parse::<f64>().ok()?),
        fifteen: round2(parts.next()?.parse::<f64>().ok()?),
    })
}

fn read_memory_stats(path: impl Into<PathBuf>) -> Option<MemoryStats> {
    let text = fs::read_to_string(path.into()).ok()?;
    parse_memory_stats(&text)
}

fn parse_memory_stats(meminfo: &str) -> Option<MemoryStats> {
    let total = meminfo_value_kib(meminfo, "MemTotal")?;
    let available = meminfo_value_kib(meminfo, "MemAvailable")
        .or_else(|| {
            let free = meminfo_value_kib(meminfo, "MemFree")?;
            let buffers = meminfo_value_kib(meminfo, "Buffers").unwrap_or_default();
            let cached = meminfo_value_kib(meminfo, "Cached").unwrap_or_default();
            Some(free.saturating_add(buffers).saturating_add(cached))
        })
        .unwrap_or_default();
    let swap_total = meminfo_value_kib(meminfo, "SwapTotal").unwrap_or_default();
    let swap_free = meminfo_value_kib(meminfo, "SwapFree").unwrap_or_default();
    Some(MemoryStats {
        total_bytes: total.saturating_mul(BYTES_PER_KIB),
        used_bytes: total
            .saturating_sub(available)
            .saturating_mul(BYTES_PER_KIB),
        swap_total_bytes: swap_total.saturating_mul(BYTES_PER_KIB),
        swap_used_bytes: swap_total
            .saturating_sub(swap_free)
            .saturating_mul(BYTES_PER_KIB),
    })
}

fn meminfo_value_kib(meminfo: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key}:");
    meminfo.lines().find_map(|line| {
        let value = line.strip_prefix(&prefix)?.trim();
        value.split_whitespace().next()?.parse::<u64>().ok()
    })
}

fn read_uptime_seconds(path: impl Into<PathBuf>) -> Option<u64> {
    let text = fs::read_to_string(path.into()).ok()?;
    text.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|value| value.max(0.0) as u64)
}

fn read_network_stats(path: impl Into<PathBuf>) -> Option<NetworkStats> {
    let text = fs::read_to_string(path.into()).ok()?;
    parse_network_stats(&text)
}

fn parse_network_stats(netdev: &str) -> Option<NetworkStats> {
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;
    let mut interfaces = 0u16;
    for line in netdev.lines().skip(2) {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == LOOPBACK_INTERFACE {
            continue;
        }
        let values = counters.split_whitespace().collect::<Vec<_>>();
        let Some(rx) = values.first().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let Some(tx) = values.get(8).and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        rx_bytes = rx_bytes.saturating_add(rx);
        tx_bytes = tx_bytes.saturating_add(tx);
        interfaces = interfaces.saturating_add(1);
    }
    (interfaces > 0).then_some(NetworkStats {
        rx_bytes,
        tx_bytes,
        interfaces,
    })
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::{
        build_node_metrics, parse_cpu_ticks, parse_memory_stats, parse_network_stats, CpuTicks,
        NetworkStats, NodeMetricsState, RawNodeMetrics,
    };
    use chrono::{TimeZone, Utc};

    #[test]
    fn parses_cpu_ticks_from_proc_stat() {
        let ticks = parse_cpu_ticks("cpu  100 0 50 850 10 0 0 0 0 0\n").expect("cpu ticks");

        assert_eq!(ticks.total, 1010);
        assert_eq!(ticks.idle, 860);
    }

    #[test]
    fn computes_cpu_and_network_delta_metrics() {
        let now = Utc.with_ymd_and_hms(2026, 6, 22, 8, 0, 10).unwrap();
        let previous = NodeMetricsState {
            sampled_at: Utc.with_ymd_and_hms(2026, 6, 22, 8, 0, 0).unwrap(),
            cpu_total_ticks: Some(1_000),
            cpu_idle_ticks: Some(700),
            network_rx_bytes: Some(1_000),
            network_tx_bytes: Some(2_000),
        };
        let raw = RawNodeMetrics {
            cpu_ticks: Some(CpuTicks {
                total: 1_200,
                idle: 820,
            }),
            network: Some(NetworkStats {
                rx_bytes: 3_000,
                tx_bytes: 2_500,
                interfaces: 1,
            }),
            ..RawNodeMetrics::default()
        };

        let metrics = build_node_metrics(now, &raw, Some(&previous));

        assert_eq!(metrics.cpu_percent, Some(40.0));
        assert_eq!(metrics.network_rx_rate_bps, Some(200));
        assert_eq!(metrics.network_tx_rate_bps, Some(50));
    }

    #[test]
    fn parses_memory_and_network_without_loopback() {
        let memory = parse_memory_stats(
            "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 500 kB\nSwapFree: 100 kB\n",
        )
        .expect("memory");
        let network = parse_network_stats(
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n lo: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n eth0: 1000 0 0 0 0 0 0 0 3000 0 0 0 0 0 0 0\n",
        )
        .expect("network");

        assert_eq!(memory.total_bytes, 1_024_000);
        assert_eq!(memory.used_bytes, 768_000);
        assert_eq!(memory.swap_used_bytes, 409_600);
        assert_eq!(network.rx_bytes, 1_000);
        assert_eq!(network.tx_bytes, 3_000);
        assert_eq!(network.interfaces, 1);
    }
}
