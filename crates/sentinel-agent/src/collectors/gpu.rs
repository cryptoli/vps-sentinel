use crate::collectors::{CollectContext, Collector};
use crate::utils::command::successful_stdout;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const NVIDIA_SMI_FORMAT: &str = "--format=csv,noheader,nounits";
const NVIDIA_GPU_STATS_QUERY: &str = "--query-gpu=uuid,utilization.gpu,power.draw";
const NVIDIA_SMI_QUERIES: &[&str] = &[
    "--query-compute-apps=pid,process_name,used_gpu_memory,gpu_uuid",
    "--query-compute-apps=pid,process_name,used_gpu_memory",
    "--query-compute-apps=pid,process_name,used_memory",
];

pub struct GpuCollector;

#[async_trait]
impl Collector for GpuCollector {
    fn name(&self) -> &'static str {
        "gpu"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.gpu.enabled {
            return Ok(Vec::new());
        }
        let timeout = Duration::from_secs(ctx.config.gpu.command_timeout_seconds);
        let mut events = Vec::new();
        let nvidia_program = ctx.config.gpu.nvidia_smi_path.trim();
        if !nvidia_program.is_empty() {
            events.extend(collect_nvidia_compute_processes(nvidia_program, timeout));
        }
        let rocm_program = ctx.config.gpu.rocm_smi_path.trim();
        if !rocm_program.is_empty() {
            events.extend(collect_rocm_compute_processes(rocm_program, timeout));
        }
        Ok(events)
    }
}

fn collect_nvidia_compute_processes(program: &str, timeout: Duration) -> Vec<RawEvent> {
    NVIDIA_SMI_QUERIES
        .iter()
        .find_map(|query| successful_stdout(program, &[*query, NVIDIA_SMI_FORMAT], timeout))
        .map(|output| {
            let processes = parse_nvidia_compute_apps(&output);
            let stats = if processes.iter().any(|process| process.gpu_uuid.is_some()) {
                successful_stdout(
                    program,
                    &[NVIDIA_GPU_STATS_QUERY, NVIDIA_SMI_FORMAT],
                    timeout,
                )
                .map(|output| parse_nvidia_gpu_stats(&output))
                .unwrap_or_default()
            } else {
                BTreeMap::new()
            };
            processes
                .into_iter()
                .map(|process| {
                    let mut event = RawEvent::new("gpu", "gpu_compute_process")
                        .with_field("pid", process.pid)
                        .with_field("gpu_vendor", "nvidia")
                        .with_field("gpu_process_name", process.process_name)
                        .with_field("gpu_memory_mb", process.used_memory_mb.to_string());
                    if let Some(uuid) = process.gpu_uuid {
                        if let Some(stat) = stats.get(&uuid) {
                            event = event.with_field(
                                "gpu_utilization_percent",
                                stat.utilization_percent.to_string(),
                            );
                            if let Some(power) = stat.power_watts {
                                event = event.with_field("gpu_power_watts", format!("{power:.1}"));
                            }
                        }
                        event = event.with_field("gpu_uuid", uuid);
                    }
                    event
                })
                .collect()
        })
        .unwrap_or_default()
}

fn collect_rocm_compute_processes(program: &str, timeout: Duration) -> Vec<RawEvent> {
    successful_stdout(program, &["--showpids", "--json"], timeout)
        .map(|output| {
            parse_rocm_compute_apps(&output)
                .into_iter()
                .map(|process| {
                    RawEvent::new("gpu", "gpu_compute_process")
                        .with_field("pid", process.pid)
                        .with_field("gpu_vendor", "amd")
                        .with_field("gpu_process_name", process.process_name)
                        .with_field("gpu_memory_mb", process.used_memory_mb.to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GpuProcess {
    pid: String,
    process_name: String,
    used_memory_mb: u64,
    gpu_uuid: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct GpuDeviceStats {
    utilization_percent: u8,
    power_watts: Option<f32>,
}

fn parse_nvidia_compute_apps(output: &str) -> Vec<GpuProcess> {
    output
        .lines()
        .filter_map(parse_nvidia_compute_app_line)
        .collect()
}

fn parse_nvidia_compute_app_line(line: &str) -> Option<GpuProcess> {
    let columns = line
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if columns.len() < 3 {
        return None;
    }

    let pid = columns.first()?.trim();
    if pid.parse::<u32>().is_err() {
        return None;
    }

    let (process_name, memory, gpu_uuid) = if columns.len() >= 4 {
        let uuid = columns.last().map(|value| (*value).to_string());
        let memory = columns.get(columns.len().saturating_sub(2))?;
        let name = columns[1..columns.len().saturating_sub(2)].join(",");
        (name, *memory, uuid)
    } else {
        (columns[1].to_string(), columns[2], None)
    };

    let used_memory_mb = parse_memory_mb(memory)?;
    Some(GpuProcess {
        pid: pid.to_string(),
        process_name: process_name.trim().to_string(),
        used_memory_mb,
        gpu_uuid: gpu_uuid.filter(|value| !value.trim().is_empty()),
    })
}

fn parse_nvidia_gpu_stats(output: &str) -> BTreeMap<String, GpuDeviceStats> {
    output
        .lines()
        .filter_map(parse_nvidia_gpu_stat_line)
        .collect()
}

fn parse_nvidia_gpu_stat_line(line: &str) -> Option<(String, GpuDeviceStats)> {
    let columns = line
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if columns.len() < 2 {
        return None;
    }
    let uuid = columns.first()?.trim();
    if !uuid.starts_with("GPU-") {
        return None;
    }
    let utilization_percent = parse_percent(columns.get(1)?)?;
    let power_watts = columns.get(2).and_then(|value| parse_float(value));
    Some((
        uuid.to_string(),
        GpuDeviceStats {
            utilization_percent,
            power_watts,
        },
    ))
}

fn parse_memory_mb(value: &str) -> Option<u64> {
    let digits = value
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u64>().ok()
}

fn parse_percent(value: &str) -> Option<u8> {
    parse_float(value).map(|value| value.round().clamp(0.0, 100.0) as u8)
}

fn parse_float(value: &str) -> Option<f32> {
    let normalized = value.trim().replace('%', "");
    let numeric = normalized
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|ch: char| ch == '[' || ch == ']');
    numeric
        .parse::<f32>()
        .ok()
        .filter(|value| value.is_finite())
}

fn parse_rocm_compute_apps(output: &str) -> Vec<GpuProcess> {
    let Ok(value) = serde_json::from_str::<Value>(output) else {
        return Vec::new();
    };
    let mut processes = Vec::new();
    collect_rocm_process_objects(&value, &mut processes);
    processes
}

fn collect_rocm_process_objects(value: &Value, processes: &mut Vec<GpuProcess>) {
    match value {
        Value::Object(map) => {
            if let Some(process) = rocm_process_from_object(map) {
                processes.push(process);
            }
            for child in map.values() {
                collect_rocm_process_objects(child, processes);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_rocm_process_objects(child, processes);
            }
        }
        _ => {}
    }
}

fn rocm_process_from_object(map: &serde_json::Map<String, Value>) -> Option<GpuProcess> {
    let pid = first_json_string(map, &["pid", "PID", "process_id", "Process ID"])?;
    if pid.parse::<u32>().is_err() {
        return None;
    }
    let process_name = first_json_string(
        map,
        &[
            "process_name",
            "process name",
            "Process Name",
            "name",
            "command",
        ],
    )
    .unwrap_or_default();
    let memory = first_json_string(
        map,
        &[
            "used_gpu_memory",
            "gpu_memory_mb",
            "VRAM use",
            "vram_usage",
            "memory",
        ],
    )
    .and_then(|value| parse_memory_mb(&value))
    .unwrap_or(0);
    Some(GpuProcess {
        pid,
        process_name,
        used_memory_mb: memory,
        gpu_uuid: None,
    })
}

fn first_json_string(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match map.get(*key)? {
        Value::String(value) if !value.trim().is_empty() => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        parse_memory_mb, parse_nvidia_compute_apps, parse_nvidia_gpu_stats, parse_rocm_compute_apps,
    };

    #[test]
    fn parses_nvidia_compute_apps_with_gpu_uuid() {
        let output = "1234, /tmp/.cache/worker, 4096, GPU-abc\n";
        let processes = parse_nvidia_compute_apps(output);

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, "1234");
        assert_eq!(processes[0].process_name, "/tmp/.cache/worker");
        assert_eq!(processes[0].used_memory_mb, 4096);
        assert_eq!(processes[0].gpu_uuid.as_deref(), Some("GPU-abc"));
    }

    #[test]
    fn parses_nvidia_compute_apps_without_gpu_uuid() {
        let output = "5678, /usr/bin/python3, 8192 MiB\n";
        let processes = parse_nvidia_compute_apps(output);

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, "5678");
        assert_eq!(processes[0].process_name, "/usr/bin/python3");
        assert_eq!(processes[0].used_memory_mb, 8192);
        assert_eq!(processes[0].gpu_uuid, None);
    }

    #[test]
    fn skips_non_process_lines() {
        let output = "No running processes found\npid, process_name, used_gpu_memory\n";
        assert!(parse_nvidia_compute_apps(output).is_empty());
    }

    #[test]
    fn parses_numeric_memory_prefix() {
        assert_eq!(parse_memory_mb("2048 MiB"), Some(2048));
        assert_eq!(parse_memory_mb("[N/A]"), None);
    }

    #[test]
    fn parses_nvidia_gpu_utilization_and_power_stats() {
        let stats = parse_nvidia_gpu_stats("GPU-abc, 97, 211.5\nGPU-def, 12 %, [N/A]\n");

        assert_eq!(stats["GPU-abc"].utilization_percent, 97);
        assert_eq!(stats["GPU-abc"].power_watts, Some(211.5));
        assert_eq!(stats["GPU-def"].utilization_percent, 12);
        assert_eq!(stats["GPU-def"].power_watts, None);
    }

    #[test]
    fn parses_rocm_json_process_objects() {
        let output = r#"{
          "card0": {
            "processes": [
              {"pid": 4321, "process_name": "/tmp/.cache/worker", "VRAM use": "4096 MB"}
            ]
          }
        }"#;

        let processes = parse_rocm_compute_apps(output);

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, "4321");
        assert_eq!(processes[0].process_name, "/tmp/.cache/worker");
        assert_eq!(processes[0].used_memory_mb, 4096);
    }
}
