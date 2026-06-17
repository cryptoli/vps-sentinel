use crate::collectors::{CollectContext, Collector};
use crate::utils::command::successful_stdout;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::time::Duration;

const NVIDIA_SMI_FORMAT: &str = "--format=csv,noheader,nounits";
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
        let program = ctx.config.gpu.nvidia_smi_path.trim();
        if program.is_empty() {
            return Ok(Vec::new());
        }
        let timeout = Duration::from_secs(ctx.config.gpu.command_timeout_seconds);
        Ok(collect_nvidia_compute_processes(program, timeout))
    }
}

fn collect_nvidia_compute_processes(program: &str, timeout: Duration) -> Vec<RawEvent> {
    NVIDIA_SMI_QUERIES
        .iter()
        .find_map(|query| successful_stdout(program, &[*query, NVIDIA_SMI_FORMAT], timeout))
        .map(|output| {
            parse_nvidia_compute_apps(&output)
                .into_iter()
                .map(|process| {
                    let mut event = RawEvent::new("gpu", "gpu_compute_process")
                        .with_field("pid", process.pid)
                        .with_field("gpu_process_name", process.process_name)
                        .with_field("gpu_memory_mb", process.used_memory_mb.to_string());
                    if let Some(uuid) = process.gpu_uuid {
                        event = event.with_field("gpu_uuid", uuid);
                    }
                    event
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

fn parse_memory_mb(value: &str) -> Option<u64> {
    let digits = value
        .chars()
        .skip_while(|ch| !ch.is_ascii_digit())
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_memory_mb, parse_nvidia_compute_apps};

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
}
