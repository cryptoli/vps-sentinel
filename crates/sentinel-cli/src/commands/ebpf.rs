use anyhow::{Context, Result};
use clap::{ArgAction, Subcommand};
use sentinel_agent::runtime_probe::{
    bpftrace_script, default_output_path, default_script_path, output_path_is_bridge_configured,
    spawn_runtime_probe, RuntimeProbeLaunch, RuntimeProbeOptions,
};
use sentinel_core::SentinelConfig;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub enum EbpfCommand {
    /// Print or write the lightweight bpftrace runtime-probe script.
    Script {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, action = ArgAction::SetTrue)]
        capture_files: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        no_capture_files: bool,
    },
    /// Run bpftrace and append emitted JSONL events for the ebpf_bridge collector.
    Run {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        script_path: Option<PathBuf>,
        #[arg(long)]
        bpftrace: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        capture_files: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        no_capture_files: bool,
    },
    /// Show local runtime-probe readiness and paths.
    Doctor,
}

pub fn run_ebpf(config: SentinelConfig, command: EbpfCommand) -> Result<()> {
    match command {
        EbpfCommand::Script {
            output,
            capture_files,
            no_capture_files,
        } => {
            let options = probe_options(&config, capture_files, no_capture_files);
            let script = bpftrace_script(options);
            if let Some(path) = output {
                write_text(&path, &script)?;
                println!("script_written: {}", path.display());
            } else {
                print!("{script}");
            }
        }
        EbpfCommand::Run {
            output,
            script_path,
            bpftrace,
            capture_files,
            no_capture_files,
        } => {
            let options = probe_options(&config, capture_files, no_capture_files);
            let output_path = output.unwrap_or_else(|| default_output_path(&config));
            let script_path = script_path.unwrap_or_else(|| default_script_path(&config));
            let program = bpftrace.unwrap_or_else(|| {
                config
                    .advanced_collectors
                    .ebpf_runtime_probe_command
                    .clone()
            });
            if !output_path_is_bridge_configured(&config, &output_path) {
                eprintln!(
                    "warning: {} is not listed in advanced_collectors.ebpf_event_paths; the agent will not read it until config is updated",
                    output_path.display()
                );
            }
            eprintln!(
                "running eBPF runtime probe: command={} script={} output={}",
                program,
                script_path.display(),
                output_path.display()
            );
            spawn_runtime_probe(RuntimeProbeLaunch {
                program,
                output_path,
                script_path,
                options,
                reset_output: false,
            })?
            .wait()?;
        }
        EbpfCommand::Doctor => print_probe_doctor(&config),
    }
    Ok(())
}

fn probe_options(
    config: &SentinelConfig,
    capture_files: bool,
    no_capture_files: bool,
) -> RuntimeProbeOptions {
    let mut options = RuntimeProbeOptions::from_config(config);
    if capture_files {
        options.capture_file_activity = true;
    }
    if no_capture_files {
        options.capture_file_activity = false;
    }
    options
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    ensure_parent_dir(path)?;
    fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

fn print_probe_doctor(config: &SentinelConfig) {
    let output_path = default_output_path(config);
    println!(
        "ebpf_runtime_probe_enabled: {}",
        config.advanced_collectors.ebpf_runtime_probe_enabled
    );
    println!(
        "bpftrace_command: {}",
        config.advanced_collectors.ebpf_runtime_probe_command
    );
    println!("output_path: {}", output_path.display());
    println!(
        "output_path_configured_for_bridge: {}",
        output_path_is_bridge_configured(config, &output_path)
    );
    println!(
        "capture_files_default: {}",
        config.advanced_collectors.ebpf_runtime_probe_capture_files
    );
}
