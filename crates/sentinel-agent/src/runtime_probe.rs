use sentinel_core::{SentinelConfig, SentinelError, SentinelResult};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeProbeOptions {
    pub capture_exec: bool,
    pub capture_file_activity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeProbeLaunch {
    pub program: String,
    pub output_path: PathBuf,
    pub script_path: PathBuf,
    pub options: RuntimeProbeOptions,
    pub reset_output: bool,
}

pub struct RuntimeProbeHandle {
    launch: RuntimeProbeLaunch,
    child: Option<Child>,
    output_thread: Option<JoinHandle<SentinelResult<()>>>,
}

impl RuntimeProbeOptions {
    pub fn from_config(config: &SentinelConfig) -> Self {
        Self {
            capture_exec: true,
            capture_file_activity: config.advanced_collectors.ebpf_runtime_probe_capture_files,
        }
    }
}

impl RuntimeProbeLaunch {
    pub fn from_config(config: &SentinelConfig) -> Self {
        Self {
            program: config
                .advanced_collectors
                .ebpf_runtime_probe_command
                .clone(),
            output_path: default_output_path(config),
            script_path: default_script_path(config),
            options: RuntimeProbeOptions::from_config(config),
            reset_output: true,
        }
    }
}

impl RuntimeProbeHandle {
    pub fn launch(&self) -> &RuntimeProbeLaunch {
        &self.launch
    }

    pub fn is_running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                let _ = self.join_output_thread();
                false
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    pub fn wait(mut self) -> SentinelResult<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let status = child
            .wait()
            .map_err(|err| SentinelError::Command(format!("failed to wait for bpftrace: {err}")))?;
        self.join_output_thread()?;
        if !status.success() {
            return Err(SentinelError::Command(format!(
                "bpftrace exited with status {status}"
            )));
        }
        Ok(())
    }

    pub fn stop(&mut self) -> SentinelResult<()> {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(err) => {
                    return Err(SentinelError::Command(format!(
                        "failed to inspect bpftrace process: {err}"
                    )));
                }
            }
        }
        self.join_output_thread()
    }

    fn join_output_thread(&mut self) -> SentinelResult<()> {
        let Some(thread) = self.output_thread.take() else {
            return Ok(());
        };
        thread.join().unwrap_or_else(|_| {
            Err(SentinelError::Command(
                "bpftrace output writer thread panicked".to_string(),
            ))
        })
    }
}

impl Drop for RuntimeProbeHandle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn default_output_path(config: &SentinelConfig) -> PathBuf {
    config
        .advanced_collectors
        .ebpf_runtime_probe_output_path
        .clone()
}

pub fn default_script_path(config: &SentinelConfig) -> PathBuf {
    config.agent.data_dir.join("vps-sentinel-ebpf.bt")
}

pub fn bpftrace_script(options: RuntimeProbeOptions) -> String {
    let mut sections = vec![script_header()];
    if options.capture_exec {
        sections.push(exec_probe());
    }
    if options.capture_file_activity {
        sections.push(file_activity_probe());
    }
    sections.join("\n\n")
}

pub fn output_path_is_bridge_configured(config: &SentinelConfig, path: &Path) -> bool {
    config
        .advanced_collectors
        .ebpf_event_paths
        .iter()
        .any(|configured| configured == path)
}

pub fn spawn_configured_runtime_probe(
    config: &SentinelConfig,
) -> SentinelResult<Option<RuntimeProbeHandle>> {
    if !config.advanced_collectors.ebpf_runtime_probe_enabled {
        return Ok(None);
    }
    spawn_runtime_probe(RuntimeProbeLaunch::from_config(config)).map(Some)
}

pub fn spawn_runtime_probe(launch: RuntimeProbeLaunch) -> SentinelResult<RuntimeProbeHandle> {
    if launch.program.trim().is_empty() {
        return Err(SentinelError::Config(
            "advanced_collectors.ebpf_runtime_probe_command must not be empty".to_string(),
        ));
    }
    let script = bpftrace_script(launch.options);
    write_text(&launch.script_path, &script)?;
    ensure_parent_dir(&launch.output_path)?;
    let mut output_options = OpenOptions::new();
    output_options.create(true).write(true);
    if launch.reset_output {
        output_options.truncate(true);
    } else {
        output_options.append(true);
    }
    let output = output_options
        .open(&launch.output_path)
        .map_err(|err| SentinelError::io(&launch.output_path, err))?;
    let mut child = Command::new(&launch.program)
        .arg("-q")
        .arg(&launch.script_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| {
            SentinelError::Command(format!(
                "failed to start eBPF runtime probe command '{}': {err}",
                launch.program
            ))
        })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        SentinelError::Command("failed to capture eBPF runtime probe stdout".to_string())
    })?;
    let output_path = launch.output_path.clone();
    let output_thread = thread::spawn(move || copy_probe_output(stdout, output, output_path));
    Ok(RuntimeProbeHandle {
        launch,
        child: Some(child),
        output_thread: Some(output_thread),
    })
}

fn copy_probe_output(
    stdout: impl std::io::Read,
    mut output: fs::File,
    output_path: PathBuf,
) -> SentinelResult<()> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    while reader
        .read_line(&mut line)
        .map_err(|err| SentinelError::io(&output_path, err))?
        != 0
    {
        output
            .write_all(line.as_bytes())
            .map_err(|err| SentinelError::io(&output_path, err))?;
        output
            .flush()
            .map_err(|err| SentinelError::io(&output_path, err))?;
        line.clear();
    }
    Ok(())
}

fn write_text(path: &Path, text: &str) -> SentinelResult<()> {
    ensure_parent_dir(path)?;
    fs::write(path, text).map_err(|err| SentinelError::io(path, err))
}

fn ensure_parent_dir(path: &Path) -> SentinelResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| SentinelError::io(parent, err))?;
    }
    Ok(())
}

fn script_header() -> String {
    r#"/*
 * vps-sentinel lightweight eBPF runtime probe.
 *
 * This script is intentionally narrow: it emits short-lived exec events and,
 * when enabled, mutating file operations as JSON lines for the agent's
 * ebpf_bridge collector. Keep filtering here coarse and let the Rust detector
 * apply scoring, baselines, allowlists, and notification policy.
 */
BEGIN
{
    printf("{\"kind\":\"probe_start\",\"probe\":\"vps-sentinel-ebpf\",\"pid\":%d,\"comm\":\"%s\"}\n", pid, comm);
}"#
    .to_string()
}

fn exec_probe() -> String {
    r#"tracepoint:syscalls:sys_enter_execve
{
    printf("{\"kind\":\"process_exec\",\"pid\":%d,\"uid\":%d,\"comm\":\"%s\",\"exe\":\"%s\",\"cmdline\":\"%s\"}\n",
        pid, uid, comm, str(args->filename), str(args->filename));
}"#
    .to_string()
}

fn file_activity_probe() -> String {
    r#"tracepoint:syscalls:sys_enter_openat
/(args->flags & 1) || (args->flags & 64) || (args->flags & 512) || (args->flags & 1024)/
{
    printf("{\"kind\":\"file_write\",\"pid\":%d,\"uid\":%d,\"comm\":\"%s\",\"path\":\"%s\",\"flags\":%d}\n",
        pid, uid, comm, str(args->filename), args->flags);
}

tracepoint:syscalls:sys_enter_renameat
{
    printf("{\"kind\":\"file_rename\",\"pid\":%d,\"uid\":%d,\"comm\":\"%s\",\"path\":\"%s\",\"new_path\":\"%s\"}\n",
        pid, uid, comm, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_enter_renameat2
{
    printf("{\"kind\":\"file_rename\",\"pid\":%d,\"uid\":%d,\"comm\":\"%s\",\"path\":\"%s\",\"new_path\":\"%s\"}\n",
        pid, uid, comm, str(args->oldname), str(args->newname));
}

tracepoint:syscalls:sys_enter_unlinkat
{
    printf("{\"kind\":\"file_unlink\",\"pid\":%d,\"uid\":%d,\"comm\":\"%s\",\"path\":\"%s\"}\n",
        pid, uid, comm, str(args->pathname));
}"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{bpftrace_script, RuntimeProbeOptions};

    #[test]
    fn script_contains_exec_probe_by_default() {
        let script = bpftrace_script(RuntimeProbeOptions {
            capture_exec: true,
            capture_file_activity: false,
        });

        assert!(script.contains("sys_enter_execve"));
        assert!(script.contains("\\\"kind\\\":\\\"process_exec\\\""));
        assert!(!script.contains("sys_enter_openat"));
    }

    #[test]
    fn script_can_include_mutating_file_activity() {
        let script = bpftrace_script(RuntimeProbeOptions {
            capture_exec: true,
            capture_file_activity: true,
        });

        assert!(script.contains("sys_enter_openat"));
        assert!(script.contains("\\\"kind\\\":\\\"file_write\\\""));
        assert!(script.contains("sys_enter_unlinkat"));
    }
}
