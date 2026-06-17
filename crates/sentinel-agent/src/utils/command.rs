use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status_success: bool,
    pub stdout: String,
}

pub fn command_output(program: &str, args: &[&str], timeout: Duration) -> Option<CommandOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take();
    let reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut stdout) = stdout {
            let _ = stdout.read_to_end(&mut buffer);
        }
        String::from_utf8_lossy(&buffer).to_string()
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = reader.join().unwrap_or_default();
                return Some(CommandOutput {
                    status_success: status.success(),
                    stdout,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
        }
    }
}

pub fn successful_stdout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    command_output(program, args, timeout)
        .filter(|output| output.status_success)
        .map(|output| output.stdout)
}

#[cfg(test)]
mod tests {
    use super::successful_stdout;
    use std::time::Duration;

    #[test]
    fn missing_command_returns_none() {
        assert!(successful_stdout(
            "vps-sentinel-command-that-does-not-exist",
            &[],
            Duration::from_millis(50),
        )
        .is_none());
    }
}
