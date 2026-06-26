use std::fs;

/// Best-effort process resident-set size in KiB.
///
/// Linux exposes the current RSS through `/proc/self/status`. Other platforms
/// return `None`; vps-sentinel is Linux-focused, but tests and development may
/// run elsewhere.
pub fn current_rss_kb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    parse_status_kb(&status, "VmRSS")
}

fn parse_status_kb(status: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key}:");
    status.lines().find_map(|line| {
        let value = line.strip_prefix(&prefix)?.trim();
        value
            .split_whitespace()
            .next()
            .and_then(|number| number.parse::<u64>().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::parse_status_kb;

    #[test]
    fn parses_linux_status_kb_field() {
        let status = "Name:\tvps-sentinel\nVmRSS:\t  17296 kB\n";
        assert_eq!(parse_status_kb(status, "VmRSS"), Some(17296));
    }
}
