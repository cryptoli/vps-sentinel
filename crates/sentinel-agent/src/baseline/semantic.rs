use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticProfile {
    pub kind: &'static str,
    pub hash: String,
    pub summary: String,
    pub features: Vec<String>,
}

pub fn profile_for_path(path: &str, text: &str) -> Option<SemanticProfile> {
    let normalized = path.replace('\\', "/");
    if normalized.ends_with("/authorized_keys") || normalized.ends_with("/authorized_keys2") {
        return authorized_keys_profile(text);
    }
    if is_systemd_unit(&normalized) {
        return command_lines_profile(
            "systemd_unit",
            text,
            &["ExecStart", "ExecStartPre", "ExecStartPost"],
        );
    }
    if is_cron_path(&normalized) {
        return cron_profile(text);
    }
    if normalized == "/etc/sudoers" || normalized.starts_with("/etc/sudoers.d/") {
        return sudoers_profile(text);
    }
    if normalized == "/etc/ssh/sshd_config" || normalized.starts_with("/etc/ssh/sshd_config.d/") {
        return sshd_config_profile(text);
    }
    if is_web_server_config(&normalized) {
        return web_server_config_profile(text);
    }
    if is_package_manager_config(&normalized) {
        return package_manager_config_profile(&normalized, text);
    }
    None
}

pub fn semantic_delta(
    previous_kind: &str,
    previous_hash: &str,
    previous_summary: &str,
    current_kind: &str,
    current_hash: &str,
    current_summary: &str,
) -> Option<String> {
    if previous_kind.is_empty() && current_kind.is_empty() {
        return None;
    }
    if previous_hash == current_hash && previous_summary == current_summary {
        return None;
    }
    let kind = if !current_kind.is_empty() {
        current_kind
    } else {
        previous_kind
    };
    Some(format!(
        "{kind}: {} -> {}",
        empty_as_missing(previous_summary),
        empty_as_missing(current_summary)
    ))
}

fn authorized_keys_profile(text: &str) -> Option<SemanticProfile> {
    let mut fingerprints = BTreeSet::new();
    let mut options = BTreeSet::new();
    let mut key_count = 0_usize;
    for line in semantic_lines(text) {
        let Some((option_text, key_type, key_body)) = split_authorized_key_line(&line) else {
            continue;
        };
        key_count += 1;
        let fingerprint = blake3::hash(format!("{key_type}:{key_body}").as_bytes())
            .to_hex()
            .to_string();
        fingerprints.insert(fingerprint[..16].to_string());
        for option in option_text
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            if let Some(name) = option
                .split('=')
                .next()
                .filter(|name| !name.trim().is_empty())
            {
                options.insert(name.to_ascii_lowercase());
            }
        }
    }
    if key_count == 0 {
        return None;
    }
    let features = options.iter().cloned().collect::<Vec<_>>();
    let summary = if features.is_empty() {
        format!("keys={key_count}")
    } else {
        format!("keys={key_count} options={}", features.join(","))
    };
    Some(profile(
        "authorized_keys",
        fingerprints.into_iter().collect::<Vec<_>>(),
        summary,
        features,
    ))
}

fn command_lines_profile(
    kind: &'static str,
    text: &str,
    prefixes: &[&str],
) -> Option<SemanticProfile> {
    let lines = semantic_lines(text)
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            prefixes
                .iter()
                .any(|prefix| key.trim().eq_ignore_ascii_case(prefix))
                .then(|| format!("{}={}", key.trim(), normalize_command_value(value)))
        })
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    let mut features = Vec::new();
    if lines
        .iter()
        .any(|line| line.contains("/tmp/") || line.contains("/dev/shm/"))
    {
        features.push("temporary_path".to_string());
    }
    if lines.iter().any(|line| contains_download_or_shell(line)) {
        features.push("network_or_shell_command".to_string());
    }
    Some(profile(
        kind,
        lines.clone(),
        format!("commands={}", lines.len()),
        features,
    ))
}

fn cron_profile(text: &str) -> Option<SemanticProfile> {
    let lines = semantic_lines(text)
        .map(|line| normalize_command_value(&line))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    let mut features = Vec::new();
    if lines.iter().any(|line| line.contains("@reboot")) {
        features.push("reboot_entry".to_string());
    }
    if lines.iter().any(|line| contains_download_or_shell(line)) {
        features.push("network_or_shell_command".to_string());
    }
    Some(profile(
        "cron",
        lines.clone(),
        format!("entries={}", lines.len()),
        features,
    ))
}

fn sudoers_profile(text: &str) -> Option<SemanticProfile> {
    let lines = semantic_lines(text)
        .map(|line| normalize_command_value(&line))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }
    let mut features = Vec::new();
    if lines
        .iter()
        .any(|line| line.to_ascii_uppercase().contains("NOPASSWD"))
    {
        features.push("nopasswd".to_string());
    }
    if lines.iter().any(|line| line.contains("ALL=(ALL")) {
        features.push("broad_privilege".to_string());
    }
    Some(profile(
        "sudoers",
        lines.clone(),
        format!("rules={}", lines.len()),
        features,
    ))
}

fn sshd_config_profile(text: &str) -> Option<SemanticProfile> {
    let directives = semantic_lines(text)
        .filter_map(|line| split_config_directive(&line))
        .map(|(key, value)| {
            format!(
                "{}={}",
                key.to_ascii_lowercase(),
                normalize_command_value(&value.to_ascii_lowercase())
            )
        })
        .collect::<Vec<_>>();
    if directives.is_empty() {
        return None;
    }
    let mut features = Vec::new();
    if directives
        .iter()
        .any(|line| line == "passwordauthentication=yes")
    {
        features.push("password_auth_enabled".to_string());
    }
    if directives.iter().any(|line| line == "permitrootlogin=yes") {
        features.push("root_login_enabled".to_string());
    }
    if directives
        .iter()
        .any(|line| line.starts_with("authorizedkeyscommand="))
    {
        features.push("authorized_keys_command".to_string());
    }
    Some(profile(
        "sshd_config",
        directives.clone(),
        format!("directives={}", directives.len()),
        features,
    ))
}

fn web_server_config_profile(text: &str) -> Option<SemanticProfile> {
    let directives = semantic_lines(text)
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("server_name")
                || lower.contains("listen")
                || lower.contains("proxy_pass")
                || lower.contains("root ")
                || lower.contains("try_files")
                || lower.contains("php")
                || lower.contains("fastcgi")
        })
        .map(|line| normalize_command_value(&line.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    if directives.is_empty() {
        return None;
    }
    let mut features = Vec::new();
    if directives
        .iter()
        .any(|line| line.contains("proxy_pass http://"))
    {
        features.push("plain_http_proxy".to_string());
    }
    if directives
        .iter()
        .any(|line| line.contains("fastcgi") || line.contains("php"))
    {
        features.push("dynamic_runtime".to_string());
    }
    Some(profile(
        "web_server_config",
        directives.clone(),
        format!("directives={}", directives.len()),
        features,
    ))
}

fn package_manager_config_profile(path: &str, text: &str) -> Option<SemanticProfile> {
    let entries = semantic_lines(text)
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("mirror")
                || lower.contains("repo")
                || lower.contains("baseurl")
                || lower.contains("signed-by")
                || lower.contains("trusted")
                || lower.starts_with("deb ")
        })
        .map(|line| normalize_command_value(&line.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return None;
    }
    let mut features = Vec::new();
    if entries.iter().any(|line| line.contains("trusted=yes")) {
        features.push("trusted_repo".to_string());
    }
    if entries.iter().any(|line| line.contains("http://")) {
        features.push("plain_http_repo".to_string());
    }
    Some(profile(
        if path.contains("/apt/") {
            "apt_source"
        } else if path.contains("/yum") || path.contains("/dnf") {
            "rpm_repo"
        } else {
            "package_manager_config"
        },
        entries.clone(),
        format!("entries={}", entries.len()),
        features,
    ))
}

fn profile(
    kind: &'static str,
    normalized_items: Vec<String>,
    summary: String,
    features: Vec<String>,
) -> SemanticProfile {
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    for item in normalized_items {
        hasher.update(item.as_bytes());
        hasher.update(b"\n");
    }
    SemanticProfile {
        kind,
        hash: hasher.finalize().to_hex().to_string(),
        summary,
        features,
    }
}

fn split_authorized_key_line(line: &str) -> Option<(&str, &str, &str)> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let key_index = parts.iter().position(|part| {
        part.starts_with("ssh-") || part.starts_with("ecdsa-") || part.starts_with("sk-")
    })?;
    let key_type = *parts.get(key_index)?;
    let key_body = *parts.get(key_index + 1)?;
    let option_text = if key_index == 0 { "" } else { parts[0] };
    Some((option_text, key_type, key_body))
}

fn semantic_lines(text: &str) -> impl Iterator<Item = String> + '_ {
    text.lines().filter_map(|line| {
        let trimmed = line.trim();
        (!trimmed.is_empty() && !trimmed.starts_with('#')).then(|| trimmed.to_string())
    })
}

fn split_config_directive(line: &str) -> Option<(String, String)> {
    if let Some((key, value)) = line.split_once('=') {
        return Some((key.trim().to_string(), value.trim().to_string()));
    }
    let mut parts = line.split_whitespace();
    let key = parts.next()?.trim().to_string();
    let value = parts.collect::<Vec<_>>().join(" ");
    (!key.is_empty() && !value.is_empty()).then_some((key, value))
}

fn normalize_command_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_download_or_shell(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("curl ")
        || lowered.contains("wget ")
        || lowered.contains("| sh")
        || lowered.contains("| bash")
        || lowered.contains("/bin/sh")
        || lowered.contains("/bin/bash")
}

fn is_systemd_unit(path: &str) -> bool {
    path.ends_with(".service")
        && (path.starts_with("/etc/systemd/system/")
            || path.starts_with("/lib/systemd/system/")
            || path.starts_with("/usr/lib/systemd/system/"))
}

fn is_cron_path(path: &str) -> bool {
    path == "/etc/crontab"
        || path.starts_with("/etc/cron.d/")
        || path.starts_with("/var/spool/cron/")
}

fn is_web_server_config(path: &str) -> bool {
    (path.starts_with("/etc/nginx/") && path.ends_with(".conf"))
        || path.starts_with("/etc/apache2/")
        || path.starts_with("/etc/httpd/")
        || path.starts_with("/etc/caddy/")
}

fn is_package_manager_config(path: &str) -> bool {
    path.starts_with("/etc/apt/sources.list")
        || path.starts_with("/etc/apt/sources.list.d/")
        || path.starts_with("/etc/yum.repos.d/")
        || path.starts_with("/etc/dnf/")
}

fn empty_as_missing(value: &str) -> &str {
    if value.trim().is_empty() {
        "missing"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{profile_for_path, semantic_delta};

    #[test]
    fn authorized_keys_profile_hashes_key_material_without_raw_key() {
        let profile = profile_for_path(
            "/root/.ssh/authorized_keys",
            "from=\"1.2.3.4\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user\n",
        )
        .expect("profile");

        assert_eq!(profile.kind, "authorized_keys");
        assert!(profile.summary.contains("keys=1"));
        assert!(profile.features.contains(&"from".to_string()));
        assert!(!profile.hash.contains("FakeKey"));
    }

    #[test]
    fn semantic_delta_summarizes_change() {
        let delta = semantic_delta(
            "authorized_keys",
            "old",
            "keys=1",
            "authorized_keys",
            "new",
            "keys=2 options=from",
        );

        assert_eq!(
            delta.as_deref(),
            Some("authorized_keys: keys=1 -> keys=2 options=from")
        );
    }

    #[test]
    fn sshd_config_profile_flags_risky_auth_directives() {
        let profile = profile_for_path(
            "/etc/ssh/sshd_config",
            "PasswordAuthentication yes\nPermitRootLogin yes\n",
        )
        .expect("profile");

        assert_eq!(profile.kind, "sshd_config");
        assert!(profile
            .features
            .contains(&"password_auth_enabled".to_string()));
        assert!(profile.features.contains(&"root_login_enabled".to_string()));
    }

    #[test]
    fn web_and_package_configs_have_semantic_profiles() {
        let nginx = profile_for_path(
            "/etc/nginx/conf.d/site.conf",
            "server { listen 80; proxy_pass http://127.0.0.1:8080; }\n",
        )
        .expect("nginx profile");
        let apt = profile_for_path(
            "/etc/apt/sources.list.d/custom.list",
            "deb [trusted=yes] http://example.invalid stable main\n",
        )
        .expect("apt profile");

        assert_eq!(nginx.kind, "web_server_config");
        assert!(nginx.features.contains(&"plain_http_proxy".to_string()));
        assert_eq!(apt.kind, "apt_source");
        assert!(apt.features.contains(&"trusted_repo".to_string()));
    }
}
