use crate::utils::fs::{path_string, resolve_under_root};
use glob::glob;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_CONFIG_DIR: &str = "/etc/ssh/sshd_config.d";
const DEFAULT_AUTHORIZED_KEYS: &[&str] = &[".ssh/authorized_keys", ".ssh/authorized_keys2"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDirective {
    pub key: String,
    pub value: String,
    pub in_match_block: bool,
}

/// Parse sshd_config directives, preserving whether an option was declared under Match.
pub fn parse_ssh_config_directives(content: &str) -> Vec<SshDirective> {
    let mut directives = Vec::new();
    let mut in_match_block = false;
    for line in content.lines() {
        let Some(trimmed) = strip_comment(line) else {
            continue;
        };
        let (key, value) = split_directive(trimmed);
        if key.is_empty() || value.is_empty() {
            continue;
        }
        if key.eq_ignore_ascii_case("Match") {
            in_match_block = true;
        }
        directives.push(SshDirective {
            key: key.to_string(),
            value: value.to_string(),
            in_match_block,
        });
    }
    directives
}

pub fn discover_authorized_key_patterns(scan_root: &Path) -> Vec<PathBuf> {
    let mut config_files = BTreeSet::new();
    collect_config_files(scan_root, Path::new(SSHD_CONFIG), &mut config_files);
    collect_config_files(scan_root, Path::new(SSHD_CONFIG_DIR), &mut config_files);

    let mut directives = Vec::new();
    for path in config_files {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let parsed = parse_ssh_config_directives(&content);
        collect_include_files(scan_root, &path, &parsed, &mut directives);
        directives.extend(parsed);
    }
    authorized_key_patterns_from_directives(&directives)
}

pub fn authorized_key_patterns_from_directives(directives: &[SshDirective]) -> Vec<PathBuf> {
    let mut values = directives
        .iter()
        .filter(|directive| directive.key.eq_ignore_ascii_case("AuthorizedKeysFile"))
        .flat_map(|directive| directive.value.split_whitespace())
        .collect::<Vec<_>>();
    if values.is_empty() {
        values.extend(DEFAULT_AUTHORIZED_KEYS.iter().copied());
    }

    let mut patterns = BTreeSet::new();
    for value in values {
        for pattern in expand_authorized_key_value(value) {
            patterns.insert(path_string(&pattern));
        }
    }
    patterns.into_iter().map(PathBuf::from).collect()
}

fn collect_config_files(scan_root: &Path, system_path: &Path, files: &mut BTreeSet<PathBuf>) {
    let resolved = resolve_under_root(scan_root, system_path);
    if resolved.is_file() {
        files.insert(resolved);
        return;
    }
    if !resolved.is_dir() {
        return;
    }
    let pattern = resolved.join("*.conf");
    let pattern = path_string(&pattern);
    if let Ok(paths) = glob(&pattern) {
        for path in paths.filter_map(Result::ok).filter(|path| path.is_file()) {
            files.insert(path);
        }
    }
}

fn collect_include_files(
    scan_root: &Path,
    source_file: &Path,
    directives: &[SshDirective],
    collected_directives: &mut Vec<SshDirective>,
) {
    for directive in directives
        .iter()
        .filter(|directive| directive.key.eq_ignore_ascii_case("Include"))
    {
        for pattern in directive.value.split_whitespace() {
            let resolved_pattern = resolve_include_pattern(scan_root, source_file, pattern);
            if let Ok(paths) = glob(&path_string(&resolved_pattern)) {
                for path in paths.filter_map(Result::ok).filter(|path| path.is_file()) {
                    if let Ok(content) = fs::read_to_string(path) {
                        collected_directives.extend(parse_ssh_config_directives(&content));
                    }
                }
            }
        }
    }
}

fn resolve_include_pattern(scan_root: &Path, source_file: &Path, pattern: &str) -> PathBuf {
    let include = Path::new(pattern);
    if include.is_absolute() {
        return resolve_under_root(scan_root, include);
    }
    let base = source_file.parent().unwrap_or_else(|| {
        Path::new(SSHD_CONFIG)
            .parent()
            .unwrap_or(Path::new("/etc/ssh"))
    });
    base.join(include)
}

fn expand_authorized_key_value(value: &str) -> Vec<PathBuf> {
    let normalized = value
        .replace("%u", "*")
        .replace("%U", "*")
        .replace('\\', "/");
    if normalized.contains("%h") {
        return expand_home_token(&normalized)
            .into_iter()
            .map(PathBuf::from)
            .collect();
    }
    if normalized.starts_with('/') {
        return expand_home_token(&normalized)
            .into_iter()
            .map(PathBuf::from)
            .collect();
    }
    expand_home_token(&normalized)
        .into_iter()
        .flat_map(|relative| [format!("/root/{relative}"), format!("/home/*/{relative}")])
        .map(PathBuf::from)
        .collect()
}

fn expand_home_token(value: &str) -> Vec<String> {
    if value.contains("%h") {
        vec![value.replace("%h", "/root"), value.replace("%h", "/home/*")]
    } else {
        vec![value.to_string()]
    }
}

fn strip_comment(line: &str) -> Option<&str> {
    let mut in_quote = false;
    for (index, ch) in line.char_indices() {
        if ch == '"' {
            in_quote = !in_quote;
        }
        if ch == '#' && !in_quote {
            let trimmed = line[..index].trim();
            return (!trimmed.is_empty()).then_some(trimmed);
        }
    }
    let trimmed = line.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn split_directive(line: &str) -> (&str, &str) {
    if let Some((key, value)) = line.split_once('=') {
        return (key.trim(), trim_quotes(value.trim()));
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let key = parts.next().unwrap_or("").trim();
    let value = parts.next().unwrap_or("").trim();
    (key, trim_quotes(value))
}

fn trim_quotes(value: &str) -> &str {
    value.trim_matches('"')
}

#[cfg(test)]
mod tests {
    use super::{
        authorized_key_patterns_from_directives, discover_authorized_key_patterns,
        parse_ssh_config_directives,
    };
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn parses_comments_equals_and_match_context() {
        let parsed = parse_ssh_config_directives(
            r#"
            PasswordAuthentication=yes # inline comment
            AuthorizedKeysFile ".ssh/authorized_keys custom/%u.keys"
            Match User backup
              PasswordAuthentication no
            "#,
        );

        assert_eq!(parsed[0].key, "PasswordAuthentication");
        assert_eq!(parsed[0].value, "yes");
        assert!(!parsed[0].in_match_block);
        assert_eq!(parsed[1].key, "AuthorizedKeysFile");
        assert!(parsed[2].in_match_block);
        assert!(parsed[3].in_match_block);
    }

    #[test]
    fn expands_authorized_keys_paths_for_root_and_home_users() {
        let directives = parse_ssh_config_directives(
            "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u %h/custom.keys",
        );
        let patterns = authorized_key_patterns_from_directives(&directives);

        assert!(patterns.contains(&PathBuf::from("/root/.ssh/authorized_keys")));
        assert!(patterns.contains(&PathBuf::from("/home/*/.ssh/authorized_keys")));
        assert!(patterns.contains(&PathBuf::from("/etc/ssh/keys/*")));
        assert!(patterns.contains(&PathBuf::from("/root/custom.keys")));
        assert!(patterns.contains(&PathBuf::from("/home/*/custom.keys")));
    }

    #[test]
    fn discovers_include_files_under_scan_root() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let etc_ssh = temp.path().join("etc/ssh");
        fs::create_dir_all(etc_ssh.join("sshd_config.d"))?;
        fs::write(
            etc_ssh.join("sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        )?;
        fs::write(
            etc_ssh.join("sshd_config.d/custom.conf"),
            "AuthorizedKeysFile .ssh/authorized_keys custom/%u.keys\n",
        )?;

        let patterns = discover_authorized_key_patterns(temp.path());

        assert!(patterns.contains(&PathBuf::from("/home/*/custom/*.keys")));
        Ok(())
    }
}
