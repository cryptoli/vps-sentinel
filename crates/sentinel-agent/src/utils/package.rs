pub fn package_owner_for_path(path: &str) -> Option<String> {
    let normalized = path
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| path.trim());
    if normalized.is_empty() || !normalized.starts_with('/') {
        return None;
    }
    query_package_owner(normalized)
}

#[cfg(unix)]
fn query_package_owner(path: &str) -> Option<String> {
    for (program, args) in [
        ("dpkg-query", vec!["-S", path]),
        ("rpm", vec!["-qf", path]),
        ("pacman", vec!["-Qo", path]),
        ("apk", vec!["info", "-W", path]),
    ] {
        let Ok(output) = std::process::Command::new(program).args(args).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !text.is_empty() {
            return Some(format!("{program}: {text}"));
        }
    }
    None
}

#[cfg(not(unix))]
fn query_package_owner(_path: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::package_owner_for_path;

    #[test]
    fn ignores_non_absolute_or_anonymous_paths() {
        assert_eq!(package_owner_for_path(""), None);
        assert_eq!(package_owner_for_path("memfd:kworker (deleted)"), None);
        assert_eq!(package_owner_for_path("relative/path"), None);
    }
}
