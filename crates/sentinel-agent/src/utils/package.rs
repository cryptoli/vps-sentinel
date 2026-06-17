use std::collections::BTreeMap;

#[cfg(unix)]
use crate::utils::command::successful_stdout;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
const PACKAGE_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub struct PackageOwnerCache {
    owners: BTreeMap<String, Option<String>>,
}

impl PackageOwnerCache {
    pub fn owner_for_path(&mut self, path: &str) -> Option<String> {
        let normalized = normalized_package_path(path)?;
        if let Some(owner) = self.owners.get(normalized) {
            return owner.clone();
        }
        let owner = query_package_owner(normalized);
        self.owners.insert(normalized.to_string(), owner.clone());
        owner
    }
}

fn normalized_package_path(path: &str) -> Option<&str> {
    let normalized = path
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| path.trim());
    if normalized.is_empty() || !normalized.starts_with('/') {
        return None;
    }
    Some(normalized)
}

#[cfg(unix)]
fn query_package_owner(path: &str) -> Option<String> {
    for (program, args) in [
        ("dpkg-query", vec!["-S", path]),
        ("rpm", vec!["-qf", path]),
        ("pacman", vec!["-Qo", path]),
        ("apk", vec!["info", "-W", path]),
    ] {
        let Some(output) = successful_stdout(program, &args, PACKAGE_QUERY_TIMEOUT) else {
            continue;
        };
        let text = output.trim().to_string();
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
    use super::{normalized_package_path, PackageOwnerCache};

    #[test]
    fn ignores_non_absolute_or_anonymous_paths() {
        assert_eq!(normalized_package_path(""), None);
        assert_eq!(normalized_package_path("memfd:kworker (deleted)"), None);
        assert_eq!(normalized_package_path("relative/path"), None);
        assert_eq!(
            normalized_package_path("/usr/bin/bash (deleted)"),
            Some("/usr/bin/bash")
        );
    }

    #[test]
    fn cache_rejects_paths_that_cannot_have_package_owners() {
        let mut cache = PackageOwnerCache::default();
        assert_eq!(cache.owner_for_path("relative/path"), None);
    }
}
