use glob::Pattern;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub(crate) struct PathMatcher {
    exact_or_prefix: Vec<String>,
    glob_patterns: Vec<CompiledPattern>,
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    pattern: Pattern,
    basename_only: bool,
}

impl PathMatcher {
    pub(crate) fn from_paths(paths: &[impl AsRef<Path>]) -> Self {
        Self::from_strings(paths.iter().map(|path| path.as_ref().to_string_lossy()))
    }

    pub(crate) fn from_strings<'a>(
        patterns: impl IntoIterator<Item = impl AsRef<str> + 'a>,
    ) -> Self {
        let mut exact_or_prefix = Vec::new();
        let mut glob_patterns = Vec::new();

        for raw in patterns {
            let normalized = normalize_path_pattern(raw.as_ref());
            if normalized.is_empty() {
                continue;
            }
            if has_glob_meta(&normalized) {
                if let Ok(pattern) = Pattern::new(&normalized) {
                    glob_patterns.push(CompiledPattern {
                        basename_only: !normalized.contains('/'),
                        pattern,
                    });
                }
            } else {
                exact_or_prefix.push(normalized.trim_end_matches('/').to_string());
            }
        }

        exact_or_prefix.sort();
        exact_or_prefix.dedup();
        Self {
            exact_or_prefix,
            glob_patterns,
        }
    }

    pub(crate) fn matches(&self, value: &str) -> bool {
        let normalized = normalize_observed_path(value);
        if normalized.is_empty() {
            return false;
        }
        self.exact_or_prefix
            .iter()
            .any(|allowed| normalized == *allowed || normalized.starts_with(&format!("{allowed}/")))
            || self.glob_patterns.iter().any(|compiled| {
                if compiled.basename_only {
                    compiled.pattern.matches(path_basename(&normalized))
                } else {
                    compiled.pattern.matches(&normalized)
                }
            })
    }
}

fn normalize_path_pattern(value: &str) -> String {
    value.trim().replace('\\', "/")
}

fn normalize_observed_path(value: &str) -> String {
    value.trim().replace('\\', "/")
}

fn has_glob_meta(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

fn path_basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::PathMatcher;
    use std::path::PathBuf;

    #[test]
    fn exact_and_directory_prefix_patterns_match_paths() {
        let matcher = PathMatcher::from_paths(&[
            PathBuf::from("/etc/ssh/sshd_config"),
            PathBuf::from("/opt/vendor"),
        ]);

        assert!(matcher.matches("/etc/ssh/sshd_config"));
        assert!(matcher.matches("/opt/vendor/bin/tool"));
        assert!(!matcher.matches("/opt/vendorized/bin/tool"));
    }

    #[test]
    fn glob_patterns_match_full_paths_and_basenames() {
        let matcher =
            PathMatcher::from_strings(["/etc/systemd/system/snap-*.mount", "snap-*.scope"]);

        assert!(matcher.matches("/etc/systemd/system/snap-core20-2890.mount"));
        assert!(matcher.matches("/run/systemd/snap-core20.scope"));
        assert!(!matcher.matches("/etc/systemd/system/not-snap.mount"));
    }
}
