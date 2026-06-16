use sentinel_core::{Category, Severity};

/// Static metadata for one built-in detection rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub default_severity: Severity,
    pub description: &'static str,
}

impl RuleMetadata {
    pub fn new(
        id: &'static str,
        title: &'static str,
        category: Category,
        default_severity: Severity,
        description: &'static str,
    ) -> Self {
        Self {
            id,
            title,
            category,
            default_severity,
            description,
        }
    }
}
