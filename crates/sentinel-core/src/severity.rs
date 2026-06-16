use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Risk level used by all findings and notifier routing rules.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Returns true when this severity should pass a minimum-severity filter.
    pub fn meets(self, minimum: Severity) -> bool {
        self >= minimum
    }
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        f.write_str(text)
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown severity '{other}'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn severity_ordering_supports_minimum_filters() {
        assert!(Severity::Critical.meets(Severity::High));
        assert!(Severity::High.meets(Severity::High));
        assert!(!Severity::Medium.meets(Severity::High));
    }

    #[test]
    fn severity_uses_pascal_case_serialization() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = serde_json::to_string(&Severity::High)?;
        assert_eq!(encoded, "\"High\"");
        let decoded: Severity = serde_json::from_str("\"Critical\"")?;
        assert_eq!(decoded, Severity::Critical);
        Ok(())
    }
}
