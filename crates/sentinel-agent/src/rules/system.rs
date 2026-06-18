use super::model::RuleMetadata;
use sentinel_core::{Category, Severity};

pub const ACTIVE_RESPONSE_SUMMARY_RULE_ID: &str = "ACTIVE-001";

pub fn rules() -> Vec<RuleMetadata> {
    vec![RuleMetadata::new(
        ACTIVE_RESPONSE_SUMMARY_RULE_ID,
        "Multiple IPs blocked by active response",
        Category::System,
        Severity::High,
        "Active response blocked many source IPs in one scan window and summarized the details.",
    )]
}
