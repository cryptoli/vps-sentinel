use super::model::RuleMetadata;
use sentinel_core::{Category, Severity};

pub const ACTIVE_RESPONSE_SUMMARY_RULE_ID: &str = "ACTIVE-001";
pub const DAILY_REPORT_RULE_ID: &str = "REPORT-001";
pub const SERVICE_PROFILE_NEW_RULE_ID: &str = "SERVICE-001";
pub const SERVICE_PROFILE_DRIFT_RULE_ID: &str = "SERVICE-002";

pub fn rules() -> Vec<RuleMetadata> {
    vec![
        RuleMetadata::new(
            ACTIVE_RESPONSE_SUMMARY_RULE_ID,
            "Multiple IPs blocked by active response",
            Category::System,
            Severity::High,
            "Active response blocked many source IPs in one scan window and summarized the details.",
        ),
        RuleMetadata::new(
            DAILY_REPORT_RULE_ID,
            "VPS Sentinel daily report",
            Category::System,
            Severity::Info,
            "Daily security summary generated from local scan history and findings.",
        ),
        RuleMetadata::new(
            SERVICE_PROFILE_NEW_RULE_ID,
            "New service profile entry detected",
            Category::Network,
            Severity::Medium,
            "A listening service was not present in the previous service profile baseline.",
        ),
        RuleMetadata::new(
            SERVICE_PROFILE_DRIFT_RULE_ID,
            "Service executable drift detected",
            Category::Network,
            Severity::Medium,
            "A known listening service is now owned by a different executable or process identity.",
        ),
    ]
}
