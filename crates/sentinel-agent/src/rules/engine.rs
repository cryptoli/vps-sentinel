use crate::detectors::default_detectors;
use crate::rules::model::RuleMetadata;

/// Return metadata for all built-in MVP rules.
pub fn builtin_rules() -> Vec<RuleMetadata> {
    default_detectors()
        .into_iter()
        .flat_map(|detector| detector.rules())
        .collect()
}

/// Return one built-in rule by ID.
pub fn find_rule(rule_id: &str) -> Option<RuleMetadata> {
    builtin_rules()
        .into_iter()
        .find(|rule| rule.id.eq_ignore_ascii_case(rule_id))
}
