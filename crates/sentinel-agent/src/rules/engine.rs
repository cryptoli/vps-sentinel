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

#[cfg(test)]
mod tests {
    use super::{builtin_rules, find_rule};
    use std::collections::BTreeSet;

    #[test]
    fn builtin_rule_ids_are_unique_and_normalized() {
        let rules = builtin_rules();
        let mut seen = BTreeSet::new();
        for rule in &rules {
            assert!(
                seen.insert(rule.id),
                "duplicate built-in rule id: {}",
                rule.id
            );
            assert!(
                is_normalized_rule_id(rule.id),
                "rule id should look like PREFIX-000: {}",
                rule.id
            );
            assert!(!rule.title.trim().is_empty());
            assert!(!rule.description.trim().is_empty());
        }
        assert!(!rules.is_empty());
    }

    #[test]
    fn find_rule_is_case_insensitive() {
        assert_eq!(find_rule("ssh-005").map(|rule| rule.id), Some("SSH-005"));
    }

    fn is_normalized_rule_id(rule_id: &str) -> bool {
        let Some((prefix, number)) = rule_id.split_once('-') else {
            return false;
        };
        !prefix.is_empty()
            && prefix.chars().all(|ch| ch.is_ascii_uppercase())
            && number.len() == 3
            && number.chars().all(|ch| ch.is_ascii_digit())
    }
}
