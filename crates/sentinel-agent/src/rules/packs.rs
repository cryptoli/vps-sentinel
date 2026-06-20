use crate::rules::engine::builtin_rules;
use serde::Serialize;
use std::collections::BTreeMap;

const BUILTIN_PACK_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RulePackSummary {
    pub id: String,
    pub title: String,
    pub version: String,
    pub source: String,
    pub rule_count: usize,
    pub owners: Vec<RulePackOwnerSummary>,
    pub capabilities: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RulePackOwnerSummary {
    pub owner: String,
    pub rule_count: usize,
    pub rules: Vec<&'static str>,
}

pub fn builtin_rule_pack() -> RulePackSummary {
    let mut by_owner = BTreeMap::<String, Vec<&'static str>>::new();
    for rule in builtin_rules() {
        by_owner.entry(rule.owner.to_string()).or_default().push(rule.id);
    }
    let owners = by_owner
        .into_iter()
        .map(|(owner, mut rules)| {
            rules.sort_unstable();
            RulePackOwnerSummary {
                owner,
                rule_count: rules.len(),
                rules,
            }
        })
        .collect::<Vec<_>>();
    let rule_count = owners.iter().map(|owner| owner.rule_count).sum();
    RulePackSummary {
        id: "builtin-linux-vps".to_string(),
        title: "Built-in Linux VPS defensive signal rules".to_string(),
        version: BUILTIN_PACK_VERSION.to_string(),
        source: "compiled".to_string(),
        rule_count,
        owners,
        capabilities: vec![
            "collector_detector_registry",
            "rule_owner_matrix",
            "external_sigma_like_toml",
            "optional_yara_cli",
        ],
    }
}

pub fn list_rule_packs() -> Vec<RulePackSummary> {
    vec![builtin_rule_pack()]
}

#[cfg(test)]
mod tests {
    use super::builtin_rule_pack;

    #[test]
    fn builtin_pack_groups_rules_by_owner() {
        let pack = builtin_rule_pack();

        assert!(pack.rule_count > 0);
        assert!(pack.owners.iter().any(|owner| owner.owner == "ssh"));
        assert!(pack
            .owners
            .iter()
            .any(|owner| owner.rules.contains(&"WEB-001")));
    }
}
