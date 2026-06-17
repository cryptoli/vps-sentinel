use std::collections::BTreeSet;

/// Stable risk-scoring container shared by detectors that use feature-based scoring.
#[derive(Debug, Clone, Default)]
pub(crate) struct RiskAssessment {
    pub(crate) score: u16,
    reasons: BTreeSet<String>,
    features: BTreeSet<String>,
}

impl RiskAssessment {
    pub(crate) fn is_suspicious(&self, min_score: u16) -> bool {
        self.score >= min_score
    }

    pub(crate) fn add_signal(
        &mut self,
        score: u16,
        feature: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.score = self.score.max(score);
        self.features.insert(feature.into());
        self.reasons.insert(reason.into());
    }

    pub(crate) fn add_feature(&mut self, feature: impl Into<String>) {
        self.features.insert(feature.into());
    }

    pub(crate) fn merge_max(&mut self, other: Self) {
        self.score = self.score.max(other.score);
        self.reasons.extend(other.reasons);
        self.features.extend(other.features);
    }

    pub(crate) fn reason_text(&self) -> String {
        self.reasons.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    pub(crate) fn feature_names(&self) -> String {
        self.features.iter().cloned().collect::<Vec<_>>().join(", ")
    }

    pub(crate) fn has_feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }
}

#[cfg(test)]
mod tests {
    use super::RiskAssessment;

    #[test]
    fn merges_signals_with_stable_feature_and_reason_order() {
        let mut assessment = RiskAssessment::default();
        assessment.add_signal(80, "temporary_path", "temporary executable path");
        assessment.add_signal(90, "network_execution_bridge", "network shell bridge");

        assert_eq!(assessment.score, 90);
        assert_eq!(
            assessment.feature_names(),
            "network_execution_bridge, temporary_path"
        );
        assert_eq!(
            assessment.reason_text(),
            "network shell bridge; temporary executable path"
        );
    }

    #[test]
    fn merge_max_keeps_highest_score_and_unions_context() {
        let mut left = RiskAssessment::default();
        left.add_signal(45, "shell_wrapper", "plain shell wrapper");
        let mut right = RiskAssessment::default();
        right.add_signal(85, "download_to_shell", "downloaded payload piped to shell");

        left.merge_max(right);

        assert_eq!(left.score, 85);
        assert!(left.has_feature("shell_wrapper"));
        assert!(left.has_feature("download_to_shell"));
    }
}
