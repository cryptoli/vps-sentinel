use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct RootkitDetector;

impl Detector for RootkitDetector {
    fn name(&self) -> &'static str {
        "rootkit_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![RuleMetadata::new(
            "ROOTKIT-003",
            "Suspicious ld preload",
            Category::Rootkit,
            Severity::High,
            "ld.so.preload contains active entries. This is a rootkit signal, not proof by itself.",
        )]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        events
            .iter()
            .filter(|event| event.kind == "ld_preload_present")
            .filter(|event| event.field("entries").map(|value| !value.is_empty()).unwrap_or(false))
            .map(|event| {
                Finding::new(
                    &ctx.host_id,
                    "Rootkit signal: ld.so.preload has active entries",
                    "ld.so.preload can be abused to inject shared libraries into processes. This finding is a rootkit signal, not a definitive conclusion.",
                    Severity::High,
                    Category::Rootkit,
                    "ROOTKIT-003",
                    string_field(event, "path"),
                )
                .with_evidence(vec![
                    evidence("path", string_field(event, "path")),
                    evidence("entries", string_field(event, "entries")),
                ])
                .with_recommendations(vec![
                    "Verify every library path listed in ld.so.preload.".to_string(),
                    "Compare affected binaries and package integrity from trusted media if compromise is suspected.".to_string(),
                ])
            })
            .collect()
    }
}
