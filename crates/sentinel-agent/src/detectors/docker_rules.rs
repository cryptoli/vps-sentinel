use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct DockerDetector;

impl Detector for DockerDetector {
    fn name(&self) -> &'static str {
        "docker_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![RuleMetadata::new(
            "DOCKER-001",
            "Docker socket present",
            Category::Docker,
            Severity::Info,
            "Docker is installed; deeper container checks are planned for v0.2.",
        )]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        events
            .iter()
            .filter(|event| event.kind == "docker_socket")
            .map(|event| {
                Finding::new(
                    &ctx.host_id,
                    "Docker socket present",
                    "Docker socket was found. This is informational in v0.1; container risk inspection is documented for v0.2.",
                    Severity::Info,
                    Category::Docker,
                    "DOCKER-001",
                    string_field(event, "path"),
                )
                .with_evidence(vec![
                    evidence("path", string_field(event, "path")),
                    evidence("exists", string_field(event, "exists")),
                ])
                .with_recommendations(vec![
                    "Review containers for privileged mode, host networking, and docker.sock mounts.".to_string(),
                ])
            })
            .collect()
    }
}
