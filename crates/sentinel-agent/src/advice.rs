use crate::incident::Incident;
use sentinel_core::{Category, Finding, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advice {
    pub title: String,
    pub priority: Severity,
    pub steps: Vec<String>,
}

pub fn advice_for_finding(finding: &Finding) -> Advice {
    let mut steps = Vec::new();
    steps.push(format!(
        "Review the finding details: vs findings show {}",
        finding.id
    ));
    match finding.category {
        Category::Ssh => {
            steps.push("Check authentication history around the event window.".to_string());
            steps.push("Confirm whether the source IP later had a successful login.".to_string());
            steps.push("If unauthorized access is confirmed, rotate SSH credentials and review authorized_keys.".to_string());
        }
        Category::Web => {
            steps.push(
                "Review web access and error logs for the same source IP and URI family."
                    .to_string(),
            );
            steps.push(
                "Patch or disable the targeted web component if the probe matched a real route."
                    .to_string(),
            );
            steps.push("Use active response blocks only when repeated or exploit-grade evidence is present.".to_string());
        }
        Category::Process => {
            steps.push("Capture process metadata before killing it: pid, parent, executable hash, cwd, sockets, and cgroup.".to_string());
            steps.push(
                "Check executable package ownership and recent deployment or package-manager logs."
                    .to_string(),
            );
            steps.push(
                "If malicious, isolate the host from outbound traffic before removing persistence."
                    .to_string(),
            );
        }
        Category::Network => {
            steps.push("Confirm the owning process, service manager unit, and firewall exposure for the listener.".to_string());
            steps.push(
                "Refresh the service profile only after confirming the change is expected."
                    .to_string(),
            );
        }
        Category::FileIntegrity | Category::Persistence => {
            steps.push(
                "Compare the changed file with package-manager logs and administrator activity."
                    .to_string(),
            );
            steps.push(
                "Preserve the file and surrounding timestamps before reverting suspicious changes."
                    .to_string(),
            );
        }
        Category::Rootkit => {
            steps.push("Treat rootkit signals as high risk; collect volatile evidence and consider rebuilding the host.".to_string());
        }
        _ => {
            steps.push(
                "Review related findings and incidents before taking destructive action."
                    .to_string(),
            );
        }
    }
    if evidence_value(finding, "active_response_status").is_some() {
        steps.push("Review active response state: vs blocks list --no-verify".to_string());
    }
    if evidence_value(finding, "threat_intel_match").as_deref() == Some("true") {
        steps.push("Treat the matched indicator as supporting evidence and validate freshness before widening blocks.".to_string());
    }
    Advice {
        title: format!("Advice for {}", finding.rule_id),
        priority: finding.severity,
        steps,
    }
}

pub fn advice_for_incident(incident: &Incident) -> Advice {
    let mut steps = vec![
        format!("Review the incident timeline: vs incidents timeline {}", incident.id),
        "Start with the earliest event and verify whether later events share the same IP, process, or path.".to_string(),
        "Use finding-specific advice for the highest-severity finding in the incident.".to_string(),
    ];
    if incident.categories.iter().any(|category| category == "ssh") {
        steps.push("Check whether SSH failures were followed by a successful login.".to_string());
    }
    if incident
        .categories
        .iter()
        .any(|category| category == "process")
    {
        steps.push(
            "Preserve process and network evidence before terminating suspicious workloads."
                .to_string(),
        );
    }
    Advice {
        title: format!("Advice for incident {}", incident.id),
        priority: incident.severity,
        steps,
    }
}

fn evidence_value(finding: &Finding, key: &str) -> Option<String> {
    finding
        .evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.clone())
}

#[cfg(test)]
mod tests {
    use super::advice_for_finding;
    use sentinel_core::{Category, Finding, Severity};

    #[test]
    fn process_advice_includes_evidence_preservation() {
        let finding = Finding::new(
            "host",
            "process",
            "process",
            Severity::High,
            Category::Process,
            "PROC-006",
            "pid=1",
        );
        let advice = advice_for_finding(&finding);

        assert!(advice
            .steps
            .iter()
            .any(|step| step.contains("Capture process metadata")));
    }
}
