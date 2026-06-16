use sentinel_core::{NotificationLanguage, Severity};

pub struct MessageCatalog {
    pub heading: &'static str,
    pub severity: &'static str,
    pub host: &'static str,
    pub time: &'static str,
    pub category: &'static str,
    pub rule: &'static str,
    pub subject: &'static str,
    pub description: &'static str,
    pub evidence: &'static str,
    pub impact: &'static str,
    pub recommendations: &'static str,
    pub event_id: &'static str,
    pub dedup_key: &'static str,
}

pub fn catalog(language: NotificationLanguage) -> MessageCatalog {
    match language {
        NotificationLanguage::En => MessageCatalog {
            heading: "VPS Sentinel Alert",
            severity: "Severity",
            host: "Host",
            time: "Time",
            category: "Category",
            rule: "Rule",
            subject: "Subject",
            description: "Description",
            evidence: "Evidence",
            impact: "Impact",
            recommendations: "Recommendations",
            event_id: "Event ID",
            dedup_key: "Dedup Key",
        },
        NotificationLanguage::ZhCn => MessageCatalog {
            heading: "VPS Sentinel 告警",
            severity: "风险等级",
            host: "主机",
            time: "时间",
            category: "分类",
            rule: "规则",
            subject: "对象",
            description: "说明",
            evidence: "证据",
            impact: "影响",
            recommendations: "建议",
            event_id: "事件 ID",
            dedup_key: "去重 Key",
        },
    }
}

pub fn severity_label(severity: Severity, language: NotificationLanguage) -> &'static str {
    match language {
        NotificationLanguage::En => match severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        },
        NotificationLanguage::ZhCn => match severity {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "信息",
        },
    }
}
