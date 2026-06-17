use sentinel_core::{NotificationLanguage, Severity};

pub struct MessageCatalog {
    pub heading: &'static str,
    pub vps: &'static str,
    pub severity: &'static str,
    pub host_id: &'static str,
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
    pub technical_details: &'static str,
}

pub fn catalog(language: NotificationLanguage) -> MessageCatalog {
    match language {
        NotificationLanguage::En => MessageCatalog {
            heading: "VPS Sentinel Alert",
            vps: "VPS",
            severity: "Severity",
            host_id: "Host ID",
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
            technical_details: "Technical Details",
        },
        NotificationLanguage::ZhCn => MessageCatalog {
            heading: "VPS Sentinel 告警",
            vps: "VPS 名称",
            severity: "风险等级",
            host_id: "主机 ID",
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
            technical_details: "技术详情",
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

pub fn evidence_label(key: &str, language: NotificationLanguage) -> String {
    let text = match language {
        NotificationLanguage::En => match key {
            "local_addr" => "local address",
            "local_port" => "local port",
            "port" => "port",
            "process_name" => "process",
            "previous_process_name" => "previous process",
            "previous_executable" => "previous executable",
            "source_ip" | "ip" => "source IP",
            "cmdline" => "command line",
            "cwd" => "working directory",
            "euid" => "effective UID",
            "exe_path" | "executable" => "executable",
            "package_activity_recent" => "recent package activity",
            "package_activity_sources" => "package logs",
            "risk_score" => "risk score",
            "risk_reasons" => "risk reasons",
            "risk_features" => "risk features",
            "socket_fd_count" => "socket FDs",
            "signals" => "signals",
            other => other,
        },
        NotificationLanguage::ZhCn => match key {
            "protocol" => "协议",
            "local_addr" => "监听地址",
            "local_port" => "监听端口",
            "port" => "端口",
            "process_name" => "进程",
            "previous_process_name" => "原进程",
            "previous_executable" => "原可执行文件",
            "pid" => "进程 ID",
            "source_ip" | "ip" => "来源 IP",
            "cmdline" => "命令行",
            "cwd" => "工作目录",
            "euid" => "有效 UID",
            "exe_path" | "executable" => "可执行文件",
            "package_activity_recent" => "近期软件包活动",
            "package_activity_sources" => "软件包日志",
            "risk_score" => "风险评分",
            "risk_reasons" => "风险原因",
            "risk_features" => "风险特征",
            "socket_fd_count" => "Socket FD 数",
            "signals" => "关联信号",
            "path" => "路径",
            "user" => "用户",
            "method" => "认证方式",
            "status" => "状态码",
            "log_source" => "日志来源",
            "failure_count" => "失败次数",
            other => other,
        },
    };
    text.to_string()
}
