use sentinel_core::{Finding, NotificationLanguage};

pub struct LocalizedFinding {
    pub title: String,
    pub description: String,
    pub impact: Vec<String>,
    pub recommendations: Vec<String>,
}

pub fn localized_finding(finding: &Finding, language: NotificationLanguage) -> LocalizedFinding {
    match language {
        NotificationLanguage::En => from_finding(finding),
        NotificationLanguage::ZhCn => zh_rule(finding).unwrap_or_else(|| from_finding(finding)),
    }
}

fn from_finding(finding: &Finding) -> LocalizedFinding {
    LocalizedFinding {
        title: finding.title.clone(),
        description: finding.description.clone(),
        impact: finding.impact.clone(),
        recommendations: finding.recommendations.clone(),
    }
}

fn zh_rule(finding: &Finding) -> Option<LocalizedFinding> {
    let message = match finding.rule_id.as_str() {
        "SYSTEM-TEST" => RuleMessage {
            title: "VPS Sentinel 测试通知",
            description: "这是一条用于验证通知渠道是否可达的测试消息。",
            impact: &[],
            recommendations: &["如果你收到了这条消息，说明该通知渠道可以正常送达。"],
        },
        "SSH-001" => RuleMessage {
            title: "检测到 root SSH 登录",
            description: "root 账号刚刚通过 SSH 成功认证。",
            impact: &["直接使用 root 登录会降低操作可追溯性，并扩大误操作或入侵后的影响范围。"],
            recommendations: &[
                "确认登录来源和时间是否符合预期。",
                "如果不需要直接 root 登录，请关闭 PermitRootLogin。",
                "如果该登录不符合预期，请轮换相关凭据。",
            ],
        },
        "SSH-002" => RuleMessage {
            title: "检测到 SSH 密码登录",
            description: "一次成功的 SSH 登录使用了密码认证。",
            impact: &["密码登录更容易受到撞库、弱口令和暴力破解影响。"],
            recommendations: &[
                "确认该登录是否符合预期。",
                "条件允许时优先使用密钥登录，并关闭 SSH 密码登录。",
            ],
        },
        "SSH-003" => RuleMessage {
            title: "检测到 SSH 暴力尝试",
            description: "同一个来源 IP 在扫描窗口内产生了大量 SSH 登录失败记录。",
            impact: &["连续失败可能表示正在进行 SSH 密码猜测。"],
            recommendations: &[
                "检查 SSH 暴露面、fail2ban 或防火墙限速策略。",
                "确认同一来源是否随后出现成功登录。",
            ],
        },
        "SSH-005" => RuleMessage {
            title: "SSH authorized_keys 发生变化",
            description: "authorized_keys 文件相对基线发生创建、修改或删除。",
            impact: &["未知 SSH 公钥可能提供持久远程访问能力。"],
            recommendations: &[
                "确认密钥所有者和指纹后再信任该变更。",
                "发现未知密钥时先保留证据，再移除并轮换凭据。",
            ],
        },
        "USER-001" => RuleMessage {
            title: "检测到新增本地用户",
            description: "本地用户账号相对基线新增。",
            impact: &[],
            recommendations: &[
                "确认该账号是否由管理员或自动化流程创建。",
                "检查该用户的 shell、home 目录和近期登录记录。",
            ],
        },
        "USER-002" => RuleMessage {
            title: "检测到 UID 0 用户",
            description: "非 root 账号拥有 UID 0，或账号被修改为 UID 0。",
            impact: &["UID 0 等同 root 权限，是常见的持久化和提权手法。"],
            recommendations: &[
                "从可信会话核对 /etc/passwd。",
                "保留证据后禁用未知 UID 0 账号。",
            ],
        },
        "USER-003" => RuleMessage {
            title: "本地用户账号发生变化",
            description: "本地用户账号相对基线发生了可能影响权限的变化。",
            impact: &[],
            recommendations: &["查看账号差异，并和计划内运维操作进行关联。"],
        },
        "PROC-001" => RuleMessage {
            title: "进程从临时目录运行",
            description: "运行中的进程可执行文件位于常被恶意程序用于落地的临时目录。",
            impact: &[],
            recommendations: &[
                "检查可执行文件哈希、父进程和文件属主。",
                "停止或删除进程前先保留证据。",
            ],
        },
        "PROC-002" => RuleMessage {
            title: "已删除的可执行文件仍在运行",
            description: "进程的可执行文件看起来已被删除，但进程仍在运行。",
            impact: &[],
            recommendations: &[
                "终止前先采集进程详情和网络连接。",
                "回溯该进程是如何启动的。",
            ],
        },
        "PROC-003" => RuleMessage {
            title: "检测到网络命令执行桥接",
            description: "进程命令行同时具备网络通道以及 shell、system 或文件描述符桥接执行特征。",
            impact: &["如果该进程不符合预期，这可能表示存在远程命令执行或交互式入侵活动。"],
            recommendations: &[
                "如果未经授权，请隔离网络访问。",
                "保留命令行、可执行文件和父进程证据。",
            ],
        },
        "PROC-004" => RuleMessage {
            title: "疑似挖矿或扫描进程",
            description: "进程命令行包含常见挖矿或扫描器特征。",
            impact: &[],
            recommendations: &[
                "检查 CPU、网络用量以及该二进制是否由你安装。",
                "确认入侵后轮换相关凭据。",
            ],
        },
        "NET-001" => RuleMessage {
            title: "检测到新增公网监听端口",
            description: "一个公网监听端口相对已保存基线新增。",
            impact: &[],
            recommendations: &[
                "确认该服务是否应当暴露到公网。",
                "计划内变更确认后刷新基线。",
                "不需要公网访问时使用防火墙或绑定本地/VPN 地址。",
            ],
        },
        "NET-002" => RuleMessage {
            title: "公网监听端口的进程发生变化",
            description: "端口仍在监听，但背后的进程与基线记录不一致。",
            impact: &[],
            recommendations: &[
                "确认服务替换是否为计划内变更。",
                "检查当前可执行文件路径和 systemd unit。",
                "计划内变更确认后刷新基线。",
            ],
        },
        "NET-003" => RuleMessage {
            title: "公网监听端口背后存在可疑进程",
            description: "一个公网监听端口由具备可疑执行特征的进程持有。",
            impact: &["攻击者经常把后门或 WebShell 启动器伪装到看起来正常的公网端口后面。"],
            recommendations: &[
                "核对可执行文件路径、软件包归属和服务单元。",
                "停止服务前先保留进程和 socket 证据。",
            ],
        },
        "CONFIG-001" => RuleMessage {
            title: "SSH 密码认证已启用",
            description: "有效 sshd 配置中启用了 PasswordAuthentication yes。",
            impact: &[],
            recommendations: &[
                "条件允许时优先使用密钥认证并关闭密码登录。",
                "如果必须保留密码登录，请确认已启用 fail2ban 或等效限速。",
            ],
        },
        "CONFIG-003" => RuleMessage {
            title: "高风险服务端口公网暴露",
            description: "数据库、管理面、容器、监控或仪表盘服务正在公网监听。",
            impact: &["管理或数据库服务公网暴露后，一旦认证或补丁不足可能直接导致入侵。"],
            recommendations: &[
                "除非确有需要，请绑定到 localhost 或 VPN-only 地址。",
                "核对认证、TLS 和防火墙策略。",
            ],
        },
        "CONFIG-004" => RuleMessage {
            title: "允许直接 root SSH 登录",
            description: "有效 sshd 配置允许直接 root 登录。",
            impact: &[],
            recommendations: &[
                "除非有明确运维需求，请关闭 PermitRootLogin。",
                "使用具名 sudo 账号提升可审计性。",
            ],
        },
        "FILE-001" => RuleMessage {
            title: "关键系统文件发生变化",
            description: "受监控的关键系统文件相对基线发生变化。",
            impact: &["身份、sudo、SSH、cron 或 systemd 文件变化可能影响持久化或权限。"],
            recommendations: &[
                "从可信 shell 会话查看文件差异。",
                "关联软件包升级或管理员操作。",
            ],
        },
        "FILE-002" => RuleMessage {
            title: "检测到疑似 WebShell 文件",
            description: "受监控文件包含常见 WebShell 或脚本落地特征。",
            impact: &["如果该文件可被 Web 服务访问，可能导致远程命令执行。"],
            recommendations: &[
                "先确认不是合法业务代码，再隔离处理。",
                "检查 Web 访问日志和部署历史。",
            ],
        },
        "FILE-003" => RuleMessage {
            title: "Web 目录中存在可执行文件",
            description: "受监控 Web 路径包含可执行或脚本类文件。",
            impact: &[],
            recommendations: &[
                "确认 Web 服务是否能执行该文件。",
                "尽量将上传目录放在不可执行路径。",
            ],
        },
        "PERSIST-001" => RuleMessage {
            title: "持久化相关文件发生变化",
            description: "cron、systemd 或 shell 启动文件相对基线发生变化。",
            impact: &[],
            recommendations: &[
                "确认启动项是否由管理员或软件包更新添加。",
                "检查引用的可执行文件是否位于临时目录或 Web 可写路径。",
            ],
        },
        "PERSIST-002" => RuleMessage {
            title: "检测到可疑启动命令",
            description: "启动相关文件包含常见持久化命令片段。",
            impact: &["主机可能在重启或登录后自动运行攻击者控制的代码。"],
            recommendations: &["检查命令目标和网络目的地。", "移除未知启动项前先保留文件。"],
        },
        "PERSIST-003" => RuleMessage {
            title: "ld.so.preload 发生变化",
            description: "动态链接器 preload 配置相对基线变化或存在条目。",
            impact: &[],
            recommendations: &[
                "核对 preload 中的每一个库路径。",
                "未知条目应视为 rootkit 信号，但不是单独定罪证据。",
            ],
        },
        "WEB-001" => RuleMessage {
            title: "检测到 Web 漏洞探测",
            description: "Web 请求路径匹配常见自动化漏洞扫描模式。",
            impact: &[],
            recommendations: &[
                "检查探测路径是否返回成功响应。",
                "关联同一时间附近的文件变化和进程异常。",
            ],
        },
        "WEB-002" => RuleMessage {
            title: "单一来源产生大量 Web 错误",
            description: "同一来源 IP 在扫描窗口内产生大量 403/404 响应。",
            impact: &[],
            recommendations: &["除非和成功请求或主机变化相关联，否则将其作为上下文信息处理。"],
        },
        "DOCKER-001" => RuleMessage {
            title: "检测到 Docker socket",
            description: "发现 Docker socket；当前版本将其作为攻击面上下文提示。",
            impact: &[],
            recommendations: &["检查容器是否使用 privileged、host network 或挂载 docker.sock。"],
        },
        "ROOTKIT-003" => RuleMessage {
            title: "Rootkit 信号：ld.so.preload 存在活动条目",
            description:
                "ld.so.preload 可被滥用来向进程注入共享库；这是 rootkit 信号，不是单独结论。",
            impact: &[],
            recommendations: &[
                "验证 ld.so.preload 中列出的每个库路径。",
                "如怀疑入侵，请从可信介质比对受影响二进制和软件包完整性。",
            ],
        },
        _ => return None,
    };
    Some(message.into_localized())
}

struct RuleMessage {
    title: &'static str,
    description: &'static str,
    impact: &'static [&'static str],
    recommendations: &'static [&'static str],
}

impl RuleMessage {
    fn into_localized(self) -> LocalizedFinding {
        LocalizedFinding {
            title: self.title.to_string(),
            description: self.description.to_string(),
            impact: self
                .impact
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            recommendations: self
                .recommendations
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }
}
