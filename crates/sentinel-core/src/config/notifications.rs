use crate::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationsConfig {
    pub request_timeout_seconds: u64,
    pub telegram: TelegramConfig,
    pub email: EmailConfig,
    pub webhook: WebhookConfig,
    pub ntfy: NtfyConfig,
    pub gotify: GotifyConfig,
    pub bark: BarkConfig,
    pub serverchan: ServerChanConfig,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            request_timeout_seconds: 15,
            telegram: TelegramConfig::default(),
            email: EmailConfig::default(),
            webhook: WebhookConfig::default(),
            ntfy: NtfyConfig::default(),
            gotify: GotifyConfig::default(),
            bark: BarkConfig::default(),
            serverchan: ServerChanConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    pub min_severity: Severity,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub min_severity: Severity,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: String::new(),
            smtp_port: 587,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            to: Vec::new(),
            min_severity: Severity::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub secret: String,
    pub min_severity: Severity,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            secret: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NtfyConfig {
    pub enabled: bool,
    pub server: String,
    pub topic: String,
    pub token: String,
    pub min_severity: Severity,
}

impl Default for NtfyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "https://ntfy.sh".to_string(),
            topic: String::new(),
            token: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GotifyConfig {
    pub enabled: bool,
    pub server: String,
    pub token: String,
    pub min_severity: Severity,
}

impl Default for GotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: String::new(),
            token: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BarkConfig {
    pub enabled: bool,
    pub server: String,
    pub device_key: String,
    pub min_severity: Severity,
}

impl Default for BarkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "https://api.day.app".to_string(),
            device_key: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerChanConfig {
    pub enabled: bool,
    pub send_key: String,
    pub min_severity: Severity,
}

impl Default for ServerChanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            send_key: String::new(),
            min_severity: Severity::Medium,
        }
    }
}
