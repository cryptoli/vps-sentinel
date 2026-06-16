mod notifications;
mod sections;

use crate::error::{SentinelError, SentinelResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub use notifications::{
    BarkConfig, EmailConfig, GotifyConfig, NotificationsConfig, NtfyConfig, ServerChanConfig,
    TelegramConfig, WebhookConfig,
};
pub use sections::{
    AgentConfig, AllowlistConfig, DockerConfig, FileIntegrityConfig, NetworkConfig,
    NoiseControlConfig, PersistenceConfig, PrivacyConfig, ProcessConfig, SentinelPaths, SshConfig,
    StorageConfig, WebConfig,
};

/// Top-level TOML configuration for the agent and CLI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    pub agent: AgentConfig,
    pub privacy: PrivacyConfig,
    pub storage: StorageConfig,
    pub ssh: SshConfig,
    pub file_integrity: FileIntegrityConfig,
    pub web: WebConfig,
    pub process: ProcessConfig,
    pub network: NetworkConfig,
    pub persistence: PersistenceConfig,
    pub docker: DockerConfig,
    pub notifications: NotificationsConfig,
    pub noise_control: NoiseControlConfig,
    pub allowlist: AllowlistConfig,
}

impl SentinelConfig {
    /// Load configuration from TOML.
    pub fn load(path: &Path) -> SentinelResult<Self> {
        let text = fs::read_to_string(path).map_err(|err| SentinelError::io(path, err))?;
        let config: Self =
            toml::from_str(&text).map_err(|err| SentinelError::Config(err.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Serialize the default configuration as TOML.
    pub fn default_toml() -> SentinelResult<String> {
        toml::to_string_pretty(&Self::default())
            .map_err(|err| SentinelError::Config(err.to_string()))
    }

    /// Validate cross-field requirements.
    pub fn validate(&self) -> SentinelResult<()> {
        if self.agent.scan_interval_seconds == 0 {
            return Err(SentinelError::Config(
                "agent.scan_interval_seconds must be greater than 0".to_string(),
            ));
        }
        if self.storage.r#type != "sqlite" {
            return Err(SentinelError::Unsupported(format!(
                "storage.type '{}' is not supported",
                self.storage.r#type
            )));
        }
        if self.ssh.failed_login_threshold == 0 {
            return Err(SentinelError::Config(
                "ssh.failed_login_threshold must be greater than 0".to_string(),
            ));
        }
        if self.file_integrity.max_file_size_mb == 0 {
            return Err(SentinelError::Config(
                "file_integrity.max_file_size_mb must be greater than 0".to_string(),
            ));
        }
        if self.notifications.request_timeout_seconds == 0 {
            return Err(SentinelError::Config(
                "notifications.request_timeout_seconds must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve the host identifier, falling back to the configured hostname.
    pub fn host_id(&self) -> String {
        if !self.agent.host_id.trim().is_empty() {
            return self.agent.host_id.clone();
        }
        if !self.agent.hostname.trim().is_empty() {
            return self.agent.hostname.clone();
        }
        "local-host".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::SentinelConfig;

    #[test]
    fn default_config_round_trips_as_toml() -> Result<(), Box<dyn std::error::Error>> {
        let text = SentinelConfig::default_toml()?;
        let decoded: SentinelConfig = toml::from_str(&text)?;
        decoded.validate()?;
        assert_eq!(decoded.storage.r#type, "sqlite");
        assert!(!decoded.ssh.auth_log_paths.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_storage_type_is_rejected() {
        let mut config = SentinelConfig::default();
        config.storage.r#type = "postgres".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_notification_timeout_is_rejected() {
        let mut config = SentinelConfig::default();
        config.notifications.request_timeout_seconds = 0;
        assert!(config.validate().is_err());
    }
}
