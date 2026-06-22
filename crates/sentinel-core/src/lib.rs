//! Core types shared by the VPS Sentinel crates.

pub mod config;
pub mod error;
pub mod event;
pub mod finding;
pub mod severity;
pub mod time_window;

pub use config::{
    ActiveResponseConfig, BarkConfig, DingTalkConfig, EmailConfig, EmailTlsMode, FeishuConfig,
    GotifyConfig, NotificationLanguage, NotificationTimeZone, NtfyConfig, SentinelConfig,
    ServerChanConfig, TelegramConfig, WebhookConfig,
};
pub use error::{SentinelError, SentinelResult};
pub use event::RawEvent;
pub use finding::{Category, Confidence, Evidence, Finding};
pub use severity::Severity;
pub use time_window::{minute_of_day, MinuteWindow};
