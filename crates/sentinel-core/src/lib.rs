//! Core types shared by the VPS Sentinel crates.

pub mod config;
pub mod error;
pub mod event;
pub mod evidence_schema;
pub mod finding;
pub mod panel_auth;
pub mod severity;
pub mod time_window;

pub use config::{
    ActiveResponseConfig, AllowlistConfig, BarkConfig, EmailConfig, EmailTlsMode, GotifyConfig,
    NotificationLanguage, NotificationTimeZone, NtfyConfig, RiskScoringConfig, SentinelConfig,
    ServerChanConfig, SuppressRuleEntryConfig, SuppressRulesConfig, TelegramConfig, WebhookConfig,
    DEFAULT_DYNAMIC_UDP_MIN_PORT,
};
pub use error::{SentinelError, SentinelResult};
pub use event::RawEvent;
pub use evidence_schema::{
    canonical_key, evidence_value, evidence_values, normalize_evidence_items,
    normalize_evidence_value, stable_evidence_keys, upsert_evidence, EvidenceField,
    EvidenceValueKind,
};
pub use finding::{Category, Confidence, Evidence, Finding};
pub use severity::Severity;
pub use time_window::{minute_of_day, MinuteWindow};
