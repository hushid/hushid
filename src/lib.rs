//! Replace direct identifiers this crate recognizes with typed tokens.
//!
//! The original bytes stay in a session vault. They are copied back only
//! when the host asks, and only for a token this vault issued whose check
//! character matches. A value no detector recognizes is left unchanged.
//! Secret-shaped values become the shared mark `h1_secret` and are not restored.

#![forbid(unsafe_code)]

mod audit;
mod config;
mod detect;
mod digits;
mod glossary;
mod json;
mod session;
mod shield;
mod sink;
mod stream;
mod surrogate;
mod token;
mod vault;

pub use audit::{AuditRecord, DETECTOR_VERSION};
pub use config::{
    accept_non_text, non_text_allowed, parse_identifiers_config, shielding_active, ConfigError,
    IdentifiersConfig, Mode, NonTextRefused,
};
pub use glossary::Glossary;
pub use json::{restore_json_write, shield_json_strings, JsonError};
pub use session::{Session, SessionError, StoredMessage};
pub use shield::{shield_text, shield_text_with, Operator};
pub use sink::{classify, judge, known_tool_sinks, permissions_view, Ephemeral, Judgment, Sink};
pub use stream::{ArgumentBuffer, HeldStream};
#[cfg(fuzzing)]
pub use token::{find_h1, parse_token_at, secret_mark_at, ParsedToken};
pub use token::{format_token, Kind, TokenError, SECRET_MARK};
pub use vault::{RestoreError, Vault, VaultError};
