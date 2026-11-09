use std::fmt;
use std::path::PathBuf;

/// Host switch. `cloud` is the only mode that shields, and only when the
/// provider is not a loopback model. The names are `off` and `cloud`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Cloud,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifiersConfig {
    pub mode: Mode,
    pub glossary: Option<PathBuf>,
}

impl Default for IdentifiersConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            glossary: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Syntax { line: usize },
    UnknownTable { line: usize },
    UnknownKey { line: usize },
    UnknownMode { line: usize },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Syntax { line } => write!(f, "invalid identifiers config on line {line}"),
            ConfigError::UnknownTable { line } => {
                write!(f, "unknown table on line {line}")
            }
            ConfigError::UnknownKey { line } => write!(f, "unknown key on line {line}"),
            ConfigError::UnknownMode { line } => {
                write!(f, "mode on line {line} must be off or cloud")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn parse_identifiers_config(text: &str) -> Result<IdentifiersConfig, ConfigError> {
    let mut config = IdentifiersConfig::default();
    let mut in_identifiers = false;
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if let Some(table) = line.strip_prefix('[') {
            let table = table
                .strip_suffix(']')
                .ok_or(ConfigError::Syntax { line: line_no })?;
            if table == "identifiers" {
                in_identifiers = true;
                continue;
            }
            return Err(ConfigError::UnknownTable { line: line_no });
        }
        if !in_identifiers {
            return Err(ConfigError::Syntax { line: line_no });
        }
        let (key, value) = split_kv(&line).ok_or(ConfigError::Syntax { line: line_no })?;
        match key {
            "mode" => {
                let value = unquote(value).ok_or(ConfigError::Syntax { line: line_no })?;
                config.mode = match value {
                    "off" => Mode::Off,
                    "cloud" => Mode::Cloud,
                    _ => return Err(ConfigError::UnknownMode { line: line_no }),
                };
            }
            "glossary" => {
                let value = unquote(value).ok_or(ConfigError::Syntax { line: line_no })?;
                if value.is_empty() {
                    config.glossary = None;
                } else {
                    config.glossary = Some(PathBuf::from(value));
                }
            }
            _ => return Err(ConfigError::UnknownKey { line: line_no }),
        }
    }
    Ok(config)
}

pub fn shielding_active(mode: Mode, provider_is_loopback: bool) -> bool {
    match mode {
        Mode::Off => false,
        Mode::Cloud => !provider_is_loopback,
    }
}

/// Images and other non-text documents are refused while `cloud` is on.
/// This crate has no image decoder.
pub fn non_text_allowed(mode: Mode) -> bool {
    !matches!(mode, Mode::Cloud)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonTextRefused;

impl fmt::Display for NonTextRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "non-text input is refused while mode is cloud")
    }
}

impl std::error::Error for NonTextRefused {}

pub fn accept_non_text(mode: Mode) -> Result<(), NonTextRefused> {
    if non_text_allowed(mode) {
        Ok(())
    } else {
        Err(NonTextRefused)
    }
}

fn strip_comment(raw: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (index, ch) in raw.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &raw[..index],
            _ => {}
        }
    }
    raw
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key, value))
}

fn unquote(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return Some(&value[1..value.len() - 1]);
        }
    }
    if value.contains(char::is_whitespace) {
        return None;
    }
    Some(value)
}
