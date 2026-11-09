use crate::audit::AuditRecord;
use crate::glossary::Glossary;
use crate::shield::shield_text;
use crate::token::{find_h1, TokenError};
use crate::vault::{RestoreError, Vault};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    Syntax { at: usize },
    Token(TokenError),
    Restore(RestoreError),
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::Syntax { at } => write!(f, "json string syntax at byte {at}"),
            JsonError::Token(err) => write!(f, "{err}"),
            JsonError::Restore(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for JsonError {}

/// Shield decoded JSON string values. Keys and numbers stay as they are.
pub fn shield_json_strings(
    vault: &mut Vault,
    glossary: &Glossary,
    input: &str,
) -> Result<(String, AuditRecord), JsonError> {
    let mut audit = AuditRecord::default();
    let text = map_string_values(input, |value| {
        let (shielded, part) = shield_text(vault, glossary, value).map_err(JsonError::Token)?;
        audit.merge(&part);
        Ok(shielded)
    })?;
    Ok((text, audit))
}

/// Restore string values and fail if any `h1_` span remains.
///
/// Keys are not rewritten. A token or secret mark left in a key fails the write.
pub fn restore_json_write(vault: &Vault, input: &str) -> Result<String, JsonError> {
    let text = map_string_values(input, |value| {
        vault.restore_write(value).map_err(JsonError::Restore)
    })?;
    if find_h1(&text, 0).is_some() {
        return match vault.restore_write(&text) {
            Err(err) => Err(JsonError::Restore(err)),
            Ok(_) => Err(JsonError::Restore(RestoreError::Unresolved {
                at: find_h1(&text, 0).unwrap_or(0),
            })),
        };
    }
    Ok(text)
}

fn map_string_values(
    input: &str,
    mut map_value: impl FnMut(&str) -> Result<String, JsonError>,
) -> Result<String, JsonError> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let (end, decoded) = parse_string(input, index)?;
            let after = skip_ws(input, end);
            let is_key = input.as_bytes().get(after) == Some(&b':');
            if is_key {
                out.push_str(&input[index..end]);
            } else {
                let mapped = map_value(&decoded)?;
                out.push('"');
                out.push_str(&encode_json(&mapped));
                out.push('"');
            }
            index = end;
            continue;
        }
        let ch = input[index..]
            .chars()
            .next()
            .ok_or(JsonError::Syntax { at: index })?;
        out.push(ch);
        index += ch.len_utf8();
    }
    Ok(out)
}

fn parse_string(input: &str, start: usize) -> Result<(usize, String), JsonError> {
    let bytes = input.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return Err(JsonError::Syntax { at: start });
    }
    let mut index = start + 1;
    let mut decoded = String::new();
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok((index + 1, decoded)),
            b'\\' => {
                index += 1;
                if index >= bytes.len() {
                    return Err(JsonError::Syntax { at: start });
                }
                match bytes[index] {
                    b'"' => {
                        decoded.push('"');
                        index += 1;
                    }
                    b'\\' => {
                        decoded.push('\\');
                        index += 1;
                    }
                    b'/' => {
                        decoded.push('/');
                        index += 1;
                    }
                    b'b' => {
                        decoded.push('\u{0008}');
                        index += 1;
                    }
                    b'f' => {
                        decoded.push('\u{000c}');
                        index += 1;
                    }
                    b'n' => {
                        decoded.push('\n');
                        index += 1;
                    }
                    b'r' => {
                        decoded.push('\r');
                        index += 1;
                    }
                    b't' => {
                        decoded.push('\t');
                        index += 1;
                    }
                    b'u' => {
                        index += 1;
                        let unit = read_hex4(bytes, index)?;
                        index += 4;
                        let ch = if (0xD800..=0xDBFF).contains(&unit) {
                            if bytes.get(index) != Some(&b'\\')
                                || bytes.get(index + 1) != Some(&b'u')
                            {
                                return Err(JsonError::Syntax { at: index });
                            }
                            index += 2;
                            let low = read_hex4(bytes, index)?;
                            index += 4;
                            decode_surrogate(unit, low).ok_or(JsonError::Syntax { at: start })?
                        } else if (0xDC00..=0xDFFF).contains(&unit) {
                            return Err(JsonError::Syntax { at: start });
                        } else {
                            char::from_u32(u32::from(unit))
                                .ok_or(JsonError::Syntax { at: start })?
                        };
                        decoded.push(ch);
                    }
                    _ => return Err(JsonError::Syntax { at: index }),
                }
            }
            byte if byte < 0x20 => return Err(JsonError::Syntax { at: index }),
            _ => {
                let ch = input[index..]
                    .chars()
                    .next()
                    .ok_or(JsonError::Syntax { at: index })?;
                decoded.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    Err(JsonError::Syntax { at: start })
}

fn read_hex4(bytes: &[u8], start: usize) -> Result<u16, JsonError> {
    if start + 4 > bytes.len() {
        return Err(JsonError::Syntax { at: start });
    }
    let text = std::str::from_utf8(&bytes[start..start + 4])
        .map_err(|_| JsonError::Syntax { at: start })?;
    u16::from_str_radix(text, 16).map_err(|_| JsonError::Syntax { at: start })
}

fn decode_surrogate(high: u16, low: u16) -> Option<char> {
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let value = 0x10000 + (((u32::from(high) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
    char::from_u32(value)
}

fn skip_ws(input: &str, mut index: usize) -> usize {
    while let Some(ch) = input[index..].chars().next() {
        if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
            index += ch.len_utf8();
        } else {
            break;
        }
    }
    index
}

fn encode_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}
