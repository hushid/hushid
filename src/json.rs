use crate::audit::AuditRecord;
use crate::detect::{find_hits, Hit};
use crate::glossary::Glossary;
use crate::shield::shield_text;
use crate::token::{find_h1, TokenError, SECRET_MARK};
use crate::vault::{RestoreError, Vault};
use std::fmt;

const MAX_JSON_DEPTH: u8 = 8;

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

/// Shield JSON string values, object keys, and numbers the detectors recognize.
///
/// A number is replaced with a quoted token and restored as a number. A string
/// whose text is itself a JSON object or array is shielded again. Keys and
/// numbers that no detector recognizes stay as they are.
pub fn shield_json_strings(
    vault: &mut Vault,
    glossary: &Glossary,
    input: &str,
) -> Result<(String, AuditRecord), JsonError> {
    let mut audit = AuditRecord::default();
    let text = shield_document(vault, glossary, input, &mut audit, 0)?;
    Ok((text, audit))
}

/// Restore JSON keys, string values, and numbers. An unresolved `h1_` span fails.
pub fn restore_json_write(vault: &Vault, input: &str) -> Result<String, JsonError> {
    let text = restore_document(vault, input, 0)?;
    if let Some(at) = find_h1(&text, 0) {
        return Err(JsonError::Restore(RestoreError::Unresolved { at }));
    }
    Ok(text)
}

fn shield_document(
    vault: &mut Vault,
    glossary: &Glossary,
    input: &str,
    audit: &mut AuditRecord,
    depth: u8,
) -> Result<String, JsonError> {
    let hits = find_hits(input, glossary);
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let (end, decoded) = parse_string(input, index)?;
            let after = skip_ws(input, end);
            let is_key = bytes.get(after) == Some(&b':');
            let mapped = shield_decoded(vault, glossary, &decoded, audit, depth, is_key)?;
            out.push('"');
            out.push_str(&encode_json(&mapped));
            out.push('"');
            index = end;
            continue;
        }
        if let Some(end) = parse_number(input, index) {
            if let Some(hit) = covering_hit(&hits, index, end) {
                let raw = &input[index..end];
                let token = token_for_hit(vault, audit, hit, raw.as_bytes())?;
                out.push('"');
                out.push_str(&token);
                out.push('"');
            } else {
                out.push_str(&input[index..end]);
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

fn shield_decoded(
    vault: &mut Vault,
    glossary: &Glossary,
    decoded: &str,
    audit: &mut AuditRecord,
    depth: u8,
    is_key: bool,
) -> Result<String, JsonError> {
    if !is_key && depth < MAX_JSON_DEPTH && is_json_document(decoded) {
        return shield_document(vault, glossary, decoded, audit, depth + 1);
    }
    let (shielded, part) = shield_text(vault, glossary, decoded).map_err(JsonError::Token)?;
    audit.merge(&part);
    Ok(shielded)
}

fn token_for_hit(
    vault: &mut Vault,
    audit: &mut AuditRecord,
    hit: &Hit,
    surface: &[u8],
) -> Result<String, JsonError> {
    match hit {
        Hit::Secret { .. } => {
            audit.secret += 1;
            Ok(SECRET_MARK.to_string())
        }
        Hit::Reversible { kind, .. } => {
            let token = vault
                .issue_json_number(*kind, surface)
                .map_err(JsonError::Token)?;
            audit.bump(*kind);
            Ok(token)
        }
    }
}

fn restore_document(vault: &Vault, input: &str, depth: u8) -> Result<String, JsonError> {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let (end, decoded) = parse_string(input, index)?;
            let after = skip_ws(input, end);
            let is_key = bytes.get(after) == Some(&b':');
            if !is_key {
                if let Some(literal) = json_number_literal(vault, &decoded) {
                    out.push_str(literal);
                    index = end;
                    continue;
                }
            }
            let mapped = if !is_key && depth < MAX_JSON_DEPTH && is_json_document(&decoded) {
                restore_document(vault, &decoded, depth + 1)?
            } else {
                vault.restore_write(&decoded).map_err(JsonError::Restore)?
            };
            out.push('"');
            out.push_str(&encode_json(&mapped));
            out.push('"');
            index = end;
            continue;
        }
        if let Some(end) = parse_number(input, index) {
            out.push_str(&input[index..end]);
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

fn json_number_literal<'a>(vault: &'a Vault, text: &str) -> Option<&'a str> {
    if !vault.is_json_number_token(text) {
        return None;
    }
    let surface = std::str::from_utf8(vault.get(text)?).ok()?;
    if parse_number(surface, 0) == Some(surface.len()) {
        Some(surface)
    } else {
        None
    }
}

fn covering_hit(hits: &[Hit], start: usize, end: usize) -> Option<&Hit> {
    hits.iter().find(|hit| {
        let (hit_start, hit_end) = hit_span(hit);
        hit_start < end && start < hit_end
    })
}

fn hit_span(hit: &Hit) -> (usize, usize) {
    match *hit {
        Hit::Secret { start, end } | Hit::Reversible { start, end, .. } => (start, end),
    }
}

fn parse_number(input: &str, start: usize) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut index = start;
    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }
    let digits_at = index;
    if bytes.get(index) == Some(&b'0') {
        index += 1;
    } else if bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
        while bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
            index += 1;
        }
    } else {
        return None;
    }
    if index == digits_at {
        return None;
    }
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_at = index;
        while bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
            index += 1;
        }
        if index == fraction_at {
            return None;
        }
    }
    if bytes
        .get(index)
        .is_some_and(|byte| *byte == b'e' || *byte == b'E')
    {
        index += 1;
        if bytes
            .get(index)
            .is_some_and(|byte| *byte == b'+' || *byte == b'-')
        {
            index += 1;
        }
        let exponent_at = index;
        while bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
            index += 1;
        }
        if index == exponent_at {
            return None;
        }
    }
    if index == start {
        return None;
    }
    Some(index)
}

fn is_json_document(input: &str) -> bool {
    let trimmed = input.trim();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    match skip_value(trimmed, 0) {
        Some(end) => trimmed[end..].trim().is_empty(),
        None => false,
    }
}

fn skip_value(input: &str, start: usize) -> Option<usize> {
    let index = skip_ws(input, start);
    let bytes = input.as_bytes();
    match bytes.get(index)? {
        b'"' => parse_string(input, index).ok().map(|(end, _)| end),
        b'{' => skip_container(input, index, b'{', b'}'),
        b'[' => skip_container(input, index, b'[', b']'),
        b't' => skip_literal(input, index, "true"),
        b'f' => skip_literal(input, index, "false"),
        b'n' => skip_literal(input, index, "null"),
        b'-' | b'0'..=b'9' => parse_number(input, index),
        _ => None,
    }
}

fn skip_container(input: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = input.as_bytes();
    if bytes.get(start) != Some(&open) {
        return None;
    }
    let mut index = skip_ws(input, start + 1);
    if bytes.get(index) == Some(&close) {
        return Some(index + 1);
    }
    loop {
        if open == b'{' {
            if bytes.get(index) != Some(&b'"') {
                return None;
            }
            let (after_key, _) = parse_string(input, index).ok()?;
            index = skip_ws(input, after_key);
            if bytes.get(index) != Some(&b':') {
                return None;
            }
            index += 1;
        }
        index = skip_value(input, index)?;
        index = skip_ws(input, index);
        match bytes.get(index)? {
            byte if *byte == close => return Some(index + 1),
            b',' => index = skip_ws(input, index + 1),
            _ => return None,
        }
    }
}

fn skip_literal(input: &str, start: usize, literal: &str) -> Option<usize> {
    if input.get(start..)?.starts_with(literal) {
        Some(start + literal.len())
    } else {
        None
    }
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
