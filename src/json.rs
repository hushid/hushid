use crate::audit::AuditRecord;
use crate::detect::{assignment_secret_prefix, find_hits, luhn_ok, Hit};
use crate::glossary::Glossary;
use crate::shield::{mask_for, mint_forgotten, shield_in_context, Operator, ShieldOp};
use crate::token::{find_h1, parse_token_at, secret_mark_at, Kind, TokenError, SECRET_MARK};
use crate::vault::{RestoreError, Vault};
use std::collections::BTreeMap;
use std::fmt;

const MAX_JSON_DEPTH: u8 = 8;

/// Surrounding characters kept for a cue, in Unicode scalars.
///
/// The window is 96, which covers the longest cue, the 40-character
/// gap, and the quote on this string.
const CUE_CONTEXT_CHARS: usize = 96;

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
/// This uses [`Operator::Token`]. [`shield_json_strings_with`] takes an
/// operator. A number is replaced with a quoted token and restored as a
/// number. A string whose text is itself a JSON object or array is shielded
/// again. A cue beside a string or a key counts the same way it does in plain
/// text, including a value inside that nested document. A key that names an
/// API-key assignment masks that value with the shared secret mark, and the
/// value is not stored. A JSON number of 13 to 19 digits that passes the
/// card check is a card on its own, including beside another number and
/// inside an array. The same digits in prose, or in a JSON string, still
/// need a cue or separators. Keys and numbers that no detector recognizes
/// stay as they are.
pub fn shield_json_strings(
    vault: &mut Vault,
    glossary: &Glossary,
    input: &str,
) -> Result<(String, AuditRecord), JsonError> {
    shield_json_strings_with(vault, glossary, input, Operator::Token)
}

/// [`shield_json_strings`] with an explicit operator.
///
/// [`Operator::Forget`] writes a token and stores nothing. The same bytes
/// share one token inside this call, including two strings and a number.
/// A later call mints another token. A token already in the vault is not
/// reused. A reply keeps that token. [`Operator::Mask`] does not store
/// either. A JSON number stays a quoted token for [`Operator::Token`],
/// [`Operator::Digits`], and [`Operator::Surrogate`], so
/// [`restore_json_write`] can write it back as a number. A later shield of
/// the same number reuses that token. A token stored for those digits as a
/// string is not reused.
///
/// ```
/// use hushid::{restore_json_write, shield_json_strings_with, Glossary, Operator, Vault};
///
/// let mut vault = Vault::new();
/// let input = r#"{"content":"mail marie@example.com"}"#;
/// let (out, _) =
///     shield_json_strings_with(&mut vault, &Glossary::empty(), input, Operator::Forget).unwrap();
/// assert!(out.contains("h1_email_"));
/// assert!(!out.contains("marie@example.com"));
/// assert!(vault.is_empty());
/// assert!(restore_json_write(&vault, &out).is_err());
/// ```
pub fn shield_json_strings_with(
    vault: &mut Vault,
    glossary: &Glossary,
    input: &str,
    operator: Operator,
) -> Result<(String, AuditRecord), JsonError> {
    let mut audit = AuditRecord::default();
    let mut forgotten = BTreeMap::new();
    let mut state = JsonState {
        audit: &mut audit,
        forgotten: &mut forgotten,
        depth: 0,
        operator,
    };
    let text = shield_document(vault, glossary, input, &mut state, ("", ""))?;
    Ok((text, audit))
}

struct JsonState<'a> {
    audit: &'a mut AuditRecord,
    forgotten: &'a mut BTreeMap<Vec<u8>, String>,
    depth: u8,
    operator: Operator,
}

/// Restore JSON keys, string values, and numbers. An unresolved `h1_` span fails.
pub fn restore_json_write(vault: &Vault, input: &str) -> Result<String, JsonError> {
    let text = restore_document(vault, input, 0, false)?;
    // A restored email can itself start with `h1_`. That text is not a
    // token. A real token shape, or `h1_secret`, still fails the write.
    if let Some(at) = unresolved_mark(&text) {
        return Err(JsonError::Restore(RestoreError::Unresolved { at }));
    }
    Ok(text)
}

/// Restore a chat reply. Issued tokens come back. `h1_secret` stays the
/// mark, because the secret was not stored. A token minted with
/// [`Operator::Forget`] stays in the text. A token this vault did not
/// mint still fails.
pub fn restore_json_reply(vault: &Vault, input: &str) -> Result<String, JsonError> {
    let text = restore_document(vault, input, 0, true)?;
    if let Some(at) = unresolved_token(vault, &text) {
        return Err(JsonError::Restore(RestoreError::Unresolved { at }));
    }
    Ok(text)
}

/// Restore text a person will read.
///
/// A JSON object or array uses [`restore_json_reply`], so a number token
/// becomes digits again. Other text uses [`Vault::restore_reply`].
pub fn restore_readable(vault: &Vault, text: &str) -> Result<String, JsonError> {
    if is_json_document(text) {
        restore_json_reply(vault, text)
    } else {
        vault.restore_reply(text).map_err(JsonError::Restore)
    }
}

/// Shield `text` when it is one JSON object or array.
///
/// [`None`] means the text is prose, or another value, and the caller
/// should use the text shield. A recognized number becomes a quoted token.
pub(crate) fn shield_if_document(
    vault: &mut Vault,
    glossary: &Glossary,
    text: &str,
    operator: Operator,
) -> Option<Result<(String, AuditRecord), TokenError>> {
    if !is_json_document(text) {
        return None;
    }
    Some(
        match shield_json_strings_with(vault, glossary, text, operator) {
            Ok(pair) => Ok(pair),
            Err(JsonError::Token(err)) => Err(err),
            Err(JsonError::Syntax { .. } | JsonError::Restore(_)) => Err(TokenError::Payload),
        },
    )
}

fn unresolved_token(vault: &Vault, text: &str) -> Option<usize> {
    let mut index = 0;
    while let Some(at) = find_h1(text, index) {
        if let Some(end) = secret_mark_at(text, at) {
            index = end;
            continue;
        }
        if let Some(parsed) = parse_token_at(text, at) {
            if parsed.check_ok && vault.forgot(&parsed.canonical) {
                index = parsed.end;
                continue;
            }
            return Some(at);
        }
        index = at + 3;
    }
    None
}

fn unresolved_mark(text: &str) -> Option<usize> {
    let mut index = 0;
    while let Some(at) = find_h1(text, index) {
        if secret_mark_at(text, at).is_some() || parse_token_at(text, at).is_some() {
            return Some(at);
        }
        index = at + 3;
    }
    None
}

fn shield_document(
    vault: &mut Vault,
    glossary: &Glossary,
    input: &str,
    state: &mut JsonState<'_>,
    context: (&str, &str),
) -> Result<String, JsonError> {
    let (outer_before, outer_after) = context;
    let hits = hits_in_value(outer_before, input, outer_after, glossary);
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let (end, decoded) = parse_string(input, index)?;
            let after = skip_ws(input, end);
            let is_key = bytes.get(after) == Some(&b':');
            let before_ctx = join_suffix(outer_before, &input[..index + 1], CUE_CONTEXT_CHARS);
            let after_ctx = join_prefix(&input[end - 1..], outer_after, CUE_CONTEXT_CHARS);
            let secret_end = if is_key {
                None
            } else {
                assignment_secret_prefix(&input[..index + 1], &decoded)
            };
            let mapped = if let Some(secret_end) = secret_end {
                mask_assignment_value(vault, glossary, &decoded, secret_end, state)?
            } else {
                shield_decoded(
                    vault,
                    glossary,
                    &decoded,
                    state,
                    is_key,
                    (&before_ctx, &after_ctx),
                )?
            };
            out.push('"');
            out.push_str(&encode_json(&mapped));
            out.push('"');
            index = end;
            continue;
        }
        if let Some(end) = parse_number(input, index) {
            let raw = &input[index..end];
            if let Some(hit) = covering_hit(&hits, index, end) {
                let token = token_for_hit(vault, state, hit, raw.as_bytes())?;
                out.push('"');
                out.push_str(&token);
                out.push('"');
            } else if json_card_number(raw) {
                // A JSON number is its own value. A 13 to 19 digit run
                // that passes the check is a card here even when no cue
                // word is nearby, and when the document holds another
                // number or the value sits in an array. The same run in
                // prose, or in a JSON string, still needs a cue. Leaving
                // this out sends the digits.
                let hit = Hit::Reversible {
                    kind: Kind::Card,
                    start: index,
                    end,
                };
                let token = token_for_hit(vault, state, &hit, raw.as_bytes())?;
                out.push('"');
                out.push_str(&token);
                out.push('"');
            } else {
                out.push_str(raw);
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

fn mask_assignment_value(
    vault: &mut Vault,
    glossary: &Glossary,
    decoded: &str,
    secret_end: usize,
    state: &mut JsonState<'_>,
) -> Result<String, JsonError> {
    let mut mapped = SECRET_MARK.to_string();
    if secret_end < decoded.len() {
        let (rest, part) = shield_in_context(
            vault,
            glossary,
            "",
            &decoded[secret_end..],
            "",
            &mut ShieldOp {
                operator: state.operator,
                forgotten: state.forgotten,
            },
            crate::shield::Names::Off,
        )
        .map_err(JsonError::Token)?;
        mapped.push_str(&rest);
        state.audit.merge(&part);
    }
    state.audit.secret += 1;
    Ok(mapped)
}

fn shield_decoded(
    vault: &mut Vault,
    glossary: &Glossary,
    decoded: &str,
    state: &mut JsonState<'_>,
    is_key: bool,
    context: (&str, &str),
) -> Result<String, JsonError> {
    if !is_key && state.depth < MAX_JSON_DEPTH && is_json_document(decoded) {
        state.depth += 1;
        let result = shield_document(vault, glossary, decoded, state, context);
        state.depth -= 1;
        return result;
    }
    let (before, after) = context;
    let (shielded, part) = shield_in_context(
        vault,
        glossary,
        before,
        decoded,
        after,
        &mut ShieldOp {
            operator: state.operator,
            forgotten: state.forgotten,
        },
        crate::shield::Names::Off,
    )
    .map_err(JsonError::Token)?;
    state.audit.merge(&part);
    Ok(shielded)
}

fn token_for_hit(
    vault: &mut Vault,
    state: &mut JsonState<'_>,
    hit: &Hit,
    surface: &[u8],
) -> Result<String, JsonError> {
    match hit {
        Hit::Secret { .. } => {
            state.audit.secret += 1;
            Ok(SECRET_MARK.to_string())
        }
        Hit::Reversible { kind, .. } => {
            let token = match state.operator {
                Operator::Forget => {
                    let text = std::str::from_utf8(surface)
                        .map_err(|_| JsonError::Token(TokenError::Payload))?;
                    mint_forgotten(vault, state.forgotten, *kind, text).map_err(JsonError::Token)?
                }
                Operator::Mask => {
                    let text = std::str::from_utf8(surface)
                        .map_err(|_| JsonError::Token(TokenError::Payload))?;
                    mask_for(*kind, text)
                }
                Operator::Token | Operator::Digits | Operator::Surrogate => {
                    if let Some(token) = vault.first_json_number_token(*kind, surface) {
                        token
                    } else {
                        vault
                            .issue_json_number(*kind, surface)
                            .map_err(JsonError::Token)?
                    }
                }
            };
            state.audit.bump(*kind);
            Ok(token)
        }
    }
}

fn restore_document(
    vault: &Vault,
    input: &str,
    depth: u8,
    reply: bool,
) -> Result<String, JsonError> {
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
                restore_document(vault, &decoded, depth + 1, reply)?
            } else if reply {
                vault.restore_reply(&decoded).map_err(JsonError::Restore)?
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

fn hits_in_value(before: &str, input: &str, after: &str, glossary: &Glossary) -> Vec<Hit> {
    if before.is_empty() && after.is_empty() {
        return find_hits(input, glossary);
    }
    let mut scan = String::with_capacity(before.len() + input.len() + after.len());
    scan.push_str(before);
    scan.push_str(input);
    scan.push_str(after);
    let origin = before.len();
    let limit = origin + input.len();
    find_hits(&scan, glossary)
        .into_iter()
        .filter_map(|hit| {
            let (start, end) = hit_span(&hit);
            if start >= origin && end <= limit {
                Some(shift_hit(hit, origin))
            } else {
                None
            }
        })
        .collect()
}

fn shift_hit(hit: Hit, origin: usize) -> Hit {
    match hit {
        Hit::Secret { start, end } => Hit::Secret {
            start: start - origin,
            end: end - origin,
        },
        Hit::Reversible { kind, start, end } => Hit::Reversible {
            kind,
            start: start - origin,
            end: end - origin,
        },
    }
}

fn json_card_number(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    (13..=19).contains(&bytes.len())
        && bytes.iter().all(|byte| byte.is_ascii_digit())
        && luhn_ok(bytes)
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
    match skip_value(trimmed, 0, 0) {
        Some(end) => trimmed[end..].trim().is_empty(),
        None => false,
    }
}

fn skip_value(input: &str, start: usize, depth: u8) -> Option<usize> {
    let index = skip_ws(input, start);
    let bytes = input.as_bytes();
    match bytes.get(index)? {
        b'"' => parse_string(input, index).ok().map(|(end, _)| end),
        b'{' => skip_container(input, index, b'{', b'}', depth),
        b'[' => skip_container(input, index, b'[', b']', depth),
        b't' => skip_literal(input, index, "true"),
        b'f' => skip_literal(input, index, "false"),
        b'n' => skip_literal(input, index, "null"),
        b'-' | b'0'..=b'9' => parse_number(input, index),
        _ => None,
    }
}

fn skip_container(input: &str, start: usize, open: u8, close: u8, depth: u8) -> Option<usize> {
    // The shield walk stops at `MAX_JSON_DEPTH`. This probe has to stop
    // there too. A deeper string is not a nested document, so the caller
    // shields it as plain text instead of overflowing the stack.
    if depth >= MAX_JSON_DEPTH {
        return None;
    }
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
        index = skip_value(input, index, depth + 1)?;
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

fn join_suffix(outer: &str, local: &str, max_chars: usize) -> String {
    // `local` may be the whole prefix of a large document. A shorter tail
    // means it already holds `max_chars`, so the outer cue is out of range.
    let local_tail = suffix_chars(local, max_chars);
    if local_tail.len() != local.len() {
        return local_tail.to_string();
    }
    let mut out = suffix_chars(outer, max_chars - local_tail.chars().count()).to_string();
    out.push_str(local_tail);
    out
}

fn join_prefix(local: &str, outer: &str, max_chars: usize) -> String {
    let local_head = prefix_chars(local, max_chars);
    if local_head.len() != local.len() {
        return local_head.to_string();
    }
    let mut out = local_head.to_string();
    out.push_str(prefix_chars(outer, max_chars - local_head.chars().count()));
    out
}

fn suffix_chars(text: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    let start = text
        .char_indices()
        .rev()
        .nth(max_chars - 1)
        .map(|(index, _)| index)
        .unwrap_or(0);
    &text[start..]
}

fn prefix_chars(text: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    match text.char_indices().nth(max_chars) {
        Some((index, _)) => &text[..index],
        None => text,
    }
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
