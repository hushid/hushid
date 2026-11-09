//! Checked token grammar.
//!
//! Shape: `h1_<kind>_<8 base32 chars><check>`.
//!
//! The payload alphabet is Crockford base32. `I` and `L` mean 1. `O` means 0.
//! The check character is the sum of the kind's UTF-8 bytes and the eight
//! payload values, modulo 32. A one-symbol change always changes that sum.
//! Restore accepts a token only when the check matches and this vault issued it.

use std::fmt;

pub const PREFIX: &str = "h1_";
pub const SECRET_MARK: &str = "h1_secret";
pub const PAYLOAD_LEN: usize = 8;

pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Email,
    Phone,
    Card,
    Sin,
    Glossary,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Phone => "phone",
            Kind::Card => "card",
            Kind::Sin => "sin",
            Kind::Glossary => "glossary",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("email") {
            Some(Kind::Email)
        } else if name.eq_ignore_ascii_case("phone") {
            Some(Kind::Phone)
        } else if name.eq_ignore_ascii_case("card") {
            Some(Kind::Card)
        } else if name.eq_ignore_ascii_case("sin") {
            Some(Kind::Sin)
        } else if name.eq_ignore_ascii_case("glossary") {
            Some(Kind::Glossary)
        } else {
            None
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    Payload,
    Entropy,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Payload => {
                write!(f, "token payload must be 8 Crockford base32 symbols")
            }
            TokenError::Entropy => write!(f, "operating system random source failed"),
        }
    }
}

impl std::error::Error for TokenError {}

pub fn symbol_value(byte: u8) -> Option<u8> {
    match byte {
        b'0' | b'o' | b'O' => Some(0),
        b'1' | b'i' | b'I' | b'l' | b'L' => Some(1),
        b'2'..=b'9' => Some(byte - b'0'),
        b'a' | b'A' => Some(10),
        b'b' | b'B' => Some(11),
        b'c' | b'C' => Some(12),
        b'd' | b'D' => Some(13),
        b'e' | b'E' => Some(14),
        b'f' | b'F' => Some(15),
        b'g' | b'G' => Some(16),
        b'h' | b'H' => Some(17),
        b'j' | b'J' => Some(18),
        b'k' | b'K' => Some(19),
        b'm' | b'M' => Some(20),
        b'n' | b'N' => Some(21),
        b'p' | b'P' => Some(22),
        b'q' | b'Q' => Some(23),
        b'r' | b'R' => Some(24),
        b's' | b'S' => Some(25),
        b't' | b'T' => Some(26),
        b'v' | b'V' => Some(27),
        b'w' | b'W' => Some(28),
        b'x' | b'X' => Some(29),
        b'y' | b'Y' => Some(30),
        b'z' | b'Z' => Some(31),
        _ => None,
    }
}

pub fn check_value(kind: Kind, payload: &[u8; PAYLOAD_LEN]) -> u8 {
    let mut sum: u32 = 0;
    for byte in kind.as_str().bytes() {
        sum = sum.wrapping_add(u32::from(byte));
    }
    for value in payload {
        sum = sum.wrapping_add(u32::from(*value));
    }
    (sum % 32) as u8
}

/// Build a canonical token. This does not record it in a vault.
pub fn format_token(kind: Kind, symbols: &str) -> Result<String, TokenError> {
    let bytes = symbols.as_bytes();
    if bytes.len() != PAYLOAD_LEN {
        return Err(TokenError::Payload);
    }
    let mut values = [0u8; PAYLOAD_LEN];
    for (index, byte) in bytes.iter().enumerate() {
        values[index] = symbol_value(*byte).ok_or(TokenError::Payload)?;
    }
    Ok(canonical(kind, &values, check_value(kind, &values)))
}

pub fn random_token(kind: Kind) -> Result<String, TokenError> {
    let mut raw = [0u8; PAYLOAD_LEN];
    getrandom::fill(&mut raw).map_err(|_| TokenError::Entropy)?;
    let mut values = [0u8; PAYLOAD_LEN];
    for (index, byte) in raw.iter().enumerate() {
        values[index] = (*byte as usize % 32) as u8;
    }
    Ok(canonical(kind, &values, check_value(kind, &values)))
}

fn canonical(kind: Kind, payload: &[u8; PAYLOAD_LEN], check: u8) -> String {
    let mut out = String::with_capacity(PREFIX.len() + kind.as_str().len() + 1 + PAYLOAD_LEN + 1);
    out.push_str(PREFIX);
    out.push_str(kind.as_str());
    out.push('_');
    for value in payload {
        out.push(ALPHABET[*value as usize] as char);
    }
    out.push(ALPHABET[check as usize] as char);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToken {
    pub kind: Kind,
    pub canonical: String,
    pub end: usize,
    pub check_ok: bool,
}

/// Parse one typed token whose first byte is `at`.
///
/// `None` means the bytes are not the typed-token shape. `check_ok` is false
/// when the shape matches and the check character does not.
pub fn parse_token_at(text: &str, at: usize) -> Option<ParsedToken> {
    let rest = text.get(at..)?;
    let rest_bytes = rest.as_bytes();
    if rest_bytes.len() < 3
        || !rest_bytes[0].eq_ignore_ascii_case(&b'h')
        || !rest_bytes[1].eq_ignore_ascii_case(&b'1')
        || rest_bytes[2] != b'_'
    {
        return None;
    }
    let after_prefix = &rest[3..];
    let kind_len = after_prefix.find('_')?;
    let kind = Kind::parse(&after_prefix[..kind_len])?;
    let symbols_at = 3 + kind_len + 1;
    let symbols = rest.get(symbols_at..)?;
    if symbols.len() < PAYLOAD_LEN + 1 {
        return None;
    }
    let symbol_bytes = symbols.as_bytes();
    let mut values = [0u8; PAYLOAD_LEN];
    for index in 0..PAYLOAD_LEN {
        values[index] = symbol_value(symbol_bytes[index])?;
    }
    let presented = symbol_value(symbol_bytes[PAYLOAD_LEN])?;
    let end = at + symbols_at + PAYLOAD_LEN + 1;
    if !text.is_char_boundary(end) {
        return None;
    }
    let expected = check_value(kind, &values);
    Some(ParsedToken {
        kind,
        canonical: canonical(kind, &values, presented),
        end,
        check_ok: presented == expected,
    })
}

/// End byte of `h1_secret` when it sits on a boundary at `at`.
pub fn secret_mark_at(text: &str, at: usize) -> Option<usize> {
    let rest = text.get(at..)?;
    if rest.len() < SECRET_MARK.len() {
        return None;
    }
    if !rest[..SECRET_MARK.len()].eq_ignore_ascii_case(SECRET_MARK) {
        return None;
    }
    let end = at + SECRET_MARK.len();
    if let Some(next) = text[end..].chars().next() {
        if next.is_ascii_alphanumeric() || next == '_' {
            return None;
        }
    }
    Some(end)
}

pub fn find_h1(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = from;
    while index < text.len() {
        if !text.is_char_boundary(index) {
            index += 1;
            continue;
        }
        if index + 3 <= bytes.len()
            && bytes[index].eq_ignore_ascii_case(&b'h')
            && bytes[index + 1].eq_ignore_ascii_case(&b'1')
            && bytes[index + 2] == b'_'
        {
            return Some(index);
        }
        let ch = text[index..].chars().next()?;
        index += ch.len_utf8();
    }
    None
}

pub fn is_hold_symbol(byte: u8) -> bool {
    symbol_value(byte).is_some()
}
