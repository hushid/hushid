//! A reversible stand-in of the same kind.
//!
//! A token such as `h1_email_` breaks a sentence. This stand-in reads as
//! that kind and is not the original bytes. A phone, a card, and a SIN
//! keep the original separators and the original digit count. The vault
//! stores those bytes.
//! A secret still becomes `h1_secret` and is not stored. The stand-in is
//! minted only for a finished span.

use crate::digits::{luhn_kind, same_shape};
use crate::token::{Kind, TokenError};

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const POSTAL_LETTERS: &[u8] = b"ABCEGHJKLMNPRSTVXY";
const NAME_CONSONANTS: &[u8] = b"BCDFGHJKLMNPQRSTV";
const NAME_VOWELS: &[u8] = b"AEIOU";

pub(crate) fn mint(kind: Kind, surface: &str) -> Result<String, TokenError> {
    for _ in 0..16 {
        let raw = random_bytes(8)?;
        let stand_in = match paint(kind, surface, &raw) {
            Ok(stand_in) => stand_in,
            Err(TokenError::Digits) => continue,
            Err(err) => return Err(err),
        };
        if acceptable(surface, &stand_in) {
            return Ok(stand_in);
        }
    }
    Err(TokenError::Surrogate)
}

fn paint(kind: Kind, surface: &str, raw: &[u8]) -> Result<String, TokenError> {
    match kind {
        Kind::Email => Ok(email(raw)),
        Kind::Phone | Kind::Card | Kind::Sin => same_shape(surface, luhn_kind(kind)),
        Kind::Ramq => Ok(ramq(raw)),
        Kind::Postal => Ok(postal(raw)),
        Kind::Address => Ok(address(raw)),
        Kind::Birth => Ok(birth(raw)),
        Kind::Glossary => Ok(name(raw)),
    }
}

fn acceptable(surface: &str, stand_in: &str) -> bool {
    if stand_in.is_empty() || stand_in.contains("h1_") {
        return false;
    }
    if stand_in.eq_ignore_ascii_case(surface) {
        return false;
    }
    // A one-letter name sits inside every generated stand-in.
    if surface.chars().count() >= 3 && (surface.contains(stand_in) || stand_in.contains(surface)) {
        return false;
    }
    digits_of(surface) != digits_of(stand_in) || digits_of(surface).is_empty()
}

fn digits_of(text: &str) -> String {
    text.chars().filter(|ch| ch.is_ascii_digit()).collect()
}

fn email(raw: &[u8]) -> String {
    let local: String = raw
        .iter()
        .map(|byte| char::from(b'a' + (byte % 26)))
        .collect();
    format!("{local}@example.org")
}

fn ramq(raw: &[u8]) -> String {
    let letters: String = raw[..4]
        .iter()
        .map(|byte| char::from(b'A' + (byte % 26)))
        .collect();
    let month = (raw[4] % 12) + 1;
    let day = (raw[5] % 28) + 1;
    let tail = (usize::from(raw[6]) << 8 | usize::from(raw[7])) % 10_000;
    format!("{letters} {month:02}{day:02} {tail:04}")
}

fn postal(raw: &[u8]) -> String {
    let letter = |byte: u8| char::from(POSTAL_LETTERS[(byte as usize) % POSTAL_LETTERS.len()]);
    let digit = |byte: u8| char::from(b'0' + (byte % 10));
    format!(
        "{}{}{} {}{}{}",
        letter(raw[0]),
        digit(raw[1]),
        letter(raw[2]),
        digit(raw[3]),
        letter(raw[4]),
        digit(raw[5])
    )
}

fn address(raw: &[u8]) -> String {
    let number = 1000 + ((usize::from(raw[0]) << 8 | usize::from(raw[1])) % 8000);
    format!("{number} Example Lane")
}

fn birth(raw: &[u8]) -> String {
    let day = (raw[0] % 28) + 1;
    let month = MONTHS[(raw[1] as usize) % MONTHS.len()];
    let year = 1920 + u16::from(raw[2] % 80);
    format!("{day} {month} {year}")
}

fn name(raw: &[u8]) -> String {
    let mut out = String::with_capacity(8);
    for index in 0..4 {
        let consonant = NAME_CONSONANTS[(raw[index * 2] as usize) % NAME_CONSONANTS.len()] as char;
        let vowel = char::from(NAME_VOWELS[(raw[index * 2 + 1] as usize) % NAME_VOWELS.len()]);
        if index == 0 {
            out.push(consonant);
        } else {
            out.push(consonant.to_ascii_lowercase());
        }
        out.push(vowel.to_ascii_lowercase());
    }
    out
}

fn random_bytes(len: usize) -> Result<Vec<u8>, TokenError> {
    let mut raw = vec![0u8; len];
    getrandom::fill(&mut raw).map_err(|_| TokenError::Entropy)?;
    Ok(raw)
}
