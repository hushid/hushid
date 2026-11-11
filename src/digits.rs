//! Reversible digits of the same shape.
//!
//! A token fails a card, SIN, or phone format check. This stand-in keeps
//! every non-digit and writes new digits in the same decimal block.
//! Card and SIN digits still pass Luhn. The vault stores the original
//! bytes. The stand-in is minted only for a finished span. There is no
//! streaming shield, so a chunk that cannot see the end of the value
//! stays on the token operator.

use crate::detect::{decimal_digit, luhn_ok};
use crate::token::{Kind, TokenError};

pub(crate) fn digit_kind(kind: Kind) -> bool {
    matches!(kind, Kind::Phone | Kind::Card | Kind::Sin)
}

pub(crate) fn luhn_kind(kind: Kind) -> bool {
    matches!(kind, Kind::Card | Kind::Sin)
}

pub(crate) fn same_shape(surface: &str, luhn: bool) -> Result<String, TokenError> {
    let places: Vec<(u8, u32)> = surface.chars().filter_map(decimal_digit).collect();
    if places.is_empty() || (luhn && places.len() < 2) {
        return Err(TokenError::Payload);
    }
    let mut raw = vec![0u8; places.len()];
    getrandom::fill(&mut raw).map_err(|_| TokenError::Entropy)?;
    let mut values: Vec<u8> = raw.iter().map(|byte| byte % 10).collect();
    if luhn {
        let mut bytes: Vec<u8> = values.iter().map(|value| b'0' + value).collect();
        let last = bytes.len() - 1;
        for value in 0..10 {
            bytes[last] = b'0' + value;
            if luhn_ok(&bytes) {
                values[last] = value;
                break;
            }
        }
    }
    let original: Vec<u8> = places.iter().map(|(value, _)| *value).collect();
    if values == original {
        return Err(TokenError::Digits);
    }
    let mut index = 0;
    let mut out = String::with_capacity(surface.len());
    for ch in surface.chars() {
        if let Some((_, zero)) = decimal_digit(ch) {
            let code = zero + u32::from(values[index]);
            let painted = char::from_u32(code).ok_or(TokenError::Payload)?;
            out.push(painted);
            index += 1;
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}
