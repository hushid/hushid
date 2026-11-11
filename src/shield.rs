use crate::audit::AuditRecord;
use crate::detect::{find_hits, Hit};
use crate::digits::{digit_kind, luhn_kind, same_shape};
use crate::glossary::Glossary;
use crate::token::{Kind, TokenError, SECRET_MARK};
use crate::vault::Vault;

/// How a reversible span is written.
///
/// [`Operator::Token`] is the default. [`Operator::Digits`] keeps the
/// shape of a phone, a card, or a SIN. Email, address, and the other
/// kinds still use a token. A secret still becomes [`SECRET_MARK`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Operator {
    #[default]
    Token,
    /// Reversible digits of the same shape. Used only when the detector
    /// has already closed the span. A stream that cannot see the end of
    /// the value stays on [`Operator::Token`].
    Digits,
}

/// Replace recognized identifiers in `text`.
///
/// Each reversible surface gets its own token, even when the bytes repeat.
/// Secret-shaped spans become [`SECRET_MARK`] and are not stored.
///
/// ```
/// use hushid::{shield_text, Glossary, Vault};
///
/// let mut vault = Vault::new();
/// let (out, audit) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
/// assert_eq!(audit.email, 1);
/// assert!(!out.contains("a@b.co"));
/// assert_eq!(vault.restore_write(&out).unwrap(), "a@b.co");
/// ```
pub fn shield_text(
    vault: &mut Vault,
    glossary: &Glossary,
    text: &str,
) -> Result<(String, AuditRecord), TokenError> {
    shield_text_with(vault, glossary, text, Operator::Token)
}

/// [`shield_text`] with an explicit operator.
pub fn shield_text_with(
    vault: &mut Vault,
    glossary: &Glossary,
    text: &str,
    operator: Operator,
) -> Result<(String, AuditRecord), TokenError> {
    shield_in_context(vault, glossary, "", text, "", operator)
}

/// Shield `text`. `before` and `after` are cue context only.
///
/// A hit is kept only when both edges sit inside `text`, so a cue just
/// outside the value can count without a match that crosses the boundary.
pub(crate) fn shield_in_context(
    vault: &mut Vault,
    glossary: &Glossary,
    before: &str,
    text: &str,
    after: &str,
    operator: Operator,
) -> Result<(String, AuditRecord), TokenError> {
    let mut scan = String::with_capacity(before.len() + text.len() + after.len());
    scan.push_str(before);
    scan.push_str(text);
    scan.push_str(after);
    let origin = before.len();
    let limit = origin + text.len();
    let hits = find_hits(&scan, glossary);
    let mut audit = AuditRecord::default();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for hit in hits {
        let (start, end) = span_of(&hit);
        if start < origin || end > limit {
            continue;
        }
        let start = start - origin;
        let end = end - origin;
        if start < cursor {
            continue;
        }
        out.push_str(&text[cursor..start]);
        match hit {
            Hit::Secret { .. } => {
                out.push_str(SECRET_MARK);
                audit.secret += 1;
            }
            Hit::Reversible { kind, .. } => {
                let surface = &text[start..end];
                let replacement = if operator == Operator::Digits && digit_kind(kind) {
                    mint_digits(vault, kind, surface)?
                } else {
                    vault.issue(kind, surface.as_bytes())?
                };
                out.push_str(&replacement);
                audit.bump(kind);
            }
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Ok((out, audit))
}

fn mint_digits(vault: &mut Vault, kind: Kind, surface: &str) -> Result<String, TokenError> {
    let luhn = luhn_kind(kind);
    for _ in 0..16 {
        let stand_in = match same_shape(surface, luhn) {
            Ok(stand_in) => stand_in,
            Err(TokenError::Digits) => continue,
            Err(err) => return Err(err),
        };
        match vault.issue_digits(kind, surface.as_bytes(), &stand_in) {
            Ok(shown) => return Ok(shown),
            Err(TokenError::Digits) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(TokenError::Digits)
}

fn span_of(hit: &Hit) -> (usize, usize) {
    match *hit {
        Hit::Secret { start, end } => (start, end),
        Hit::Reversible { start, end, .. } => (start, end),
    }
}
