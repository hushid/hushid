use crate::audit::AuditRecord;
use crate::detect::{find_hits, Hit};
use crate::digits::{digit_kind, luhn_kind, same_shape};
use crate::glossary::Glossary;
use crate::rewrite;
use crate::surrogate;
use crate::token::{Kind, TokenError, SECRET_MARK};
use crate::vault::Vault;

#[cfg(feature = "ner")]
use crate::ner::Ner;

/// Which name model, if any, runs after the glossary.
///
/// The default build has only [`Names::Off`]. A glossary hit remains the
/// only name match in that build.
pub enum Names<'a> {
    Off,
    #[cfg(feature = "ner")]
    On(&'a Ner),
    #[cfg(not(feature = "ner"))]
    #[allow(dead_code)]
    Marker(std::marker::PhantomData<&'a ()>),
}

/// How a reversible span is written.
///
/// [`Operator::Token`] is the default. [`Operator::Digits`] keeps the
/// shape of a phone, a card, or a SIN. [`Operator::Surrogate`] writes a
/// stand-in of the same kind so the sentence still reads.
/// [`Operator::Mask`] is for a display or a log and is not restored.
/// Email, address, and the other kinds still use a token under
/// [`Operator::Digits`]. A secret still becomes [`SECRET_MARK`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Operator {
    #[default]
    Token,
    /// Reversible digits of the same shape. Used only when the detector
    /// has already closed the span. A stream that cannot see the end of
    /// the value stays on [`Operator::Token`].
    Digits,
    /// A reversible stand-in of the same kind. The vault still stores the
    /// original bytes. A stream that cannot see the end of the value stays
    /// on [`Operator::Token`].
    Surrogate,
    /// Irreversible display text. The original bytes are not stored.
    Mask,
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
    shield_in_context(vault, glossary, "", text, "", operator, Names::Off)
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
    names: Names<'_>,
) -> Result<(String, AuditRecord), TokenError> {
    let mut scan = String::with_capacity(before.len() + text.len() + after.len());
    scan.push_str(before);
    scan.push_str(text);
    scan.push_str(after);
    let origin = before.len();
    let limit = origin + text.len();
    let mut hits = find_hits(&scan, glossary);
    let extras = rewrite::extra_hits(&scan, &hits, vault);
    hits.extend(extras);
    #[cfg(feature = "ner")]
    if let Names::On(ner) = names {
        let found = ner.find(&scan);
        let fresh = found
            .into_iter()
            .filter(|hit| !hit_overlaps(&hits, hit))
            .collect::<Vec<_>>();
        hits.extend(fresh);
    }
    #[cfg(not(feature = "ner"))]
    let _ = names;
    hits.sort_by_key(|hit| hit_span(hit).0);
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
                let replacement = match operator {
                    Operator::Digits if digit_kind(kind) => mint_digits(vault, kind, surface)?,
                    Operator::Surrogate => mint_surrogate(vault, kind, surface)?,
                    Operator::Mask => mask_for(kind, surface),
                    Operator::Token | Operator::Digits => vault.issue(kind, surface.as_bytes())?,
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

fn mint_surrogate(vault: &mut Vault, kind: Kind, surface: &str) -> Result<String, TokenError> {
    for _ in 0..16 {
        let stand_in = match surrogate::mint(kind, surface) {
            Ok(stand_in) => stand_in,
            Err(TokenError::Surrogate) => continue,
            Err(err) => return Err(err),
        };
        match vault.issue_digits(kind, surface.as_bytes(), &stand_in) {
            Ok(shown) => return Ok(shown),
            Err(TokenError::Digits) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(TokenError::Surrogate)
}

fn mask_for(kind: Kind, surface: &str) -> String {
    let mask = match kind {
        Kind::Email => "***@***",
        Kind::Phone => "***-***-****",
        Kind::Card => "**** **** **** ****",
        Kind::Sin => "*** *** ***",
        Kind::Ramq => "**** **** ****",
        Kind::Postal => "*** ***",
        Kind::Address => "***",
        Kind::Birth => "*** *** ***",
        Kind::Glossary => "***",
    };
    if surface == mask {
        format!("({mask})")
    } else {
        mask.to_string()
    }
}

fn hit_span(hit: &Hit) -> (usize, usize) {
    match hit {
        Hit::Secret { start, end } => (*start, *end),
        Hit::Reversible { start, end, .. } => (*start, *end),
    }
}

#[cfg(feature = "ner")]
fn hit_overlaps(hits: &[Hit], hit: &Hit) -> bool {
    let (start, end) = hit_span(hit);
    hits.iter().any(|have| {
        let (have_start, have_end) = hit_span(have);
        start < have_end && have_start < end
    })
}

fn span_of(hit: &Hit) -> (usize, usize) {
    match *hit {
        Hit::Secret { start, end } => (start, end),
        Hit::Reversible { start, end, .. } => (start, end),
    }
}
