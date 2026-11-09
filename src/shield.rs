use crate::audit::AuditRecord;
use crate::detect::{find_hits, Hit};
use crate::glossary::Glossary;
use crate::token::{TokenError, SECRET_MARK};
use crate::vault::Vault;

/// Replace recognized identifiers in `text`.
///
/// Each reversible surface gets its own token, even when the bytes repeat.
/// Secret-shaped spans become [`SECRET_MARK`] and are not stored.
pub fn shield_text(
    vault: &mut Vault,
    glossary: &Glossary,
    text: &str,
) -> Result<(String, AuditRecord), TokenError> {
    shield_in_context(vault, glossary, "", text, "")
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
                let token = vault.issue(kind, surface.as_bytes())?;
                out.push_str(&token);
                audit.bump(kind);
            }
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    Ok((out, audit))
}

fn span_of(hit: &Hit) -> (usize, usize) {
    match *hit {
        Hit::Secret { start, end } => (start, end),
        Hit::Reversible { start, end, .. } => (start, end),
    }
}
