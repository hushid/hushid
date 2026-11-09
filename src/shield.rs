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
    let hits = find_hits(text, glossary);
    let mut audit = AuditRecord::default();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for hit in hits {
        let (start, end) = span_of(&hit);
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
