//! Accidental copies of a surface this vault already knows.
//!
//! Base64 and a short `echo` or `printf` of those bytes are the same
//! disclosure as the original surface. A hostile encoding is not a target.
//! Spans that already overlap a detector hit are left to that hit.

use crate::detect::Hit;
use crate::token::{parse_token_at, Kind};
use crate::vault::Vault;

const MIN_LEN: usize = 6;

pub(crate) fn extra_hits(text: &str, hits: &[Hit], vault: &Vault) -> Vec<Hit> {
    let mut surfaces = Vec::new();
    for hit in hits {
        if let Hit::Reversible { kind, start, end } = hit {
            if let Some(surface) = text.get(*start..*end) {
                remember(&mut surfaces, *kind, surface);
            }
        }
    }
    for (token, surface) in vault.known_surfaces() {
        if let Some(parsed) = parse_token_at(&token, 0) {
            remember(&mut surfaces, parsed.kind, &surface);
        }
    }
    let mut extras = Vec::new();
    for (kind, surface) in surfaces {
        if surface.chars().count() < MIN_LEN || surface.contains('\n') {
            continue;
        }
        for needle in encodings(&surface) {
            push_bounded(text, &needle, kind, hits, &mut extras);
        }
        push_commands(text, &surface, kind, hits, &mut extras);
    }
    extras
}

fn remember(surfaces: &mut Vec<(Kind, String)>, kind: Kind, surface: &str) {
    if surfaces
        .iter()
        .any(|(have, text)| *have == kind && text == surface)
    {
        return;
    }
    surfaces.push((kind, surface.to_string()));
}

fn encodings(surface: &str) -> Vec<String> {
    if surface.len() < 8 {
        return Vec::new();
    }
    let standard = base64(surface.as_bytes(), false);
    let url = base64(surface.as_bytes(), true);
    let mut out = vec![standard.clone()];
    if url != standard {
        out.push(url.clone());
    }
    if let Some(stripped) = standard.strip_suffix('=') {
        let stripped = stripped.strip_suffix('=').unwrap_or(stripped);
        if !stripped.is_empty() && stripped != standard {
            out.push(stripped.to_string());
        }
    }
    out
}

fn push_bounded(text: &str, needle: &str, kind: Kind, hits: &[Hit], extras: &mut Vec<Hit>) {
    if needle.is_empty() {
        return;
    }
    let mut from = 0;
    while let Some(found) = text.get(from..).and_then(|rest| rest.find(needle)) {
        let start = from + found;
        let end = start + needle.len();
        if bounded_base64(text, start, end)
            && !overlaps(hits, start, end)
            && !overlaps(extras, start, end)
        {
            extras.push(Hit::Reversible { kind, start, end });
        }
        let next = end;
        if next <= from {
            break;
        }
        from = next;
    }
}

fn push_commands(text: &str, surface: &str, kind: Kind, hits: &[Hit], extras: &mut Vec<Hit>) {
    for prefix in [
        "echo ",
        "echo \"",
        "echo '",
        "printf ",
        "printf \"",
        "printf '",
        "printf %s ",
        "printf %s \"",
        "printf %s '",
    ] {
        let mut from = 0;
        let pattern = format!("{prefix}{surface}");
        while let Some(found) = text.get(from..).and_then(|rest| rest.find(&pattern)) {
            let start = from + found + prefix.len();
            let end = start + surface.len();
            let command_at = from + found;
            if command_bounded(text, command_at)
                && quote_closes(text, end, prefix)
                && !overlaps(hits, start, end)
                && !overlaps(extras, start, end)
            {
                extras.push(Hit::Reversible { kind, start, end });
            }
            let next = end;
            if next <= from {
                break;
            }
            from = next;
        }
    }
}

fn command_bounded(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .next_back()
        .is_none_or(|ch| ch.is_whitespace() || ch == ';' || ch == '\n')
}

fn quote_closes(text: &str, end: usize, prefix: &str) -> bool {
    let closer = if prefix.ends_with('"') {
        Some('"')
    } else if prefix.ends_with('\'') {
        Some('\'')
    } else {
        None
    };
    match closer {
        Some(quote) => text[end..].starts_with(quote),
        None => text[end..]
            .chars()
            .next()
            .is_none_or(|ch| ch.is_whitespace()),
    }
}

fn bounded_base64(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    before.is_none_or(|ch| !is_b64(ch)) && after.is_none_or(|ch| !is_b64(ch))
}

fn is_b64(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '-' | '_' | '=')
}

fn overlaps(hits: &[Hit], start: usize, end: usize) -> bool {
    hits.iter().any(|hit| {
        let (hit_start, hit_end) = match hit {
            Hit::Secret { start, end } | Hit::Reversible { start, end, .. } => (*start, *end),
        };
        start < hit_end && hit_start < end
    })
}

fn base64(data: &[u8], url: bool) -> String {
    const STANDARD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = if url { URL } else { STANDARD };
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let chunk = (u32::from(data[index]) << 16)
            | (u32::from(data[index + 1]) << 8)
            | u32::from(data[index + 2]);
        out.push(alphabet[((chunk >> 18) & 63) as usize] as char);
        out.push(alphabet[((chunk >> 12) & 63) as usize] as char);
        out.push(alphabet[((chunk >> 6) & 63) as usize] as char);
        out.push(alphabet[(chunk & 63) as usize] as char);
        index += 3;
    }
    let rest = data.len() - index;
    if rest == 1 {
        let chunk = u32::from(data[index]) << 16;
        out.push(alphabet[((chunk >> 18) & 63) as usize] as char);
        out.push(alphabet[((chunk >> 12) & 63) as usize] as char);
        if !url {
            out.push('=');
            out.push('=');
        }
    } else if rest == 2 {
        let chunk = (u32::from(data[index]) << 16) | (u32::from(data[index + 1]) << 8);
        out.push(alphabet[((chunk >> 18) & 63) as usize] as char);
        out.push(alphabet[((chunk >> 12) & 63) as usize] as char);
        out.push(alphabet[((chunk >> 6) & 63) as usize] as char);
        if !url {
            out.push('=');
        }
    }
    out
}
