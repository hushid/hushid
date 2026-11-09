use crate::glossary::Glossary;
use crate::token::Kind;
use regex::Regex;
use std::sync::LazyLock;

/// Higher tiers win. Inside one tier the longer span wins.
const TIER_SECRET: u8 = 0;
const TIER_SIN: u8 = 1;
const TIER_CARD: u8 = 2;
const TIER_EMAIL: u8 = 3;
const TIER_PHONE: u8 = 4;
const TIER_GLOSSARY: u8 = 5;

const CUE_WINDOW: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hit {
    Secret {
        start: usize,
        end: usize,
    },
    Reversible {
        kind: Kind,
        start: usize,
        end: usize,
    },
}

struct RawHit {
    tier: u8,
    start: usize,
    end: usize,
    hit: Hit,
}

impl RawHit {
    fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

pub fn find_hits(text: &str, glossary: &Glossary) -> Vec<Hit> {
    let mut raw = Vec::new();
    push_secrets(text, &mut raw);
    push_sins(text, &mut raw);
    push_cards(text, &mut raw);
    push_emails(text, &mut raw);
    push_phones(text, &mut raw);
    for (start, end) in glossary.find(text) {
        raw.push(RawHit {
            tier: TIER_GLOSSARY,
            start,
            end,
            hit: Hit::Reversible {
                kind: Kind::Glossary,
                start,
                end,
            },
        });
    }
    resolve(raw)
}

fn resolve(mut raw: Vec<RawHit>) -> Vec<Hit> {
    raw.sort_by(|left, right| {
        left.tier
            .cmp(&right.tier)
            .then(right.len().cmp(&left.len()))
            .then(left.start.cmp(&right.start))
    });
    let mut chosen: Vec<RawHit> = Vec::new();
    for hit in raw {
        let overlaps = chosen
            .iter()
            .any(|kept| hit.start < kept.end && kept.start < hit.end);
        if !overlaps {
            chosen.push(hit);
        }
    }
    chosen.sort_by_key(|hit| hit.start);
    chosen.into_iter().map(|hit| hit.hit).collect()
}

fn push_emails(text: &str, out: &mut Vec<RawHit>) {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}\b")
            .expect("email pattern")
    });
    for hit in RE.find_iter(text) {
        out.push(span(TIER_EMAIL, Kind::Email, hit.start(), hit.end()));
    }
}

fn push_phones(text: &str, out: &mut Vec<RawHit>) {
    static NANP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?:\+1[\s.\-]|1[\s.\-])?(?:\(\d{3}\)[\s.\-]\d{3}[\s.\-]\d{4}|\d{3}[\s.\-]\d{3}[\s.\-]\d{4})",
        )
        .expect("nanp pattern")
    });
    static INTERNATIONAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\+\d{1,3}(?:[\s.\-]\d{1,4}){2,6}").expect("international pattern")
    });
    static PLUS_DIGITS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\+\d{8,15}").expect("plus digits pattern"));
    for hit in NANP.find_iter(text) {
        if digit_bounded(text, hit.start(), hit.end()) {
            out.push(span(TIER_PHONE, Kind::Phone, hit.start(), hit.end()));
        }
    }
    for hit in INTERNATIONAL.find_iter(text) {
        let digits = digit_count(hit.as_str());
        if (8..=15).contains(&digits) && digit_bounded(text, hit.start(), hit.end()) {
            out.push(span(TIER_PHONE, Kind::Phone, hit.start(), hit.end()));
        }
    }
    for hit in PLUS_DIGITS.find_iter(text) {
        if digit_bounded(text, hit.start(), hit.end()) {
            out.push(span(TIER_PHONE, Kind::Phone, hit.start(), hit.end()));
        }
    }
}

fn push_cards(text: &str, out: &mut Vec<RawHit>) {
    static GROUPED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\d{4}[\s\-]\d{6}[\s\-]\d{5}|\d{4}(?:[\s\-]\d{4}){3}")
            .expect("grouped card pattern")
    });
    static RUN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\d{13,19}").expect("card run pattern"));
    static CUES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            r"(?i)\bcredit card\b",
            r"(?i)\bamerican express\b",
            r"(?i)\bmaster card\b",
            r"(?i)\bmastercard\b",
            r"(?i)\bvisa\b",
            r"(?i)\bamex\b",
            r"(?i)\bdebit\b",
            r"(?i)\bcarte\b",
            r"(?i)\bcvv\b",
            r"(?i)\bcvc\b",
            r"(?i)\bcard\b",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("card cue"))
        .collect()
    });
    for hit in GROUPED.find_iter(text) {
        if !digit_bounded(text, hit.start(), hit.end()) {
            continue;
        }
        let digits = digits_of(hit.as_str());
        if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
            out.push(span(TIER_CARD, Kind::Card, hit.start(), hit.end()));
        }
    }
    let cues = cue_spans(text, &CUES);
    for hit in RUN.find_iter(text) {
        if !digit_bounded(text, hit.start(), hit.end()) {
            continue;
        }
        let digits = digits_of(hit.as_str());
        if !luhn_ok(&digits) {
            continue;
        }
        if cue_near(&cues, hit.start(), hit.end(), text) {
            out.push(span(TIER_CARD, Kind::Card, hit.start(), hit.end()));
        }
    }
}

fn push_sins(text: &str, out: &mut Vec<RawHit>) {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\d{3}[\s\-]\d{3}[\s\-]\d{3}|\d{9}").expect("sin pattern"));
    static CUES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            r"(?i)\bsocial insurance\b",
            r"(?i)\bnuméro d['’]assurance sociale\b",
            r"(?i)\bnumero d['’]assurance sociale\b",
            r"(?i)\bSIN\b",
            r"(?i)\bNAS\b",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("sin cue"))
        .collect()
    });
    let cues = cue_spans(text, &CUES);
    for hit in RE.find_iter(text) {
        if !digit_bounded(text, hit.start(), hit.end()) {
            continue;
        }
        let digits = digits_of(hit.as_str());
        if digits.len() != 9 || !luhn_ok(&digits) {
            continue;
        }
        if cue_near(&cues, hit.start(), hit.end(), text) {
            out.push(span(TIER_SIN, Kind::Sin, hit.start(), hit.end()));
        }
    }
}

fn push_secrets(text: &str, out: &mut Vec<RawHit>) {
    static RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            r"\bAKIA[0-9A-Z]{16}\b",
            r"\bghp_[A-Za-z0-9]{36}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"\bgho_[A-Za-z0-9]{36}\b",
            r"\bghu_[A-Za-z0-9]{36}\b",
            r"\bghs_[A-Za-z0-9]{36}\b",
            r"\bghr_[A-Za-z0-9]{36}\b",
            r"\bglpat-[A-Za-z0-9_\-]{20,}\b",
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}",
            r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b",
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            r"\bnpm_[A-Za-z0-9]{36}\b",
            r"\bhf_[A-Za-z0-9]{20,}\b",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}",
            r"(?s)-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
            r#"(?i)\b(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["']?[A-Za-z0-9+/=_\-]{16,}"#,
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("secret pattern"))
        .collect()
    });
    for pattern in RES.iter() {
        for hit in pattern.find_iter(text) {
            out.push(RawHit {
                tier: TIER_SECRET,
                start: hit.start(),
                end: hit.end(),
                hit: Hit::Secret {
                    start: hit.start(),
                    end: hit.end(),
                },
            });
        }
    }
}

fn span(tier: u8, kind: Kind, start: usize, end: usize) -> RawHit {
    RawHit {
        tier,
        start,
        end,
        hit: Hit::Reversible { kind, start, end },
    }
}

fn digit_bounded(text: &str, start: usize, end: usize) -> bool {
    if text[..start]
        .chars()
        .next_back()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        return false;
    }
    if text[end..]
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        return false;
    }
    true
}

fn cue_spans(text: &str, cues: &[Regex]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for cue in cues {
        for hit in cue.find_iter(text) {
            spans.push((hit.start(), hit.end()));
        }
    }
    spans
}

fn cue_near(cues: &[(usize, usize)], start: usize, end: usize, text: &str) -> bool {
    cues.iter()
        .any(|(cue_start, cue_end)| edge_gap(*cue_start, *cue_end, start, end, text) <= CUE_WINDOW)
}

fn edge_gap(a0: usize, a1: usize, b0: usize, b1: usize, text: &str) -> usize {
    if a0 < b1 && b0 < a1 {
        return 0;
    }
    let (from, to) = if a1 <= b0 { (a1, b0) } else { (b1, a0) };
    text.get(from..to)
        .map(|gap| gap.chars().count())
        .unwrap_or(usize::MAX)
}

fn digits_of(text: &str) -> Vec<u8> {
    text.bytes().filter(|byte| byte.is_ascii_digit()).collect()
}

fn digit_count(text: &str) -> usize {
    text.chars().filter(|ch| ch.is_ascii_digit()).count()
}

pub(crate) fn luhn_ok(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0;
    let mut alternate = false;
    for byte in digits.iter().rev() {
        let mut value = (byte - b'0') as i32;
        if alternate {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        alternate = !alternate;
    }
    sum % 10 == 0
}
