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

/// Dash punctuation, U+2212 MINUS SIGN, and U+00AD SOFT HYPHEN.
///
/// Those two marks look like a hyphen and are not `\p{Pd}`. Leaving
/// them out sends the head of an email, or the whole grouped number.
const HYPHEN: &str = r"\p{Pd}\u{2212}\u{00AD}";

fn hyphen_class(rest: &str) -> String {
    let mut class = String::with_capacity(rest.len() + HYPHEN.len() + 2);
    class.push('[');
    class.push_str(rest);
    class.push_str(HYPHEN);
    class.push(']');
    class
}

/// One or more whitespace characters or hyphen marks between cue words.
///
/// `american-express` is still `american express`. An en dash, a minus
/// sign, or a soft hyphen is that same mark. The phrase has no shorter cue.
fn cue_word_gap() -> String {
    format!("{}+", hyphen_class(r"\s"))
}

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
        // `'` and U+2019 belong in the local part (`o'brien@`). Leaving
        // them out starts the match after the mark, so that head is sent.
        // A letter outside ASCII belongs too (`josé@`, `société.fr`),
        // including a decomposed accent. Leaving it out sends the address.
        // A hyphen mark in the local part or a domain label is part of
        // the address. The mark is dash punctuation, a minus sign, or a
        // soft hyphen. Leaving it out sends the head, or the whole
        // address when the mark sits in the domain. The local part does
        // not start on that mark, so a mark between two addresses is not
        // swallowed by the second one.
        Regex::new(
            &r"\b[\p{L}\p{M}0-9._%+'\u{2019}][\p{L}\p{M}0-9._%+{hyphen}'\u{2019}]*@[\p{L}\p{M}0-9][\p{L}\p{M}0-9.{hyphen}]*\.(?:\p{L}\p{M}*){2,}\b"
                .replace("{hyphen}", HYPHEN),
        )
        .expect("email pattern")
    });
    for hit in RE.find_iter(text) {
        out.push(span(TIER_EMAIL, Kind::Email, hit.start(), hit.end()));
    }
}

fn push_phones(text: &str, out: &mut Vec<RawHit>) {
    static NANP: LazyLock<Regex> = LazyLock::new(|| {
        // `+1` may sit against a shaped number with no separator (`+1(416)`
        // or `+1416-555-0123`). A trunk `1` still needs a separator here.
        // Whitespace may sit between `+` and that trunk digit
        // (`+ 1416-555-0123`). Leaving it out sends the digit when the
        // tail is already a phone. A run of `{sep}` still separates groups
        // (`416 - 555 - 0123`). Whitespace may sit inside the area-code
        // parentheses (`( 416 )`), including a non-breaking space. That is
        // still the 3-3-4 number. Leaving the space out sends the digits
        // when there is no leading plus.
        phone_pattern(
            r"(?:\+\s*1{sep}*|1{sep}+)?(?:\(\s*\d{3}\s*\){sep}*\d{3}{sep}+\d{4}|\d{3}{sep}+\d{3}{sep}+\d{4})",
        )
    });
    // `1(416)555-0123`, including spaces inside the parentheses. A bare
    // `1` before more digits is not this form.
    static NANP_TRUNK: LazyLock<Regex> =
        LazyLock::new(|| phone_pattern(r"1\(\s*\d{3}\s*\){sep}*\d{3}{sep}+\d{4}"));
    // Parentheses wrap one group (`+44 (20) 7946 0958`). A trunk zero
    // may sit against the next digits (`+33 (0)1`). A later group may
    // hold more than four digits (`+44 7700 900123`). Five or more
    // digits glued to `)` are still a bare tail (`+44 (20)79460958`).
    // The NANP separator stays without parentheses, so a bare
    // `(416)5550123` is still not a phone. Whitespace may sit between
    // `+` and the country code (`+ 44 20 7946 0958`). Leaving it out
    // sends the number, or leaves the country code when the tail is a
    // 3-3-4. The same space applies to a plus and a digit run
    // (`+ 14165550123`).
    static INTERNATIONAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            &r"\+\s*\d{1,3}(?:{sep}+\d{1,14}){2,6}".replace("{sep}", &international_sep_class()),
        )
        .expect("international phone pattern")
    });
    static PLUS_DIGITS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\+\s*\d{8,15}").expect("plus digits pattern"));
    for hit in NANP.find_iter(text).chain(NANP_TRUNK.find_iter(text)) {
        if digit_bounded(text, hit.start(), hit.end()) {
            out.push(span(TIER_PHONE, Kind::Phone, hit.start(), hit.end()));
        }
    }
    for hit in INTERNATIONAL.find_iter(text) {
        if let Some((start, end)) = international_span(text, hit.start(), hit.end()) {
            out.push(span(TIER_PHONE, Kind::Phone, start, end));
        }
    }
    for hit in PLUS_DIGITS.find_iter(text) {
        if digit_bounded(text, hit.start(), hit.end()) {
            out.push(span(TIER_PHONE, Kind::Phone, hit.start(), hit.end()));
        }
    }
}

fn push_cards(text: &str, out: &mut Vec<RawHit>) {
    static GROUPED: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        // 4-4-4-4-3, 6-13, 4-6-5, 4-6-4, 4-4-4-4, 4-4-4-3, and 4-4-5.
        // Each shape is its own search. One alternation would take a
        // 16-digit card plus a three-digit tail, fail Luhn, and skip
        // the card. The separator is a run of whitespace, dots, or hyphen
        // marks (`4111 - 1111 - 1111 - 1111`, a figure dash, an en dash,
        // a minus sign, or a soft hyphen). Four, four, five is the
        // 13-digit grouping.
        [
            r"\d{4}(?:{sep}+\d{4}){3}{sep}+\d{3}",
            r"\d{6}{sep}+\d{13}",
            r"\d{4}{sep}+\d{6}{sep}+\d{5}",
            r"\d{4}{sep}+\d{6}{sep}+\d{4}",
            r"\d{4}(?:{sep}+\d{4}){3}",
            r"\d{4}(?:{sep}+\d{4}){2}{sep}+\d{3}",
            r"\d{4}{sep}+\d{4}{sep}+\d{5}",
        ]
        .into_iter()
        .map(|pattern| {
            Regex::new(&pattern.replace("{sep}", &hyphen_class(r"\s.")))
                .expect("grouped card pattern")
        })
        .collect()
    });
    static RUN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\d{13,19}").expect("card run pattern"));
    static CUES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        // The mark between cue words may be any whitespace or a hyphen
        // mark. A plain space is not the only mark between `american`
        // and `express`, and that phrase has no shorter cue. Leaving
        // the mark out sends the card.
        let gap = cue_word_gap();
        let mut patterns = vec![
            format!(r"(?i)\bcredit{gap}card\b"),
            format!(r"(?i)\bamerican{gap}express\b"),
            format!(r"(?i)\bmaster{gap}card\b"),
        ];
        for word in [
            "mastercard",
            "visa",
            "amex",
            "debit",
            "carte",
            "cvv",
            "cvc",
            "card",
        ] {
            patterns.push(format!(r"(?i)\b{word}\b"));
        }
        patterns
            .into_iter()
            .map(|pattern| Regex::new(&pattern).expect("card cue"))
            .collect()
    });
    for pattern in GROUPED.iter() {
        for hit in pattern.find_iter(text) {
            if !digit_bounded(text, hit.start(), hit.end()) {
                continue;
            }
            let digits = digits_of(hit.as_str());
            if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
                out.push(span(TIER_CARD, Kind::Card, hit.start(), hit.end()));
            }
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
    // A run of whitespace or a hyphen mark, so `130 - 692 - 544` is
    // still 3-3-3 when the hyphen is a figure dash, an en dash, a
    // minus sign, or a soft hyphen.
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        let sep = hyphen_class(r"\s");
        Regex::new(&format!(r"\d{{3}}{sep}+\d{{3}}{sep}+\d{{3}}|\d{{9}}")).expect("sin pattern")
    });
    static CUES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        // Same mark as a card cue. `social insurance 130692544` stays a
        // SIN when a hyphen, an en dash, or a soft hyphen sits between
        // the words. That phrase has no shorter cue.
        let gap = cue_word_gap();
        let mut patterns = vec![
            format!(r"(?i)\bsocial{gap}insurance\b"),
            format!(r"(?i)\bnuméro{gap}d['’]assurance{gap}sociale\b"),
            format!(r"(?i)\bnumero{gap}d['’]assurance{gap}sociale\b"),
        ];
        for word in ["SIN", "NAS"] {
            patterns.push(format!(r"(?i)\b{word}\b"));
        }
        patterns
            .into_iter()
            .map(|pattern| Regex::new(&pattern).expect("sin cue"))
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
            // AKIA is a long-term access key id. ASIA is the temporary
            // one. Both are 20 characters. Leaving ASIA out sends the id.
            r"\bA(?:K|S)IA[0-9A-Z]{16}\b",
            r"\bghp_[A-Za-z0-9]{36}\b",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
            r"\bgho_[A-Za-z0-9]{36}\b",
            r"\bghu_[A-Za-z0-9]{36}\b",
            r"\bghs_[A-Za-z0-9]{36}\b",
            // The current installation token is `ghs_`, a numeric app id,
            // `_`, and a three-part JWT. `ghs_` plus 36 letters does not
            // match that. The `_` sits against `eyJ`, so the JWT rule
            // does not see it either. Leaving the shape out sends the payload.
            r"\bghs_[0-9]+_[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            r"\bghr_[A-Za-z0-9]{36}\b",
            // A routable token is `glpat-`, a payload of at least 27
            // characters, and a dot tail. The tail is 9 characters, or a
            // 2-character version, a second dot, and that same tail. The
            // payload class stops at the dot, so the tail stays in the
            // clear. A 20-character token has no tail. A following word
            // stays outside it.
            r"\bglpat-(?:[A-Za-z0-9_\-]{27,}(?:\.[0-9a-z]{2}\.[0-9a-z]{9}|\.[0-9a-z]{9})|[A-Za-z0-9_\-]{20,})\b",
            // The other GitLab token prefixes from the token overview.
            // `glpat-` is handled above. `glwt-` is the workspace token.
            // Leaving one of these out sends the token. Longer prefixes
            // come first so `glrtr-` is not cut down to `glrt-`.
            r"\b(?:glagent|glffct|glsoat|glrtr|glcbt|glptt|glimt|gloas|gldt|glft|glrt|glwt)-[A-Za-z0-9_\-]{20,}\b",
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}",
            // App-level tokens are `xapp-`, not `xoxb-`. Rotating tokens are
            // `xoxe.xapp-` or `xoxe.xoxb-`, and the refresh token is `xoxe-`.
            // Leaving the prefix out sends the token.
            r"\bxapp-[A-Za-z0-9-]{10,}\b",
            r"\bxoxe(?:\.xapp|\.xox[baprs])?-[A-Za-z0-9-]{10,}\b",
            // Stripe webhook signing secret. Leaving the prefix out sends it.
            r"\bwhsec_[A-Za-z0-9]{20,}\b",
            r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b",
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            r"\bnpm_[A-Za-z0-9]{36}\b",
            r"\bhf_[A-Za-z0-9]{20,}\b",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
            r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}",
            r"(?s)-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
            // A PGP private key says BLOCK, so the PEM rule above does
            // not see it. Leaving the header out sends the key. A public
            // key block and a PGP message stay as written.
            r"(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
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
    push_assignment_secrets(text, out);
}

// At least 16 token characters. A dot may sit between pieces
// (`abcdefghijklmnop.QRSTUVWXYZ123456`). Leaving that dot out masks
// the head and sends the tail. A dot with nothing after it stays
// outside the value, so a sentence period stays.
const SECRET_RUN: &str =
    r"(?:[A-Za-z0-9+/=_\-]+\.)*[A-Za-z0-9+/=_\-]{16,}(?:\.[A-Za-z0-9+/=_\-]+)*";

/// `api_key`, `secret_key`, `access_token`, and `auth_token`.
///
/// The mark inside `api-key`, `secret-key`, `access-token`, and
/// `auth-token` is an underscore or a hyphen mark. An ASCII hyphen is
/// not the only one. An en dash, a minus sign, or a soft hyphen is
/// still that name. Whitespace between the words is that name too, so
/// `api key` counts. `secret_access_key` is the AWS env name, including
/// spaces or hyphens between the words. Leaving that name out sends the
/// value. A slash or a dot between the words is not this name.
fn assignment_name() -> String {
    let gap = format!("(?:{})*", hyphen_class(r"_\s"));
    r"(?:[A-Za-z0-9_]*_)?(?:api{gap}key|secret{gap}access{gap}key|secret{gap}key|access{gap}token|auth{gap}token)"
        .replace("{gap}", &gap)
}

/// `api_key`, `secret_key`, `access_token`, and `auth_token` assignments.
///
/// `_` is a word character, so a word boundary misses `MY_API_KEY`. The
/// name may have a prefix before that `_`. A JSON key puts a quote between
/// the name and the colon. The character before the name stays outside the span.
fn push_assignment_secrets(text: &str, out: &mut Vec<RawHit>) {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        let name = assignment_name();
        Regex::new(&format!(
            r#"(?i)(?:^|[^A-Za-z0-9_])({name}"?\s*[=:]\s*["']?{SECRET_RUN})"#
        ))
        .expect("secret assignment pattern")
    });
    for caps in RE.captures_iter(text) {
        let Some(hit) = caps.get(1) else {
            continue;
        };
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

/// Length of a secret run at the start of a JSON string value.
///
/// `json_prefix` is the document up to and including that value's opening
/// quote. The key has to be an assignment name, immediately before the colon.
pub(crate) fn assignment_secret_prefix(json_prefix: &str, value: &str) -> Option<usize> {
    static KEY: LazyLock<Regex> = LazyLock::new(|| {
        let name = assignment_name();
        Regex::new(&format!(r#"(?i)(?:^|[^A-Za-z0-9_]){name}"\s*:\s*"$"#))
            .expect("json assignment key")
    });
    static RUN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"^{SECRET_RUN}")).expect("secret run"));
    if !KEY.is_match(json_prefix) {
        return None;
    }
    RUN.find(value).map(|hit| hit.end())
}

/// `{sep}` stands for one phone-group separator.
///
/// The class is whitespace, a dot, a slash, or a hyphen mark, so a
/// figure dash, an en dash, a minus sign, or a soft hyphen counts the
/// same as an ASCII hyphen. Patterns repeat it when the gap may hold
/// more than one, as in `416 - 555 - 0123`.
fn phone_pattern(body: &str) -> Regex {
    Regex::new(&body.replace("{sep}", &hyphen_class(r"\s./"))).expect("phone pattern")
}

fn international_sep_class() -> String {
    hyphen_class(r"\s./()")
}

/// Longest prefix of `text[start..end]` that is one international number.
///
/// The regex match may include a later digit group. Fifteen digits is
/// the longest number kept here. A shorter prefix is used only when the
/// full match is past that, so a tail that still fits stays inside it.
fn international_span(text: &str, start: usize, mut end: usize) -> Option<(usize, usize)> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            &r"^\+\s*\d{1,3}(?:{sep}+\d{1,14}){2,6}$".replace("{sep}", &international_sep_class()),
        )
        .expect("international phone span")
    });
    static TRAIL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&r"{sep}+\d+$".replace("{sep}", &international_sep_class()))
            .expect("phone group tail")
    });
    loop {
        let slice = text.get(start..end)?;
        let digits = digit_count(slice);
        if (8..=15).contains(&digits)
            && digit_bounded(text, start, end)
            && !glued_paren_tail(slice)
            && RE.is_match(slice)
        {
            return Some((start, end));
        }
        if digits <= 15 {
            return None;
        }
        let trail = TRAIL.find(slice)?;
        let next = start + trail.start();
        if next >= end {
            return None;
        }
        end = next;
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

/// Five or more digits glued to `)` are a bare tail, not another group.
///
/// `+44 (20)79460958` is that tail. `+33 (0)1` still has a one-digit
/// group against the parenthesis, and `+44 (0)7700 900123` keeps the
/// space before the long group.
fn glued_paren_tail(text: &str) -> bool {
    let bytes = text.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b')' {
            continue;
        }
        let mut digits = 0usize;
        for next in &bytes[index + 1..] {
            if !next.is_ascii_digit() {
                break;
            }
            digits += 1;
            if digits >= 5 {
                return true;
            }
        }
    }
    false
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
