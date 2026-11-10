use crate::glossary::Glossary;
use crate::token::Kind;
use regex::Regex;
use std::sync::LazyLock;

/// Higher tiers win. Inside one tier the longer span wins.
const TIER_SECRET: u8 = 0;
const TIER_SIN: u8 = 1;
const TIER_RAMQ: u8 = 2;
const TIER_CARD: u8 = 3;
const TIER_EMAIL: u8 = 4;
const TIER_PHONE: u8 = 5;
const TIER_GLOSSARY: u8 = 6;

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

/// One or more whitespace characters, dots, or hyphen marks between cue words.
///
/// `american-express` and `social.insurance` are still those phrases.
/// An en dash, a minus sign, or a soft hyphen is that same mark. A dot
/// is that mark too, including the fullwidth full stop. Leaving the
/// dot out sends the number. The phrase has no shorter cue.
fn cue_word_gap() -> String {
    format!("{}+", hyphen_class(r"\s.\u{FF0E}"))
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
    push_ramq(text, &mut raw);
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

/// ASCII `@`, the fullwidth commercial at U+FF20, and the small
/// commercial at U+FE6B.
///
/// A small commercial at is that sign. Leaving it out sends the address.
/// The local part still does not start on the sign.
const AT: &str = r"[@\u{FF20}\u{FE6B}]";

/// ASCII `.` and the fullwidth full stop, U+FF0E, outside a character class.
///
/// A wide keyboard writes that stop where a dot already separates a
/// value. Leaving it out sends the value. Inside a class the same
/// character is `\u{FF0E}` beside `.`.
const DOT: &str = r"(?:\.|\u{FF0E})";

/// ASCII digits and fullwidth digits U+FF10 through U+FF19, inside a class.
///
/// A wide keyboard writes `１` where an address already allows `1`.
/// Leaving that digit out sends the address. The final label stays
/// letters only, so a digit glued to it is still outside the address.
const DIGIT: &str = r"0-9\u{FF10}-\u{FF19}";

fn push_emails(text: &str, out: &mut Vec<RawHit>) {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        // `'` , U+2019, and U+2018 belong in the local part (`o'brien@`).
        // U+2018 is the left single quote. Leaving it out starts the
        // match after the mark, so that head is sent.
        // A letter outside ASCII belongs too (`josé@`, `société.fr`),
        // including a decomposed accent. Leaving it out sends the address.
        // A hyphen mark in the local part or a domain label is part of
        // the address. The mark is dash punctuation, a minus sign, or a
        // soft hyphen. Leaving it out sends the head, or the whole
        // address when the mark sits in the domain. The local part does
        // not start on that mark, so a mark between two addresses is not
        // swallowed by the second one.
        // The at-sign may be ASCII `@` or the fullwidth sign. A wide
        // keyboard writes U+FF20. Leaving it out sends the address.
        // The dot may be ASCII `.` or the fullwidth stop U+FF0E. That
        // keyboard writes the stop in the local part and the domain.
        // Leaving it out sends the address.
        // An ideographic full stop is that same dot. Leaving it out sends the address.
        // A halfwidth ideographic full stop is that same dot. Leaving it out sends the address.
        // A digit in the local part or the domain may be fullwidth,
        // U+FF10 through U+FF19. That keyboard writes `user１@`.
        // Leaving it out sends the address. A digit glued to the final
        // label stays outside it, same as `user@example.co1`.
        // A plus in the local part may be the fullwidth sign. That
        // keyboard writes `user＋tag@`. Leaving it out sends the head
        // and keeps the tail. The sign is not part of the domain.
        // A fullwidth low line is that underscore. Leaving it out sends the head of the address.
        Regex::new(
            &r"\b[\p{L}\p{M}{digit}.\u{FF0E}\u{3002}\u{FF61}_\u{FF3F}%{plus}'\u{2018}\u{2019}][\p{L}\p{M}{digit}.\u{FF0E}\u{3002}\u{FF61}_\u{FF3F}%{plus}{hyphen}'\u{2018}\u{2019}]*{at}[\p{L}\p{M}{digit}][\p{L}\p{M}{digit}.\u{FF0E}\u{3002}\u{FF61}{hyphen}]*{dot}(?:\p{L}\p{M}*){2,}\b"
                .replace("{digit}", DIGIT)
                .replace("{hyphen}", HYPHEN)
                .replace("{plus}", r"+\u{FF0B}")
                .replace("{at}", AT)
                .replace("{dot}", r"(?:\.|\u{FF0E}|\u{3002}|\u{FF61})"),
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
        // parentheses (`( 416 )`), including a non-breaking space. A wide
        // keyboard writes those parentheses as fullwidth marks. That is
        // still the 3-3-4 number. Leaving the space, or the fullwidth
        // mark, out sends the digits when there is no leading plus.
        // A `00` dialing prefix is that same plus (`001416-555-0123`).
        // Leaving it out sends the number. A bare digit run after `00`
        // is not this shape. A phone separator may sit between that
        // prefix and the trunk (`00-1416-555-0123`). Whitespace already
        // may. Leaving the mark out sends the number. `011` is that
        // same prefix.
        phone_pattern(
            r"(?:{plus}\s*1{sep}*|{idd}{sep}*1{sep}*|1{sep}+)?(?:{open}\s*\d{3}\s*{close}{sep}*\d{3}{sep}+\d{4}|\d{3}{sep}+\d{3}{sep}+\d{4})",
        )
    });
    // `1(416)555-0123`, including spaces inside the parentheses. A bare
    // `1` before more digits is not this form. A fullwidth parenthesis
    // is that same mark.
    static NANP_TRUNK: LazyLock<Regex> =
        LazyLock::new(|| phone_pattern(r"1{open}\s*\d{3}\s*{close}{sep}*\d{3}{sep}+\d{4}"));
    // Parentheses wrap one group (`+44 (20) 7946 0958`). A fullwidth
    // parenthesis is that same mark. A trunk zero may sit against the
    // next digits (`+33 (0)1`). A later group may
    // hold more than four digits (`+44 7700 900123`). Five or more
    // digits glued to `)`, `）`, or `﹚` are still a bare tail
    // (`+44 (20)79460958`).
    // The NANP separator stays without parentheses, so a bare
    // `(416)5550123` is still not a phone. Whitespace may sit between
    // `+` and the country code (`+ 44 20 7946 0958`). Leaving it out
    // sends the number, or leaves the country code when the tail is a
    // 3-3-4. The same space applies to a plus and a digit run
    // (`+ 14165550123`). A fullwidth plus is that same sign.
    // A `00` dialing prefix is that same plus (`0044 20 7946 0958`).
    // The two zeros are not digits of the number. Leaving the prefix
    // out sends it. A bare run after `00` stays as written. The mark
    // between the prefix and the country code is the same separator
    // as between groups (`00-44-20-7946-0958`). Whitespace already
    // may. Leaving it out sends the number, or leaves the prefix when
    // the tail is already a phone (`00-1-416-555-0123`). A plus still
    // takes only whitespace before the country code.
    static INTERNATIONAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            &r"(?:{plus}\s*|{idd}{sep}*)\d{1,3}(?:{sep}+\d{1,14}){2,6}"
                .replace("{sep}", &international_sep_class())
                .replace("{plus}", PLUS)
                .replace("{idd}", IDD),
        )
        .expect("international phone pattern")
    });
    static PLUS_DIGITS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&r"{plus}\s*\d{8,15}".replace("{plus}", PLUS)).expect("plus digits pattern")
    });
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
        // a minus sign, or a soft hyphen). A slash is that separator
        // too. A phone already treats it as one. Leaving it out sends
        // `4111/1111/1111/1111`. A fullwidth solidus is that slash.
        // Leaving it out sends the same card. A fullwidth full stop is
        // that dot. Leaving it out sends the card when the stops are wide.
        // Four, four, five is the 13-digit grouping.
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
            // A middle dot is that separator. A fullwidth solidus is the
            // slash above. Leaving either mark out sends the number.
            // A halfwidth middle dot is that separator. Leaving it out
            // sends the number.
            // A comma is that separator. Leaving it out sends the number.
            // An ideographic comma is that separator. Leaving it out sends the number.
            Regex::new(&pattern.replace(
                "{sep}",
                &hyphen_class(
                    r"\s./\u{FF0F}\u{FF0E}\u{30FB}\u{00B7}\u{FF65},\u{FF0C}\u{3001}\u{FF64}",
                ),
            ))
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
    // A run of whitespace, a dot, or a hyphen mark, so `130 - 692 - 544`
    // is still 3-3-3 when the hyphen is a figure dash, an en dash, a
    // minus sign, or a soft hyphen. `130.692.544` is that same number.
    // A card and a phone already treat a dot as a separator, including
    // the fullwidth full stop. Leaving the dot out sends the digits.
    // A slash is not this separator. A fullwidth solidus is not one either.
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        // A middle dot is that separator. Leaving it out sends the number.
        // A halfwidth middle dot is that separator. Leaving it out
        // sends the number.
        let sep = hyphen_class(r"\s.\u{FF0E}\u{30FB}\u{00B7}\u{FF65}");
        Regex::new(&format!(r"\d{{3}}{sep}+\d{{3}}{sep}+\d{{3}}|\d{{9}}")).expect("sin pattern")
    });
    static CUES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        // Same mark as a card cue. `social insurance 130692544` stays a
        // SIN when a hyphen, an en dash, or a soft hyphen sits between
        // the words. That phrase has no shorter cue. U+2018 in
        // `d'assurance` is the left single quote. Leaving it out sends
        // the number. The é in `numéro` may be e and a combining acute.
        // Leaving that form out sends the number.
        let gap = cue_word_gap();
        let mut patterns = vec![
            format!(r"(?i)\bsocial{gap}insurance\b"),
            format!(r"(?i)\bnum(?:é|e\u{{0301}})ro{gap}d['’\u{{2018}}]assurance{gap}sociale\b"),
            format!(r"(?i)\bnumero{gap}d['’\u{{2018}}]assurance{gap}sociale\b"),
            // `de l'assurance` is that same cue. Leaving it out sends the number.
            format!(
                r"(?i)\bnum(?:é|e\u{{0301}})ro{gap}de{gap}l['’\u{{2018}}]assurance{gap}sociale\b"
            ),
            format!(r"(?i)\bnumero{gap}de{gap}l['’\u{{2018}}]assurance{gap}sociale\b"),
            // `n°` and `nº` are that same cue. Leaving the sign out sends the number.
            format!(r"(?i)\bn[\u{{00B0}}\u{{00BA}}]{gap}d['’\u{{2018}}]assurance{gap}sociale\b"),
        ];
        // `S.I.N.` and `N.A.S.` are the same cues as `SIN` and `NAS`.
        // A dot, a space, or a space and a dot may sit between the letters.
        // The dot may be the fullwidth full stop. Leaving that out sends
        // the number. The trailing dot is optional. `S.I.NISTER` is not
        // this cue.
        for (word, dotted) in [
            (
                "SIN",
                format!(r"S(?:\s*{dot}\s*|\s+)I(?:\s*{dot}\s*|\s+)N", dot = DOT),
            ),
            (
                "NAS",
                format!(r"N(?:\s*{dot}\s*|\s+)A(?:\s*{dot}\s*|\s+)S", dot = DOT),
            ),
        ] {
            patterns.push(format!(r"(?i)\b{word}\b"));
            patterns.push(format!(r"(?i)\b{dotted}\b{dot}?", dot = DOT));
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

fn push_ramq(text: &str, out: &mut Vec<RawHit>) {
    // A Québec health insurance number is 4 letters and 8 digits.
    // The printed form is `AAAA 9999 9999`. A hyphen between those
    // groups is the same number. The 8 digits are year, month, day,
    // and an administrative code. The month is 01 through 12, or 51
    // through 62. The day is 01 through 31. A month or a day outside
    // that range stays as written. These checks are the published
    // layout. They do not ask RAMQ whether the number was issued.
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b[A-Z]{4}(?:[ \t-]+[0-9]{4}){2}\b|\b[A-Z]{4}[0-9]{8}\b")
            .expect("ramq pattern")
    });
    for hit in RE.find_iter(text) {
        if !digit_bounded(text, hit.start(), hit.end()) {
            continue;
        }
        if ramq_layout_ok(hit.as_str()) {
            out.push(span(TIER_RAMQ, Kind::Ramq, hit.start(), hit.end()));
        }
    }
}

fn ramq_layout_ok(text: &str) -> bool {
    let letters = text.chars().filter(|ch| ch.is_ascii_uppercase()).count();
    let digits = digits_of(text);
    if letters != 4 || digits.len() != 8 {
        return false;
    }
    let month = (digits[2] - b'0') * 10 + (digits[3] - b'0');
    let day = (digits[4] - b'0') * 10 + (digits[5] - b'0');
    let month_ok = (1u8..=12).contains(&month) || (51u8..=62).contains(&month);
    let day_ok = (1u8..=31).contains(&day);
    month_ok && day_ok
}

fn push_secrets(text: &str, out: &mut Vec<RawHit>) {
    static RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            // AKIA is a long-term access key id. ASIA is the temporary
            // one. Both are 20 characters. Leaving ASIA out sends the id.
            r"\bA(?:K|S)IA[0-9A-Z]{16}\b",
            // ABIA and ACCA are the other 20-character access key id
            // prefixes in the gitleaks aws-access-token rule. A3T plus
            // one letter and 16 characters from the AWS alphabet is
            // the same id. Leaving them out sends the id. The value
            // is not stored. A shorter id stays as written.
            r"\b(?:ABIA|ACCA)[0-9A-Z]{16}\b",
            r"\bA3T[0-9A-Z][A-Z2-7]{16}\b",
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
            // A GitLab runner registration token is `GR1348941` plus
            // 20 letters, digits, underscores, or hyphens. gitleaks
            // gitlab-rrt. The glrt- alternation does not match this
            // prefix. A final hyphen is not a word boundary. A shorter
            // body stays as written. The value is not stored.
            r"\bGR1348941(?:[A-Za-z0-9_-]{19}[A-Za-z0-9_]\b|[A-Za-z0-9_-]{19}-)",
            // Session tokens are `xoxc-` and `xoxd-`. Leaving `c` or `d`
            // out sends the token. A short payload stays as written.
            r"\bxox[abcdprs]-[0-9A-Za-z-]{10,}",
            // App-level tokens are `xapp-`, not `xoxb-`. Rotating tokens are
            // `xoxe.xapp-` or `xoxe.xoxb-`, and the refresh token is `xoxe-`.
            // Leaving the prefix out sends the token.
            r"\bxapp-[A-Za-z0-9-]{10,}\b",
            r"\bxoxe(?:\.xapp|\.xox[baprs])?-[A-Za-z0-9-]{10,}\b",
            // Workflow tokens are `xwfp-`. Leaving that prefix out sends
            // the token. The payload alphabet and the 10-character minimum
            // match `xoxb-`. A short payload stays as written.
            r"\bxwfp-[0-9A-Za-z-]{10,}",
            // A Slack webhook is hooks.slack.com, then services,
            // workflows, or triggers, then 43 to 56 token characters.
            // gitleaks slack-webhook-url. The xox rules above do not
            // see that host. A final `+` or `/` is not a word
            // boundary. A shorter path stays as written. A longer
            // path of only letters stays too. The value is not stored.
            r"https?://hooks\.slack\.com/(?:services|workflows|triggers)/(?:[A-Za-z0-9+/]{42,55}[A-Za-z0-9]\b|[A-Za-z0-9+/]{42,55}[+/])",
            r"hooks\.slack\.com/(?:services|workflows|triggers)/(?:[A-Za-z0-9+/]{42,55}[A-Za-z0-9]\b|[A-Za-z0-9+/]{42,55}[+/])",
            // Stripe webhook signing secret. Leaving the prefix out sends it.
            r"\bwhsec_[A-Za-z0-9]{20,}\b",
            r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,}\b",
            // An organization key is `sk_org_`. The rule above requires
            // `live` or `test`, so this key stays in the clear. The body
            // is letters only, at least 10, like `sk_live_`. A short
            // payload stays as written. There is no `rk_org_` prefix.
            r"\bsk_org_[0-9A-Za-z]{10,}\b",
            // An ephemeral key is `ek_test_` or `ek_live_`. The published
            // secret is 71 letters, an underscore, and 10 more. The same
            // tail follows a body of 76, 86, or 92 letters. A shorter key
            // is letters only, at least 10, like `sk_live_`. The rule
            // above stops at the underscore, so that secret stays in the
            // clear. A short payload stays as written. A body of another
            // length, once it contains an underscore, stays too.
            r"\bek_(?:live|test)_(?:(?:[A-Za-z0-9]{71}|[A-Za-z0-9]{76}|[A-Za-z0-9]{86}|[A-Za-z0-9]{92})_[A-Za-z0-9]{10}|[A-Za-z0-9]{10,})\b",
            // A Terminal connection token is `pst_test_` or `pst_live_`.
            // The API reference secret is 71 letters, an underscore, and
            // 10 more. The OpenAPI fixture is 23 letters and has no
            // underscore. The rules above do not see this prefix, so
            // the secret stays in the clear. A shorter key is letters
            // only, at least 10, like `sk_live_`. A short payload stays
            // as written. A body of another length, once it contains an
            // underscore, stays too.
            r"\bpst_(?:live|test)_(?:[A-Za-z0-9]{71}_[A-Za-z0-9]{10}|[A-Za-z0-9]{10,})\b",
            r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            r"\bnpm_[A-Za-z0-9]{36}\b",
            // A PyPI API token is `pypi-` and a URL-safe base64 macaroon.
            // PyPI's scanner asks for at least 85 characters after the
            // hyphen. The rules above do not see that prefix, so the
            // token stays in the clear. The body may contain an
            // underscore or a hyphen, including at the end. A word
            // boundary there would leave that final hyphen, so the
            // pattern stops at the first character outside this
            // alphabet. A shorter body stays as written. A trailing
            // `=` is padding and stays outside the token.
            r"\bpypi-[A-Za-z0-9_-]{85,}",
            // A PyPI upload token starts with `pypi-AgEIcHlwaS5vcmc`
            // and then 50 or more token characters. gitleaks
            // pypi-upload-token. The 85-character rule above leaves a
            // shorter macaroon in the clear. A final hyphen stays
            // inside the mark. A shorter tail stays as written. The
            // value is not stored.
            r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
            // A Sentry personal auth token is `sntryu_` and 64 hex
            // characters. An organization auth token is `sntrys_`, a
            // base64 payload, `_`, and 43 base64 characters. The
            // token formats page publishes those shapes. An
            // organization token runs about 180 to 250 characters,
            // so the payload length is not fixed. The rules above do
            // not see those prefixes, so the token stays in the
            // clear. A shorter body stays as written. A longer
            // personal token stays too. The tail may end in `+` or
            // `/`, so that alternative has no trailing word
            // boundary. The value is not stored.
            r"\bsntry(?:u_[a-f0-9]{64}\b|s_[A-Za-z0-9+/=]+_[A-Za-z0-9+/]{43})",
            // A Resend API key is `re_`, 8 letters or digits, an
            // underscore, and 24 more. Manage API keys is the page
            // for these keys. The create API key response shows that
            // body. The rules above do not see that prefix, so the
            // key stays in the clear. A shorter body stays as
            // written. A longer body stays too. The value is not
            // stored.
            r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b",
            // A Grafana service account token is `glsa_`, 32 letters
            // or digits, an underscore, and 8 hex characters. A
            // Grafana cloud token is `glc_` and at least 32 base64
            // characters. gitleaks grafana-service-account-token and
            // grafana-cloud-api-token. A trailing `+` or `/` is not a
            // word boundary, and `=` padding stays on the cloud
            // token. A shorter body stays as written. The value is
            // not stored.
            r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b",
            r"\bglc_[A-Za-z0-9+/]{32,400}={0,2}",
            // A Heroku API key is `HRKU-AA` plus 58 letters, digits,
            // underscores, or hyphens. gitleaks heroku-api-key-v2.
            // A shorter body stays as written. A longer body stays
            // too. The value is not stored.
            r"\bHRKU-AA[0-9a-zA-Z_-]{58}\b",
            // A PlanetScale service token is `pscale_tkn_` plus 32
            // to 64 token characters. gitleaks planetscale-api-token.
            // The body may end in `=`, `.`, or `-`, so a word boundary
            // would leave that character in the clear. A shorter body
            // stays as written. A longer body stays too. The value is
            // not stored.
            r"\bpscale_tkn_[A-Za-z0-9=._\-]{32,64}",
            // A PlanetScale OAuth token is `pscale_oauth_` plus 32 to
            // 64 token characters. A password is `pscale_pw_` in any
            // case, plus that same body. gitleaks planetscale-oauth-token
            // and planetscale-password. The service-token rule does not
            // see these prefixes. A final `=` stays inside the mark.
            // A shorter body stays as written. The value is not stored.
            r"\bpscale_oauth_[A-Za-z0-9=._\-]{32,64}",
            r"(?i)\bpscale_pw_[A-Za-z0-9=._\-]{32,64}",
            // An OpenShift user token is `sha256~` plus 43 letters,
            // digits, underscores, or hyphens. gitleaks
            // openshift-user-token. A final hyphen is not a word
            // boundary, so that alternative has no trailing boundary.
            // A shorter body stays as written. A longer body stays
            // too. The value is not stored.
            r"\bsha256~(?:[A-Za-z0-9_-]{42}[A-Za-z0-9_]\b|[A-Za-z0-9_-]{42}-)",
            // A Perplexity API key is `pplx-` plus 48 letters or
            // digits. The value is not stored. A shorter body and a
            // longer body stay as written.
            r"\bpplx-[a-zA-Z0-9]{48}\b",
            // A New Relic browser key is `NRJS-` plus 19 hex characters.
            // A user key is `NRAK-` plus 27 letters or digits. An insert
            // key is `NRII-` plus 32 letters, digits, or hyphens. The
            // prefix is the token. A final hyphen on an insert key is
            // not a word boundary. A shorter body stays as written.
            // The value is not stored.
            r"\bNRJS-[a-f0-9]{19}\b",
            r"\bNRAK-[a-z0-9]{27}\b",
            r"\bNRII-(?:[a-z0-9-]{31}[a-z0-9]\b|[a-z0-9-]{31}-)",
            // An Artifactory API key is `AKCp` plus 69 letters or
            // digits. A reference token is `cmVmd` plus 59 letters or
            // digits. The value is not stored. A shorter body and a
            // longer body stay as written.
            r"\bAKCp[A-Za-z0-9]{69}\b",
            r"\bcmVmd[A-Za-z0-9]{59}\b",
            // An age identity file secret is `AGE-SECRET-KEY-1` plus
            // 58 Bech32 characters. The value is not stored. A shorter
            // body stays as written. A character outside that alphabet
            // stays outside the key.
            r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b",
            // A Pulumi access token is `pul-` plus 40 hex characters.
            // The value is not stored. A shorter body, a longer body,
            // and an uppercase hex body stay as written.
            r"\bpul-[a-f0-9]{40}\b",
            // A Brevo API key is `xkeysib-`, 64 lowercase hex
            // characters, a hyphen, and 16 more letters or digits.
            // The value is not stored. A shorter body stays as written.
            r"\bxkeysib-[a-f0-9]{64}-(?i:[a-z0-9]{16})\b",
            // A Dynatrace token is `dt0c01.`, 24 letters or digits,
            // a dot, and 64 more. Both bodies may be any case. The
            // prefix is case sensitive. The value is not stored. A
            // shorter body stays as written.
            r"\bdt0c01\.(?i:[a-z0-9]{24}\.[a-z0-9]{64})\b",
            // An EasyPost production key is `EZAK` plus 54 letters
            // or digits. A test key is `EZTK` plus 54. The prefixes
            // stay uppercase. The bodies may be any case. The value
            // is not stored. A shorter body and a longer body stay
            // as written.
            r"\bEZAK(?i:[a-z0-9]{54})\b",
            r"\bEZTK(?i:[a-z0-9]{54})\b",
            // A RubyGems API token is `rubygems_` plus 48 lowercase
            // hex characters. The value is not stored. A shorter body,
            // a longer body, and an uppercase hex body stay as written.
            r"\brubygems_[a-f0-9]{48}\b",
            // A Prefect API token is `pnu_` plus 36 letters or digits.
            // The value is not stored. A shorter body and a longer body
            // stay as written.
            r"\bpnu_[a-zA-Z0-9]{36}\b",
            // A ReadMe API token is `rdme_` plus 70 lowercase letters
            // or digits. Letters past `f` are part of the token. The
            // value is not stored. A shorter body, a longer body, and
            // an uppercase body stay as written.
            r"\brdme_[a-z0-9]{70}\b",
            // A Hugging Face organization token is `api_org_` plus
            // 34 letters. The body may be any case. A digit is not
            // part of the token. The value is not stored. A shorter
            // body and a longer body stay as written.
            r"\bapi_org_(?i:[a-z]{34})\b",
            // An Adobe client secret is `p8e-` plus 32 letters or
            // digits. The body may be any case. The value is not
            // stored. A shorter body and a longer body stay as written.
            r"\bp8e-(?i:[a-z0-9]{32})\b",
            // An Alibaba Cloud access key id is `LTAI` plus 20 letters
            // or digits. The body may be any case. The value is not
            // stored. A shorter body and a longer body stay as written.
            r"\bLTAI(?i:[a-z0-9]{20})\b",
            // A Shippo token is `shippo_live_` or `shippo_test_` plus
            // 40 hex characters. The value is not stored. A shorter
            // body and a longer body stay as written.
            r"\bshippo_(?:live|test)_[a-fA-F0-9]{40}\b",
            // A Frame.io token is `fio-u-` plus 64 letters, digits,
            // `_`, `-`, or `=`. This regex crate has no lookahead, so
            // a body that ends on a letter or digit uses a word
            // boundary, and a body that ends on `-` or `=` is exact.
            // The value is not stored. A shorter body and a longer
            // body stay as written.
            r"\bfio-u-(?i:[a-z0-9_=-]{63}[a-z0-9_]\b|[a-z0-9_=-]{63}[-=])",
            // A Duffel token is `duffel_test_` or `duffel_live_` plus
            // 43 token characters. The value is not stored. A shorter
            // body stays as written. `duffel_prod_` stays as written.
            r"\bduffel_(?:test|live)_(?i:[a-z0-9_-]{42}[a-z0-9_]\b|[a-z0-9_-]{42}[-=])",
            // A Square access token may be `EAAA` plus 22 to 60
            // token characters. The existing `sq0atp` rule is a
            // different shape. The value is not stored. A shorter
            // body stays as written. A final hyphen stays inside
            // the mark.
            r"\bEAAA(?:[A-Za-z0-9_-]{21,59}[A-Za-z0-9]\b|[A-Za-z0-9_-]{21,59}-)",
            // A Clojars token is `CLOJARS_` plus 60 letters or digits.
            // The prefix may be any case. The value is not stored. A
            // shorter body and a longer body stay as written.
            r"(?i)\bCLOJARS_[a-z0-9]{60}\b",
            // An Infracost token is `ico-` plus 32 letters or digits.
            // The value is not stored. A shorter body and a longer
            // body stay as written.
            r"\bico-[A-Za-z0-9]{32}\b",
            // A Settlemint token is `sm_aat_`, `sm_pat_`, or `sm_sat_`
            // plus 16 letters or digits. The value is not stored. A
            // shorter body stays as written.
            r"\bsm_(?:aat|pat|sat)_[A-Za-z0-9]{16}\b",
            // A Fly.io deploy token is `fo1_` plus 43 token
            // characters. A macaroon token is `fm1a_`, `fm1r_`, or
            // `fm2_` plus at least 100 base64 characters. The macaroon
            // tail may end in `+`, `/`, or `=`, so that rule has no
            // trailing word boundary. The value is not stored. A
            // shorter `fo1_` body stays as written.
            r"\bfo1_[A-Za-z0-9_-]{42}[A-Za-z0-9_]\b",
            r"\bfm(?:1[ar]|2)_[A-Za-z0-9+/]{100,}={0,2}",
            // A Bedrock long-lived key is `ABSK` plus 109 to 269
            // base64 characters, with optional `=` padding. The value
            // is not stored. A shorter body stays as written.
            r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}",
            // A 1Password secret key starts with `A3-` and then the
            // published groups of uppercase letters and digits. The
            // value is not stored. A shorter group stays as written.
            r"\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b",
            // A Flutterwave test secret or public key is
            // `FLWSECK_TEST-` or `FLWPUBK_TEST-`, 32 characters from
            // `a` through `h` and digits, then `-X`. The encryption
            // key is `FLWSECK_TEST-` plus 12 of those characters. The
            // value is not stored. A shorter body stays as written.
            r"\bFLWSECK_TEST-(?i:[a-h0-9]{32})-X\b",
            r"\bFLWPUBK_TEST-(?i:[a-h0-9]{32})-X\b",
            r"\bFLWSECK_TEST-(?i:[a-h0-9]{12})\b",
            // A Grafana API key starts with `eyJrIjoi` and then 70 to
            // 400 letters or digits, with optional `=` padding. The
            // value is not stored. A shorter body stays as written.
            // This is not the `glsa_` or `glc_` token.
            r"(?i)\beyJrIjoi[A-Za-z0-9]{70,400}={0,2}",
            // An intra42 client secret is `s-s4t2ud-` or `s-s4t2af-`
            // plus 64 hex characters. The hex may be any case. The
            // value is not stored. A shorter body stays as written.
            r"\bs-s4t2(?:ud|af)-(?i:[a-f0-9]{64})\b",
            // A Scalingo token is `tk-us-` plus 48 token characters.
            // The value is not stored. A shorter body stays as written.
            // A final hyphen stays inside the mark.
            r"\btk-us-(?:[A-Za-z0-9_-]{47}[A-Za-z0-9_]\b|[A-Za-z0-9_-]{47}-)",
            // A MaxMind license key is 6 letters or digits, `_`, 29
            // letters or digits, and `_mmk`. The value is not stored.
            // A shorter middle stays as written.
            r"\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\b",
            // A Sourcegraph token is `sgp_` plus 40 hex characters,
            // or `sgp_` plus 16 hex characters or `local`, then `_`,
            // then 40 hex characters. The value is not stored. A bare
            // 40 hex run with no `sgp_` prefix stays as written. A
            // shorter `sgp_` body stays as written.
            r"\bsgp_(?:[a-fA-F0-9]{16}_|local_)[a-fA-F0-9]{40}\b",
            r"\bsgp_[a-fA-F0-9]{40}\b",
            // A Terraform API token is 14 letters or digits,
            // `.atlasv1.`, and 60 to 70 token characters. `atlasv1`
            // stays lowercase. The value is not stored. A shorter
            // tail stays as written.
            r"(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9_=-]{60,70}",
            // A Databricks token is `dapi` plus 32 lowercase hex
            // characters, with an optional hyphen and one digit. The
            // value is not stored. A shorter body stays as written.
            // Uppercase hex stays as written.
            r"\bdapi[a-f0-9]{32}(?:-\d)?\b",
            // An Authress service client key is `scauth_`,
            // `authress_`, `ext_`, or `sc_`, two short segments, the
            // lowercase marker `acc`, and a long tail. gitleaks
            // authress-service-client-access-key. A final `=` stays
            // inside the mark. A shorter segment stays as written.
            // The value is not stored.
            r"\b(?:scauth|authress|ext|sc)_(?i:[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.)acc[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}",
            // A Mapbox token is `pk.`, 60 letters or digits, a dot,
            // and 22 more. gitleaks mapbox-api-token. The prefix may
            // be any case. The word is not required. A shorter
            // segment stays as written. The value is not stored.
            r"(?i)\bpk\.[a-z0-9]{60}\.[a-z0-9]{22}\b",
            // A Cloudflare Origin CA key is `v1.0-`, 24 hex
            // characters, a hyphen, and 146 more hex characters.
            // gitleaks cloudflare-origin-ca-key. The word is not
            // required. A shorter group stays as written. Uppercase
            // hex stays as written. The value is not stored.
            r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b",
            // A Yandex IAM token is `t1.`, a token segment, optional
            // `=` padding, a dot, and 86 more token characters.
            // gitleaks yandex-access-token. The prefix may be any
            // case. The word is not required. A final `=` stays
            // inside the mark. A shorter second segment stays as
            // written. The value is not stored.
            r"(?i)\bt1\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]{86}={0,2}",
            // An Airtable personal access token is `pat`, 14 letters
            // or digits, a dot, and 64 lowercase hex characters.
            // gitleaks airtable-personnal-access-token. The word is
            // not required. A shorter group stays as written. The
            // value is not stored.
            r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b",
            // A Microsoft Teams incoming webhook is
            // `{tenant}.webhook.office.com/webhookb2/`, two ids, and
            // `IncomingWebhook`. gitleaks microsoft-teams-webhook.
            // A shorter URL stays as written. The value is not stored.
            r"\bhttps://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}\b",
            // A Sonar token is `squ_`, `sqp_`, or `sqa_` plus 40
            // token characters. gitleaks sonar-api-token. The
            // prefix may be any case. A bare 40-character string
            // is not this token. A final hyphen or `=` stays inside
            // the mark. A shorter body stays as written. The value
            // is not stored.
            r"(?i)\b(?:squ|sqp|sqa)_(?:[a-z0-9_=-]{39}[a-z0-9_]\b|[a-z0-9_=-]{39}[-=])",
            // A Defined Networking token is `dnkey-`, 26 token
            // characters, a hyphen, and 52 more. gitleaks
            // defined-networking-api-token. The prefix may be any
            // case. A final `=` or hyphen stays inside the mark.
            // A shorter group stays as written. The value is not stored.
            r"(?i)\bdnkey-(?:[a-z0-9=_-]{26}-[a-z0-9=_-]{51}[a-z0-9_]\b|[a-z0-9=_-]{26}-[a-z0-9=_-]{51}[-=])",
            // An Atlassian API token is `ATATT3` plus 186 letters,
            // digits, underscores, hyphens, or equals signs. gitleaks
            // atlassian-api-token. The word-gated alternative is not
            // used. A final hyphen or `=` stays inside the mark. A
            // shorter body stays as written. The value is not stored.
            r"\bATATT3(?:[A-Za-z0-9_\-=]{185}[A-Za-z0-9_]\b|[A-Za-z0-9_\-=]{185}[-=])",
            // An Azure AD client secret is 3 token characters, a
            // digit, `Q~`, and 31 to 34 more token characters.
            // gitleaks azure-ad-client-secret. A final hyphen, dot,
            // or tilde stays inside the mark when it follows 30
            // token characters. Letting that punctuation follow a
            // longer run also takes a sentence dot. A shorter tail
            // stays as written. The value is not stored.
            r"\b[A-Za-z0-9_~.]{3}\dQ~(?:[A-Za-z0-9_~.-]{30,33}[A-Za-z0-9_]\b|[A-Za-z0-9_~.-]{30}[.~-]{1,4})",
            // A Groq API key is `gsk_` and 52 letters or digits. The
            // API keys page is where those credentials are issued.
            // The rules above do not see that prefix, so the key stays
            // in the clear. A shorter body stays as written. A longer
            // body stays too. The value is not stored.
            r"\bgsk_[A-Za-z0-9]{52}\b",
            // A Linear personal API key is `lin_api_` plus 40
            // characters. Working with the GraphQL API is the page
            // that sends that key. The rules above do not see that
            // prefix, so the key stays in the clear. A shorter body
            // stays as written. A longer body stays too. The value
            // is not stored.
            r"\blin_api_[A-Za-z0-9]{40}\b",
            // A Doppler service token is `dp.st.` and a personal token
            // is `dp.pt.`. A CLI token is `dp.ct.`. A service account
            // token is `dp.sa.` and a service account identity token is
            // `dp.said.`. A SCIM token is `dp.scim.` and an audit token
            // is `dp.audit.`. The auth token formats page publishes a
            // body of 40 to 44 letters or digits. A service token may
            // put a config name of 2 to 35 characters between that
            // prefix and the body. The other tokens have no config
            // name. The service tokens page shows `dp.st.`. The rules
            // above do not see those prefixes, so the token stays in
            // the clear. A shorter body stays as written. A longer
            // body stays too. The value is not stored.
            r"\bdp\.(?:st\.(?:[a-z0-9_-]{2,35}\.)?|pt\.|ct\.|said\.|scim\.|audit\.|sa\.)[A-Za-z0-9]{40,44}\b",
            // An older Square access token is `sq0atp-` plus 22
            // characters. An older application secret is `sq0csp-`
            // plus 43. Square's access tokens page is where those
            // credentials are issued. The rules above do not see
            // those prefixes, so the token stays in the clear. A
            // shorter body stays as written. A longer body stays
            // too. The value is not stored.
            r"\bsq0(?:atp-[A-Za-z0-9_-]{22}|csp-[A-Za-z0-9_-]{43})\b",
            // A Notion integration token is `ntn_` and a 46-character
            // body. The authentication page sends that bearer token.
            // New tokens start with `ntn_` so scanners can find them.
            // The body is 11 digits and 35 letters or digits. The
            // rules above do not see that prefix, so the token stays
            // in the clear. A shorter body stays as written. The
            // older `secret_` prefix is a common word and stays as
            // written. The value is not stored.
            r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b",
            // A Postman API key is `PMAK-`, 24 hex characters, a
            // hyphen, and 34 hex characters. Postman's authentication
            // page shows that shape. The rules above do not see that
            // prefix, so the key stays in the clear. A shorter body
            // stays as written. The value is not stored.
            r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b",
            // A Telegram bot token is 5 to 16 digits, a colon, and a
            // 35-character secret. gitleaks telegram-bot-api-token
            // allows that id length. The old 8-to-10 rule left a
            // shorter or longer id in the clear. A final hyphen is
            // not a word boundary, so that alternative has no
            // trailing boundary. A shorter tail stays as written. A
            // longer tail stays too. A bare number stays. The value
            // is not stored.
            r"\b[0-9]{5,16}:(?:[A-Za-z0-9_-]{34}[A-Za-z0-9]\b|[A-Za-z0-9_-]{34}-)",
            // A Shopify access token is `shpat_` (public and online
            // admin), `shpca_` (custom apps), `shppa_` (legacy private
            // apps), or `shpss_` (app secret). The body is 32 letters
            // or digits. The rules above do not see those prefixes, so
            // the token stays in the clear. A shorter body stays as
            // written. A longer body stays too. The value is not stored.
            r"\bshp(?:at|ca|pa|ss)_[0-9A-Za-z]{32}\b",
            r"\bhf_[A-Za-z0-9]{20,}\b",
            // DigitalOcean tokens are `dop_v1_` from the control panel,
            // `doo_v1_` from the OAuth flow, and `dor_v1_` for a refresh
            // token. The rules above do not see those prefixes, so the
            // token stays in the clear. The published body is 64 letters.
            // A short payload stays as written.
            r"\b(?:dop|doo|dor)_v1_[A-Za-z0-9]{64}\b",
            // Vault 1.10 prefixes a service token with `hvs.`, a batch
            // token with `hvb.`, and a recovery token with `hvr.`. The
            // rules above do not see those prefixes, so the token stays
            // in the clear. After the prefix, 24 or more characters are
            // appended. A longer token may contain an underscore or a
            // hyphen. A short payload stays as written. The earlier
            // `s.`, `b.`, and `r.` prefixes stay too.
            r"\bhv[sbr]\.[A-Za-z0-9_\-]{24,}\b",
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            // A 1Password service account token is `ops_` plus the
            // URL-safe base64 of a JSON object. The body starts with
            // `eyJ`. The JWT rule below needs a word boundary before
            // `eyJ`, and the underscore sits against that `e`, so the
            // token stays in the clear. The published example is 630
            // characters after `ops_`. The same JSON with the sign-in
            // address `my.1password.com` and a one-character email
            // local part is 604. A shorter body stays as written. The
            // encoding may include an underscore or a hyphen,
            // including at the end, so this pattern does not use a
            // trailing word boundary. A trailing `=` is padding and
            // stays outside the token.
            r"\bops_eyJ[A-Za-z0-9_-]{601,}",
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
// (`abcdefghijklmnop.QRSTUVWXYZ123456`). The dot may be the fullwidth
// stop. Leaving that dot out masks the head and sends the tail. A dot
// with nothing after it stays outside the value, so a sentence period
// stays.
const SECRET_RUN: &str = r"(?:[A-Za-z0-9+/=_\-]+(?:\.|\u{FF0E}))*[A-Za-z0-9+/=_\-]{16,}(?:(?:\.|\u{FF0E})[A-Za-z0-9+/=_\-]+)*";

/// `api_key`, `secret_key`, `access_token`, `auth_token`, and
/// `session_token`.
///
/// The mark inside `api-key`, `secret-key`, `access-token`, and
/// `auth-token` is an underscore or a hyphen mark. An ASCII hyphen is
/// not the only one. An en dash, a minus sign, or a soft hyphen is
/// still that name. Whitespace between the words is that name too, so
/// `api key` counts. `secret_access_key` is the AWS env name, including
/// spaces or hyphens between the words. `session_token` is the AWS
/// session token. Leaving that name out sends the value. A slash or a
/// dot between the words is not this name.
fn assignment_name() -> String {
    let gap = format!("(?:{})*", hyphen_class(r"_\s"));
    r"(?:[A-Za-z0-9_]*_)?(?:api{gap}key|secret{gap}access{gap}key|secret{gap}key|access{gap}token|auth{gap}token|session{gap}token)"
        .replace("{gap}", &gap)
}

/// `api_key`, `secret_key`, `access_token`, `auth_token`, and `session_token` assignments.
///
/// `_` is a word character, so a word boundary misses `MY_API_KEY`. The
/// name may have a prefix before that `_`. A JSON key puts a quote between
/// the name and the colon. The character before the name stays outside the span.
fn push_assignment_secrets(text: &str, out: &mut Vec<RawHit>) {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        let name = assignment_name();
        // A fullwidth equals or colon is that separator. Leaving it out sends the value.
        Regex::new(&format!(
            r#"(?i)(?:^|[^A-Za-z0-9_])({name}"?\s*[=:\u{{FF1D}}\u{{FF1A}}]\s*["']?{SECRET_RUN})"#
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
/// same as an ASCII hyphen. A fullwidth full stop counts as that dot.
/// A fullwidth solidus counts as that slash. Patterns repeat it when
/// the gap may hold more than one, as in `416 - 555 - 0123`.
fn phone_pattern(body: &str) -> Regex {
    Regex::new(
        &body
            // A middle dot is that separator. A fullwidth solidus is that
            // slash. Leaving either mark out sends the number.
            // A halfwidth middle dot is that separator. Leaving it out
            // sends the number.
            // A comma is that separator. Leaving it out sends the number.
            // An ideographic comma is that separator. Leaving it out sends the number.
            .replace(
                "{sep}",
                &hyphen_class(
                    r"\s./\u{FF0F}\u{FF0E}\u{30FB}\u{00B7}\u{FF65},\u{FF0C}\u{3001}\u{FF64}",
                ),
            )
            .replace("{plus}", PLUS)
            .replace("{idd}", IDD)
            .replace("{open}", OPEN_PAREN)
            .replace("{close}", CLOSE_PAREN),
    )
    .expect("phone pattern")
}

/// ASCII `+` and the fullwidth plus. A wide-character keyboard writes
/// the fullwidth sign. Leaving it out sends the number.
const PLUS: &str = r"(?:\+|\u{FF0B})";

/// Dialing prefix written where a plus would sit.
///
/// `00` is the prefix outside NANP (`0044` for `+44`). `011` is the
/// NANP exit code (`011 44` for `+44`). Neither prefix is digits of
/// the number. `011` is listed first so it is not read as `00`. Each
/// of those digits may be fullwidth. A wide keyboard writes `０１１`
/// and `００`. Leaving that form out sends the number. A bare run
/// after the prefix stays as written. This is not a plus sign.
const IDD: &str = r"(?:(?:0|\u{FF10})(?:1|\u{FF11})(?:1|\u{FF11})|(?:0|\u{FF10})(?:0|\u{FF10}))";

/// ASCII parentheses and the fullwidth pair. A wide-character keyboard
/// writes those marks around a group. Leaving them out sends the number.
/// A small parenthesis is that mark. Leaving it out sends the number.
const OPEN_PAREN: &str = r"(?:\(|\u{FF08}|\u{FE59})";
const CLOSE_PAREN: &str = r"(?:\)|\u{FF09}|\u{FE5A})";

fn international_sep_class() -> String {
    // A middle dot is that separator. A fullwidth solidus is that
    // slash. Leaving either mark out sends the number.
    // A halfwidth middle dot is that separator. Leaving it out
    // sends the number.
    // A small parenthesis is that mark. Leaving it out sends the number.
    // A comma is that separator. Leaving it out sends the number.
    // An ideographic comma is that separator. Leaving it out sends the number.
    hyphen_class(
        r"\s./\u{FF0F}()\u{FF08}\u{FF09}\u{FE59}\u{FE5A}\u{FF0E}\u{30FB}\u{00B7}\u{FF65},\u{FF0C}\u{3001}\u{FF64}",
    )
}

/// Longest prefix of `text[start..end]` that is one international number.
///
/// The regex match may include a later digit group. Fifteen digits is
/// the longest number kept here. A leading `00` prefix is not part of
/// that count. A shorter prefix is used only when the full match is past
/// that, so a tail that still fits stays inside it.
fn international_span(text: &str, start: usize, mut end: usize) -> Option<(usize, usize)> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            &r"^(?:{plus}\s*|{idd}{sep}*)\d{1,3}(?:{sep}+\d{1,14}){2,6}$"
                .replace("{sep}", &international_sep_class())
                .replace("{plus}", PLUS)
                .replace("{idd}", IDD),
        )
        .expect("international phone span")
    });
    static TRAIL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&r"{sep}+\d+$".replace("{sep}", &international_sep_class()))
            .expect("phone group tail")
    });
    loop {
        let slice = text.get(start..end)?;
        let digits = significant_phone_digits(slice);
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
        .is_some_and(|ch| narrow_digit(ch).is_some())
    {
        return false;
    }
    if text[end..]
        .chars()
        .next()
        .is_some_and(|ch| narrow_digit(ch).is_some())
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

/// Start of each run of ten Unicode decimal digits.
///
/// `\d` matches every run. ASCII and fullwidth are in this list, and so
/// are Arabic-Indic digits. `char::to_digit` only accepts ASCII, so
/// leaving a run out drops a number the pattern already matched, and the
/// number is sent. The value is the offset from the start of the run.
/// Luhn subtracts `b'0'`. A hex letter is not in a run.
const DECIMAL_DIGIT_ZERO: [u32; 76] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0,
    0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950, 0x11BF0, 0x11C50, 0x11D50,
    0x11DA0, 0x11F50, 0x16130, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE, 0x1D7D8,
    0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
];

fn narrow_digit(ch: char) -> Option<u8> {
    let code = ch as u32;
    let found = DECIMAL_DIGIT_ZERO.partition_point(|&zero| zero <= code);
    let index = found.checked_sub(1)?;
    let value = code - DECIMAL_DIGIT_ZERO[index];
    if value < 10 {
        Some(b'0' + value as u8)
    } else {
        None
    }
}

fn digits_of(text: &str) -> Vec<u8> {
    text.chars().filter_map(narrow_digit).collect()
}

fn digit_count(text: &str) -> usize {
    text.chars()
        .filter(|ch| narrow_digit(*ch).is_some())
        .count()
}

/// Digits of one international number, ignoring a leading `00` prefix.
///
/// `+44 20 7946 0958` is twelve digits. `0044 20 7946 0958` and
/// `011 44 20 7946 0958` are that number with a dialing prefix.
/// Counting the prefix would keep a short number, or drop the tail
/// of a fifteen-digit number. The prefix digits may be fullwidth.
fn significant_phone_digits(slice: &str) -> usize {
    let digits = digit_count(slice);
    digits.saturating_sub(idd_prefix_digits(slice))
}

/// `011` or `00` at the start of a matched number, ASCII or fullwidth.
///
/// `011` is three digits and `00` is two. A leading plus is not this
/// prefix. The count is digits, not bytes, so a fullwidth prefix still
/// comes out of the fifteen-digit limit.
fn idd_prefix_digits(slice: &str) -> usize {
    let mut digits = slice.chars().map(narrow_digit);
    match (digits.next(), digits.next(), digits.next()) {
        (Some(Some(b'0')), Some(Some(b'1')), Some(Some(b'1'))) => 3,
        (Some(Some(b'0')), Some(Some(b'0')), _) => 2,
        _ => 0,
    }
}

/// Five or more digits glued to `)`, `）`, or `﹚` are a bare tail, not another group.
///
/// `+44 (20)79460958` is that tail. A fullwidth closing mark is the same
/// tail. A small closing mark is that same tail. `+33 (0)1` still has a
/// one-digit group against the parenthesis, and `+44 (0)7700 900123`
/// keeps the space before the long group.
fn glued_paren_tail(text: &str) -> bool {
    for (index, ch) in text.char_indices() {
        if ch != ')' && ch != '\u{FF09}' && ch != '\u{FE5A}' {
            continue;
        }
        let mut digits = 0usize;
        for next in text[index + ch.len_utf8()..].chars() {
            if narrow_digit(next).is_none() {
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
