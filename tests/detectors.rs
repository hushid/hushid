use hushid::{
    restore_json_write, shield_json_strings, shield_text, Glossary, Vault, DETECTOR_VERSION,
};

fn shield(text: &str) -> (Vault, String, hushid::AuditRecord) {
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &Glossary::empty(), text).unwrap();
    (vault, out, audit)
}

fn round_trip(text: &str, kind_count: fn(&hushid::AuditRecord) -> u32) {
    let (vault, out, audit) = shield(text);
    assert_eq!(audit.detector_version, DETECTOR_VERSION);
    assert_eq!(kind_count(&audit), 1);
    assert!(!out.contains(text));
    assert_eq!(vault.restore_write(&out).unwrap(), text);
    let debug = format!("{audit:?}");
    assert!(!debug.contains(text));
}

fn luhn_check_digit(body: &str) -> char {
    let mut sum = 0;
    let mut double = true;
    for ch in body.chars().rev() {
        let mut value = ch.to_digit(10).unwrap();
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    let digit = (10 - (sum % 10)) % 10;
    char::from_digit(digit, 10).unwrap()
}

#[test]
fn ramq_number_is_shielded_and_restored() {
    // Fictional numbers in the published 4-letter, 8-digit layout.
    // They are not issued RAMQ numbers. Month 51 and 52 are January
    // and February with 50 added. A bad month, a bad day, a lowercase
    // number, and a glued extra digit stay as written.
    let samples = [
        "BOUF 9451 1419",
        "DUPA 9503 1512",
        "MART 8807 2345",
        "TREJ 0209 1018",
        "GAGL 7552 2816",
        "BELA 9911 0507",
        "ROBE 0612 1719",
        "BOUF94511419",
        "BOUF-9451-1419",
    ];
    for sample in samples {
        let (vault, out, audit) = shield(sample);
        assert_eq!(audit.ramq, 1, "{sample} -> {out}");
        assert!(out.starts_with("h1_ramq_"), "{sample} -> {out}");
        let digits: String = sample.chars().filter(|ch| ch.is_ascii_digit()).collect();
        assert!(hidden(&out, &digits), "{sample} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), sample);
    }

    let (vault, out, audit) = shield("see BOUF 9451 1419 next");
    assert_eq!(audit.ramq, 1, "{out}");
    assert!(out.starts_with("see h1_ramq_"), "{out}");
    assert!(out.ends_with(" next"), "{out}");
    assert!(hidden(&out, "94511419"), "{out}");
    assert_eq!(
        vault.restore_write(&out).unwrap(),
        "see BOUF 9451 1419 next"
    );

    let raw = r#"{"nam":"BOUF 9451 1419"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.ramq, 1, "{out}");
    assert!(hidden(&out, "9451"), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        "BOUF 9413 1419",
        "BOUF 9400 1419",
        "BOUF 9401 0019",
        "bouf 9451 1419",
        "BOU 9451 1419",
        "BOUF945114199",
        "BOUF 9451 14199",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.ramq, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

fn valid_sin() -> String {
    let body = "13069254";
    let mut sin = body.to_string();
    sin.push(luhn_check_digit(body));
    sin
}

/// The issued token's payload is Crockford base32, so a short digit run
/// such as `416` can sit inside the token. That run is not the original
/// number. Leak checks have to look at the text outside the token.
fn visible(out: &str) -> String {
    let mut rest = out;
    let mut cleaned = String::new();
    while let Some(at) = rest.find("h1_") {
        cleaned.push_str(&rest[..at]);
        let tail = &rest[at + 3..];
        if let Some(skip) = mark_body_len(tail) {
            rest = &tail[skip..];
        } else {
            cleaned.push_str("h1_");
            rest = tail;
        }
    }
    cleaned.push_str(rest);
    cleaned
}

fn hidden(out: &str, needle: &str) -> bool {
    !visible(out).contains(needle)
}

fn mark_body_len(tail: &str) -> Option<usize> {
    if let Some(rest) = tail.strip_prefix("secret") {
        if at_boundary(rest) {
            return Some("secret".len());
        }
    }
    for head in ["email_", "phone_", "card_", "sin_", "glossary_"] {
        let Some(rest) = tail.strip_prefix(head) else {
            continue;
        };
        if rest.len() < 9 || !rest.as_bytes()[..9].iter().copied().all(is_crockford) {
            continue;
        }
        if at_boundary(&rest[9..]) {
            return Some(head.len() + 9);
        }
    }
    None
}

fn at_boundary(rest: &str) -> bool {
    match rest.chars().next() {
        None => true,
        Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' => false,
        Some(_) => true,
    }
}

fn is_crockford(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'
    )
}

#[test]
fn email_round_trip_keeps_exact_bytes() {
    round_trip("marie+tag@example.com", |audit| audit.email);
    let (vault, out, _) = shield("mail a@b.co.");
    assert_eq!(vault.restore_write(&out).unwrap(), "mail a@b.co.");
    assert!(out.ends_with('.'), "{out}");
    assert!(!out.contains("co."));
}

#[test]
fn email_apostrophe_stays_inside_the_address() {
    for email in [
        "o'brien@example.com",
        "marie.o'brien@example.com",
        "o'brien+tag@example.com",
        "O'Brien@Example.COM",
        "o\u{2019}brien@example.com",
    ] {
        let (vault, out, audit) = shield(email);
        assert_eq!(audit.email, 1, "{email} -> {out}");
        assert!(out.starts_with("h1_email_"), "{email} -> {out}");
        assert!(!out.contains('\''), "{email} -> {out}");
        assert!(!out.contains('\u{2019}'), "{email} -> {out}");
        assert!(!out.contains('@'), "{email} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), email);
    }

    let sentence = "mail o'brien@example.com today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains("o'"), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let dotted = "mail o'brien@example.com.";
    let (vault, out, audit) = shield(dotted);
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with('.'), "{out}");
    assert!(!out.contains("o'"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), dotted);

    let quoted = "see 'o'brien@example.com' now";
    let (vault, out, audit) = shield(quoted);
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("see 'h1_email_"), "{out}");
    assert!(out.ends_with("' now"), "{out}");
    assert!(!out.contains("o'brien"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), quoted);

    let prose = "o'brien wrote a@b.co";
    let (vault, out, audit) = shield(prose);
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("o'brien wrote h1_email_"), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), prose);

    let raw = r#"{"to":"o'brien@example.com"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains("o'"), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn left_single_quote_stays_inside_the_address() {
    let mark = '\u{2018}';
    let email = format!("o{mark}brien@example.com");
    let (vault, out, audit) = shield(&email);
    assert_eq!(audit.email, 1, "{email} -> {out}");
    assert!(out.starts_with("h1_email_"), "{out}");
    assert!(!out.contains(mark), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), email);

    let sentence = format!("mail o{mark}brien@example.com today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains(mark), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let prose = format!("o{mark}brien wrote a@b.co");
    let (vault, out, audit) = shield(&prose);
    assert_eq!(audit.email, 1, "{prose} -> {out}");
    assert!(
        out.starts_with(&format!("o{mark}brien wrote h1_email_")),
        "{out}"
    );
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), prose);

    let raw = format!(r#"{{"to":"o{mark}brien@example.com"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{raw} -> {out}");
    assert!(!out.contains(mark), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let sin = "130692544";
    for cued in [
        format!("numéro d{mark}assurance sociale {sin}"),
        format!("numero d{mark}assurance sociale {sin}"),
    ] {
        let (vault, out, audit) = shield(&cued);
        assert_eq!(audit.sin, 1, "{cued} -> {out}");
        assert!(hidden(&out, sin), "{cued} -> {out}");
        assert!(out.contains(mark), "{cued} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), cued);
    }
}

#[test]
fn email_with_a_non_ascii_letter_stays_one_address() {
    for email in [
        "josé@example.com",
        "marie.josé@example.com",
        "user@société.fr",
        "Élise.O'Brien@Société.FR",
        "jose\u{0301}@example.com",
        "user@socie\u{0301}te.fr",
        "user@example.com\u{0301}",
    ] {
        let (vault, out, audit) = shield(email);
        assert_eq!(audit.email, 1, "{email} -> {out}");
        assert!(out.starts_with("h1_email_"), "{email} -> {out}");
        assert!(!out.contains('@'), "{email} -> {out}");
        assert!(
            !out.contains('é') && !out.contains('É') && !out.contains('\u{0301}'),
            "{email} -> {out}"
        );
        assert_eq!(vault.restore_write(&out).unwrap(), email);
    }

    let sentence = "écrire à josé@example.com aujourd'hui";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("écrire à h1_email_"), "{out}");
    assert!(out.ends_with(" aujourd'hui"), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(!out.contains("josé"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let raw = r#"{"to":"josé@example.com"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(!out.contains("josé"), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in ["josé habite ici", "josé@home", "marie.josé wrote"] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.email, 0, "{bare} -> {out}");
    }
}

#[test]
fn email_with_dash_punctuation_stays_one_address() {
    // U+2010 hyphen, U+2011 non-breaking hyphen, U+2012 figure dash,
    // U+2013 en dash. A word processor uses these where an ASCII hyphen
    // was typed. The address is still one span.
    let hyphen = '\u{2010}';
    let nb = '\u{2011}';
    let figure = '\u{2012}';
    let en = '\u{2013}';
    for email in [
        "jean-luc@example.com".to_string(),
        "user@ex-ample.com".to_string(),
        format!("jean{en}luc@example.com"),
        format!("marie.jean{en}luc@example.com"),
        format!("jean{en}luc+tag@example.com"),
        format!("Jean{en}Luc@Example.COM"),
        format!("jean{hyphen}luc@example.com"),
        format!("jean{nb}luc@example.com"),
        format!("jean{figure}luc@example.com"),
        format!("user@jean{en}luc.fr"),
        format!("user@ex{en}ample.com"),
        format!("Élise{en}Marie.O'Brien@Société.fr"),
    ] {
        let (vault, out, audit) = shield(&email);
        assert_eq!(audit.email, 1, "{email} -> {out}");
        assert!(out.starts_with("h1_email_"), "{email} -> {out}");
        assert!(!out.contains('@'), "{email} -> {out}");
        assert!(
            !out.contains(hyphen)
                && !out.contains(nb)
                && !out.contains(figure)
                && !out.contains(en)
                && !out.contains('É')
                && !out.contains('é')
                && !out.contains('\''),
            "{email} -> {out}"
        );
        assert_eq!(vault.restore_write(&out).unwrap(), email);
    }

    let sentence = format!("écrire à jean{en}luc@example.com aujourd'hui");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("écrire à h1_email_"), "{out}");
    assert!(out.ends_with(" aujourd'hui"), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(hidden(&out, "jean"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let raw = format!(r#"{{"to":"jean{en}luc@example.com"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(hidden(&out, "jean"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    // A dash with no space is part of the local part, same as `note-a@`.
    // A dash before a space, or a leading dash, is not.
    let inside = format!("note{en}a@b.co");
    let (vault, out, audit) = shield(&inside);
    assert_eq!(audit.email, 1, "{inside} -> {out}");
    assert!(out.starts_with("h1_email_"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), inside);

    let spaced = format!("note{en} a@b.co");
    let (vault, out, audit) = shield(&spaced);
    assert_eq!(audit.email, 1, "{spaced} -> {out}");
    assert!(out.starts_with(&format!("note{en} h1_email_")), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), spaced);

    let leading = format!("{en}a@b.co");
    let (vault, out, audit) = shield(&leading);
    assert_eq!(audit.email, 1, "{leading} -> {out}");
    assert!(out.starts_with(&format!("{en}h1_email_")), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), leading);

    let after = format!("mail a@b.co{en}next");
    let (vault, out, audit) = shield(&after);
    assert_eq!(audit.email, 1, "{after} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(&format!("{en}next")), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), after);

    let pair = format!("a@b.co{en}c@d.co");
    let (vault, out, audit) = shield(&pair);
    assert_eq!(audit.email, 2, "{pair} -> {out}");
    assert!(out.contains(en), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(out.matches("h1_email_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    for bare in [
        format!("jean{en}luc habite ici"),
        format!("jean{en}luc@home"),
        format!("marie.jean{en}luc wrote"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.email, 0, "{bare} -> {out}");
    }
}

#[test]
fn email_with_a_minus_sign_or_soft_hyphen_stays_one_address() {
    // `jean-luc@example.com` is already one address when the hyphen is
    // dash punctuation. U+2212 MINUS SIGN and U+00AD SOFT HYPHEN are
    // that same mark. Leaving them out sends the head and keeps
    // `luc@`, or sends the whole address when the mark sits in the
    // domain. The local part still does not start on the mark.
    let minus = '\u{2212}';
    let soft = '\u{00ad}';
    for mark in [minus, soft] {
        for email in [
            format!("jean{mark}luc@example.com"),
            format!("marie.jean{mark}luc@example.com"),
            format!("jean{mark}luc+tag@example.com"),
            format!("user@ex{mark}ample.com"),
            format!("user@jean{mark}luc.fr"),
            format!("note{mark}a@b.co"),
            format!("Élise{mark}Marie.O'Brien@Société.fr"),
        ] {
            let (vault, out, audit) = shield(&email);
            assert_eq!(audit.email, 1, "{email} -> {out}");
            assert_eq!(audit.phone, 0, "{email} -> {out}");
            assert!(out.starts_with("h1_email_"), "{email} -> {out}");
            assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
            assert!(!out.contains('@'), "{email} -> {out}");
            assert!(!out.contains(mark), "{email} -> {out}");
            assert!(hidden(&out, "jean"), "{email} -> {out}");
            assert!(!out.contains("ample"), "{email} -> {out}");
            assert!(!out.contains("note"), "{email} -> {out}");
            assert_eq!(vault.restore_write(&out).unwrap(), email);
        }

        let sentence = format!("écrire à jean{mark}luc@example.com aujourd'hui");
        let (vault, out, audit) = shield(&sentence);
        assert_eq!(audit.email, 1, "{sentence} -> {out}");
        assert!(out.starts_with("écrire à h1_email_"), "{out}");
        assert!(out.ends_with(" aujourd'hui"), "{out}");
        assert!(!out.contains('@'), "{out}");
        assert!(hidden(&out, "jean"), "{out}");
        assert!(!out.contains(mark), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), sentence);

        let dotted = format!("mail user@ex{mark}ample.com.");
        let (vault, out, audit) = shield(&dotted);
        assert_eq!(audit.email, 1, "{dotted} -> {out}");
        assert!(out.starts_with("mail h1_email_"), "{out}");
        assert!(out.ends_with('.'), "{out}");
        assert!(!out.contains(mark), "{out}");
        assert!(!out.contains('@'), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), dotted);

        let pair = format!("a@b.co{mark}c@d.co");
        let (vault, out, audit) = shield(&pair);
        assert_eq!(audit.email, 2, "{pair} -> {out}");
        assert!(out.contains(mark), "{out}");
        assert!(!out.contains('@'), "{out}");
        assert_eq!(out.matches("h1_email_").count(), 2, "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), pair);

        let spaced = format!("note{mark} a@b.co");
        let (vault, out, audit) = shield(&spaced);
        assert_eq!(audit.email, 1, "{spaced} -> {out}");
        assert!(out.starts_with(&format!("note{mark} h1_email_")), "{out}");
        assert!(!out.contains('@'), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), spaced);

        let leading = format!("{mark}a@b.co");
        let (vault, out, audit) = shield(&leading);
        assert_eq!(audit.email, 1, "{leading} -> {out}");
        assert!(out.starts_with(&format!("{mark}h1_email_")), "{out}");
        assert!(!out.contains('@'), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), leading);

        let prose = format!("jean{mark}luc wrote a@b.co");
        let (vault, out, audit) = shield(&prose);
        assert_eq!(audit.email, 1, "{prose} -> {out}");
        assert!(
            out.starts_with(&format!("jean{mark}luc wrote h1_email_")),
            "{out}"
        );
        assert!(!out.contains('@'), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), prose);

        let raw = format!(r#"{{"to":"jean{mark}luc@example.com"}}"#);
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
        assert_eq!(audit.email, 1, "{raw} -> {out}");
        assert!(!out.contains('@'), "{out}");
        assert!(hidden(&out, "jean"), "{out}");
        assert!(!out.contains(mark), "{out}");
        assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

        for bare in [
            format!("jean{mark}luc habite ici"),
            format!("jean{mark}luc@home"),
            format!("marie.jean{mark}luc wrote"),
            format!("user@{mark}example.com"),
        ] {
            let (_vault, out, audit) = shield(&bare);
            assert_eq!(out, bare, "{bare} -> {out}");
            assert_eq!(audit.email, 0, "{bare} -> {out}");
        }
    }
}

#[test]
fn fullwidth_at_sign_still_shields_the_address() {
    // `user@example.com` is already an email. A wide keyboard writes
    // the at-sign as U+FF20. Leaving that sign out sends the address.
    // A bare sign, a missing domain, and a short tail stay as written.
    let at = '\u{FF20}';
    for (email, local, domain) in [
        (format!("user{at}example.com"), "user", "example"),
        (format!("marie+tag{at}example.com"), "marie", "example"),
        (format!("o'brien{at}example.com"), "brien", "example"),
        (format!("josé{at}example.com"), "josé", "example"),
        (format!("jose\u{0301}{at}example.com"), "jose", "example"),
        (format!("user{at}ex-ample.com"), "user", "ample"),
        (format!("user{at}société.fr"), "user", "société"),
        (format!("Jean-Luc{at}Example.COM"), "Jean", "Example"),
    ] {
        let (vault, out, audit) = shield(&email);
        assert_eq!(audit.email, 1, "{email} -> {out}");
        assert_eq!(audit.phone, 0, "{email} -> {out}");
        assert_eq!(audit.card, 0, "{email} -> {out}");
        assert_eq!(audit.sin, 0, "{email} -> {out}");
        assert!(out.starts_with("h1_email_"), "{email} -> {out}");
        assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
        assert!(!out.contains(at), "{email} -> {out}");
        assert!(!out.contains('@'), "{email} -> {out}");
        assert!(hidden(&out, local), "{email} -> {out}");
        assert!(hidden(&out, domain), "{email} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), email);
    }

    let sentence = format!("mail user{at}example.com today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains(at), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let dotted = format!("mail user{at}example.com.");
    let (vault, out, audit) = shield(&dotted);
    assert_eq!(audit.email, 1, "{dotted} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with('.'), "{out}");
    assert!(!out.contains(at), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), dotted);

    let wrapped = format!("(user{at}example.com)");
    let (vault, out, audit) = shield(&wrapped);
    assert_eq!(audit.email, 1, "{wrapped} -> {out}");
    assert!(out.starts_with("(h1_email_"), "{out}");
    assert!(out.ends_with(')'), "{out}");
    assert!(!out.contains(at), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), wrapped);

    let pair = format!("a@b.co and user{at}example.com");
    let (vault, out, audit) = shield(&pair);
    assert_eq!(audit.email, 2, "{pair} -> {out}");
    assert_eq!(out.matches("h1_email_").count(), 2, "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(!out.contains(at), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert!(hidden(&out, "b.co"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    let raw = format!(r#"{{"to":"user{at}example.com"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{raw} -> {out}");
    assert!(!out.contains(at), "{raw} -> {out}");
    assert!(!out.contains('@'), "{raw} -> {out}");
    assert!(hidden(&out, "example"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        format!("{at}example.com"),
        format!("user{at}example"),
        format!("user{at}example.c"),
        format!("user{at}.com"),
        format!("user {at} example.com"),
        format!("user{at}{at}example.com"),
        format!("cost {at} shipping"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn prose_name_is_not_a_hit() {
    let (_vault, out, audit) = shield("Marie lives in Montreal");
    assert_eq!(out, "Marie lives in Montreal");
    assert_eq!(audit.email, 0);
    assert_eq!(audit.glossary, 0);
    assert_eq!(audit.secret, 0);
}

#[test]
fn parentheses_around_an_international_group_still_shield_the_number() {
    // `+44 20 7946 0958` is already a phone. Parentheses around a group
    // are that same number (`+44 (20) 7946 0958`), including a trunk
    // zero written against the next group (`+33 (0)1 23 45 67 89`).
    for phone in [
        "+44 (20) 7946 0958",
        "+44(20)7946 0958",
        "+44 (20) 7946-0958",
        "+44 ( 20 ) 7946 0958",
        "+44 (0)20 7946 0958",
        "+44 (0) 20 7946 0958",
        "+33 (0)1 23 45 67 89",
        "+33 (0) 1 23 45 67 89",
        "+33 (0)6 12 34 56 78",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(!out.contains('('), "{phone} -> {out}");
        assert!(!out.contains(')'), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }
    let sentence = "call +44 (20) 7946 0958 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(!out.contains('('), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let pair = "call +44 (20) 7946 0958 or +33 (0)1 23 45 67 89 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(!out.contains('('), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(!out.contains("23 45"), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    for bare in [
        "+44 (20)79460958",
        "+44 (20)",
        "call (20) 7946 0958 today",
        "+33 (0)123456789",
        "9+44 (20) 7946 0958",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"+44 (20) 7946 0958"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "7946"), "{raw} -> {out}");
    assert!(!out.contains('('), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn longer_international_group_still_shields_the_number() {
    // `+44 20 7946 0958` is already a phone. Groups there are at most
    // four digits. `+44 7700 900123` is the same kind of number with a
    // six-digit subscriber block, and `+49 30 12345678` keeps eight
    // digits in the last group. Both stayed in the clear.
    for phone in [
        "+44 7700 900123",
        "+44-7700-900123",
        "+44 7700 - 900123",
        "+49 30 12345678",
        "+49-30-12345678",
        "+55 11 91234-5678",
        "+44 (0)7700 900123",
        "+44 (0) 7700 900123",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(!out.contains('+'), "{phone} -> {out}");
        assert!(!out.contains(phone), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }
    let sentence = "call +44 7700 900123 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "7700"), "{out}");
    assert!(hidden(&out, "900123"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let pair = "call +44 7700 900123 or +49 30 12345678 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(hidden(&out, "7700"), "{out}");
    assert!(hidden(&out, "12345678"), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    for bare in [
        "+44 7700900123",
        "+44 (20)79460958",
        "+44 (0)7700900123",
        "+33 (0)123456789",
        "9+44 7700 900123",
        "+44 7700 9001239999",
        "call 7700 900123 today",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"+44 7700 900123"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "7700"), "{raw} -> {out}");
    assert!(hidden(&out, "900123"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn whitespace_after_a_plus_still_shields_the_number() {
    // `+44 20 7946 0958` and `+14165550123` are already phones. A space
    // after the plus is that same number. `+ 1416-555-0123` left the
    // trunk digit in the clear, and `+ 7 495 123 4567` left the country
    // code because the tail is a 3-3-4 number.
    let nbsp = '\u{00a0}';
    let narrow = '\u{202f}';
    for phone in [
        "+ 44 20 7946 0958",
        "+  44  20  7946  0958",
        "+ 44 (20) 7946 0958",
        "+ 33 (0)1 23 45 67 89",
        "+ 33 (0) 1 23 45 67 89",
        "+ 44 7700 900123",
        "+ 1 416 555 0123",
        "+ 1 (416) 555-0123",
        "+ 1(416)555-0123",
        "+ 1416-555-0123",
        "+ 14165550123",
        "+ 12345678",
        "+ 7 495 123 4567",
        "+ 416 555 0123",
        &format!("+{nbsp}44 20 7946 0958"),
        &format!("+{narrow}33 1 23 45 67 89"),
        "+\t44 20 7946 0958",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(!out.contains('+'), "{phone} -> {out}");
        assert!(hidden(&out, "7946"), "{phone} -> {out}");
        assert!(hidden(&out, "416"), "{phone} -> {out}");
        assert!(hidden(&out, "1416"), "{phone} -> {out}");
        assert!(hidden(&out, "495"), "{phone} -> {out}");
        assert!(hidden(&out, "12345678"), "{phone} -> {out}");
        assert!(!out.contains(nbsp), "{phone} -> {out}");
        assert!(!out.contains(narrow), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = "call + 44 20 7946 0958 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains('+'), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let pair = "call + 44 20 7946 0958 or + 1416-555-0123 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(!out.contains('+'), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "1416"), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    for bare in [
        "+ 44 7700900123",
        "+ 44 (20)79460958",
        "+ 33 (0)123456789",
        "9+ 44 20 7946 0958",
        "44 20 7946 0958",
        "+ 1234567",
        "+ 1 4165550123",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"+ 44 20 7946 0958"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(!out.contains('+'), "{raw} -> {out}");
    assert!(hidden(&out, "7946"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn international_number_before_a_later_group_still_shields_the_number() {
    // `+44 20 7946 0958` is already a phone. A later separated group
    // makes one match longer than 15 digits. That length check rejects
    // the match, so the phone stays in the clear. A tail that still
    // fits in 15 digits stays inside the same phone.
    let en = '\u{2013}';
    for (text, tail) in [
        ("+44 20 7946 0958 9999", " 9999"),
        ("+44-20-7946-0958-9999", "-9999"),
        ("+44 20 7946 0958 - 9999", " - 9999"),
        ("+ 44 20 7946 0958 9999", " 9999"),
        ("+44 (20) 7946 0958 9999", " 9999"),
        ("+49 30 12345678 9999", " 9999"),
        ("+33 1 23 45 67 89 75001", " 75001"),
        ("+44 20 7946 0958 1111 2222", " 1111 2222"),
        (&format!("+44 20 7946 0958{en}9999"), &format!("{en}9999")),
    ] {
        let (vault, out, audit) = shield(text);
        assert_eq!(audit.phone, 1, "{text} -> {out}");
        assert_eq!(audit.card, 0, "{text} -> {out}");
        assert_eq!(audit.sin, 0, "{text} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{text} -> {out}");
        assert!(out.ends_with(tail), "{text} -> {out}");
        assert_eq!(
            out.len(),
            "h1_phone_".len() + 9 + tail.len(),
            "{text} -> {out}"
        );
        assert!(hidden(&out, "7946"), "{text} -> {out}");
        assert!(hidden(&out, "12345678"), "{text} -> {out}");
        assert!(!out.contains("23 45"), "{text} -> {out}");
        assert!(!out.contains('+'), "{text} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), text);
    }

    let inside = "+33 1 23 45 67 89 9999";
    let (vault, out, audit) = shield(inside);
    assert_eq!(audit.phone, 1, "{inside} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert_eq!(out.len(), "h1_phone_".len() + 9, "{out}");
    assert!(!out.contains('+'), "{out}");
    assert!(!out.contains(' '), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), inside);

    let sentence = "call +44 20 7946 0958 9999 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" 9999 today"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(!out.contains('+'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let pair = "call +44 20 7946 0958 9999 or +49 30 12345678 8888 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" 9999 or "), "{out}");
    assert!(out.contains(" 8888 "), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "12345678"), "{out}");
    assert!(!out.contains('+'), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    for bare in [
        "+44 7700 9001239999",
        "+44 (20)79460958 123456",
        "9+44 20 7946 0958 9999",
        "+44 20 999999999999999",
        "+12 3",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"+44 20 7946 0958 9999"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(visible(&out).contains("9999"), "{raw} -> {out}");
    assert!(hidden(&out, "7946"), "{raw} -> {out}");
    assert!(!out.contains("+44"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn shaped_phone_round_trip_and_bare_digits_stay() {
    for phone in [
        "+1 415 555 0134",
        "(415) 555-0134",
        "(416)555-0123",
        "415.555.0134",
        "+14155550134",
        "+44 20 7946 0958",
        "+1(416)555-0123",
        "1(416)555-0123",
        "+1(416) 555-0123",
        "1(416) 555-0123",
        "+1(416)555.0123",
        "+1416-555-0123",
        // Area code, slash, exchange, hyphen, line. Same groups as 416-555-0123.
        "416/555-0123",
        "416/555/0123",
        "(416)/555-0123",
        "1/800/555-0199",
        "+1 416/555-0123",
        // Non-breaking hyphen, the hyphen that stays on one line.
        "416\u{2011}555\u{2011}0123",
        "1\u{2011}800\u{2011}555\u{2011}0199",
        "+1\u{2011}416\u{2011}555\u{2011}0123",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }
    let sentence = "call +1(416)555-0123 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);
    let slashed = "call 416/555-0123 today";
    let (vault, out, audit) = shield(slashed);
    assert_eq!(audit.phone, 1, "{slashed} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), slashed);
    let unbroken = "call 416\u{2011}555\u{2011}0123 today";
    let (vault, out, audit) = shield(unbroken);
    assert_eq!(audit.phone, 1, "{unbroken} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), unbroken);
    for bare in [
        "4155550134",
        "(416)5550123",
        "14165550123",
        "+1(416)5550123",
        "1(416)5550123",
        "11(416)555-0123",
        "21(416)555-0123",
        // One separator, then a bare seven-digit tail, still stays.
        "416/5550123",
        "416\u{2011}5550123",
        "+1/4165550123",
        "+1\u{2011}4165550123",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
    }
}

#[test]
fn spaces_inside_a_canadian_area_code_still_shield_the_number() {
    // `(416) 555-0123` is already a phone. Spaces inside the parentheses
    // are that same number. `+1 ( 416 )` is already international. The
    // trunk form without a plus stayed in the clear, and so did a
    // non-breaking space or a tab in that gap.
    let nbsp = '\u{00a0}';
    for phone in [
        "( 416 ) 555-0123",
        "( 416) 555-0123",
        "(416 ) 555-0123",
        "(  416  ) 555-0123",
        "( 416 ) 555 - 0123",
        "1 ( 416 ) 555-0123",
        "1( 416 )555-0123",
        "1( 416 ) 555-0123",
        "+1 ( 416 ) 555-0123",
        "+1( 416 )555-0123",
        &format!("({nbsp}416{nbsp}) 555-0123"),
        "(\t416\t) 555-0123",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(!out.contains('('), "{phone} -> {out}");
        assert!(!out.contains(')'), "{phone} -> {out}");
        assert!(hidden(&out, "416"), "{phone} -> {out}");
        assert!(hidden(&out, "0123"), "{phone} -> {out}");
        assert!(!out.contains(nbsp), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = "call ( 416 ) 555-0123 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(!out.contains('('), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let glued_letter = "x( 416 ) 555-0123";
    let (vault, out, audit) = shield(glued_letter);
    assert_eq!(audit.phone, 1, "{glued_letter} -> {out}");
    assert!(out.starts_with("xh1_phone_"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), glued_letter);

    let pair = "call ( 416 ) 555-0123 or 1( 604 ) 555-0199 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(hidden(&out, "604"), "{out}");
    assert!(!out.contains('('), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    for bare in [
        "( 416 ) 5550123",
        "( 416 )5550123",
        "+1( 416 )5550123",
        "1 ( 416 ) 5550123",
        "( 416 ) 555-012",
        "( 416 ) 555-01234",
        "9( 416 ) 555-0123",
        "21( 416 ) 555-0123",
        "( 20 ) 7946 0958",
        "( see 416 ) 555-0123",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"( 416 ) 555-0123"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "416"), "{raw} -> {out}");
    assert!(!out.contains('('), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn shaped_card_and_cued_card_round_trip_bare_luhn_stays() {
    let grouped = "4111-1111-1111-1111";
    let (vault, out, audit) = shield(grouped);
    assert_eq!(audit.card, 1, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), grouped);

    let amex = "3782 822463 10005";
    let (vault, out, audit) = shield(amex);
    assert_eq!(audit.card, 1, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), amex);

    // Same digits as `amex`, in the other usual groups of four.
    for amex_fours in [
        "3782 8224 6310 005",
        "3782-8224-6310-005",
        "3782 8224-6310 005",
    ] {
        let (vault, out, audit) = shield(amex_fours);
        assert_eq!(audit.card, 1, "{amex_fours} -> {out}");
        assert_eq!(audit.phone, 0, "{amex_fours} -> {out}");
        assert!(out.starts_with("h1_card_"), "{amex_fours} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), amex_fours);
    }
    let cued_fours = "visa 3782 8224 6310 005";
    let (vault, out, audit) = shield(cued_fours);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert!(hidden(&out, "3782"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued_fours);
    let bad_fours = "3782 8224 6310 006";
    let (_vault, out, audit) = shield(bad_fours);
    assert_eq!(out, bad_fours);
    assert_eq!(audit.card, 0);
    let glued_fours = "3782 8224 6310 0051";
    let (_vault, out, audit) = shield(glued_fours);
    assert_eq!(out, glued_fours);
    assert_eq!(audit.card, 0);

    // Fourteen digits, groups of four, six, and four.
    for grouped_fourteen in ["3056 930902 5904", "3056-930902-5904", "3056 930902-5904"] {
        let (vault, out, audit) = shield(grouped_fourteen);
        assert_eq!(audit.card, 1, "{grouped_fourteen} -> {out}");
        assert_eq!(audit.phone, 0, "{grouped_fourteen} -> {out}");
        assert!(out.starts_with("h1_card_"), "{grouped_fourteen} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), grouped_fourteen);
    }
    let cued_fourteen = "card 3056 930902 5904";
    let (vault, out, audit) = shield(cued_fourteen);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("card h1_card_"), "{out}");
    assert!(hidden(&out, "3056"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued_fourteen);
    let bad_fourteen = "3056 930902 5905";
    let (_vault, out, audit) = shield(bad_fourteen);
    assert_eq!(out, bad_fourteen);
    assert_eq!(audit.card, 0);
    let glued_fourteen = "3056 930902 59041";
    let (_vault, out, audit) = shield(glued_fourteen);
    assert_eq!(out, glued_fourteen);
    assert_eq!(audit.card, 0);

    let cued = "visa 4111111111111111";
    let (vault, out, audit) = shield(cued);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let bare = "4111111111111111";
    let (_vault, out, audit) = shield(bare);
    assert_eq!(out, bare);
    assert_eq!(audit.card, 0);

    let bad = "4111-1111-1111-1112";
    let (_vault, out, audit) = shield(bad);
    assert_eq!(out, bad);
    assert_eq!(audit.card, 0);

    // Same groups, with a dot between them.
    for dotted in [
        "4111.1111.1111.1111",
        "3782.822463.10005",
        "3782.8224.6310.005",
        "3056.930902.5904",
    ] {
        let (vault, out, audit) = shield(dotted);
        assert_eq!(audit.card, 1, "{dotted} -> {out}");
        assert_eq!(audit.phone, 0, "{dotted} -> {out}");
        assert!(out.starts_with("h1_card_"), "{dotted} -> {out}");
        assert!(!out.contains(dotted), "{dotted} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), dotted);
    }
    let cued_dotted = "visa 4111.1111.1111.1111";
    let (vault, out, audit) = shield(cued_dotted);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert!(hidden(&out, "4111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued_dotted);
    let dotted_sentence = "pay visa 4111.1111.1111.1111 today.";
    let (vault, out, audit) = shield(dotted_sentence);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("pay visa h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(hidden(&out, "4111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), dotted_sentence);
    let bad_dotted = "4111.1111.1111.1112";
    let (_vault, out, audit) = shield(bad_dotted);
    assert_eq!(out, bad_dotted);
    assert_eq!(audit.card, 0);
    let glued_dotted = "4111.1111.1111.11111";
    let (_vault, out, audit) = shield(glued_dotted);
    assert_eq!(out, glued_dotted);
    assert_eq!(audit.card, 0);

    let raw = r#"{"visa":"4111.1111.1111.1111"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, "4111"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
    let bare_dotted = r#"{"n":"4111.1111.1111.1111"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), bare_dotted).unwrap();
    assert_eq!(audit.card, 1, "{bare_dotted} -> {out}");
    assert!(hidden(&out, "4111"), "{bare_dotted} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), bare_dotted);
}

#[test]
fn slash_between_card_groups_still_shields_the_number() {
    for slashed in [
        "4111/1111/1111/1111",
        "3782/8224/6310/005",
        "3056/930902/5904",
        "4111 / 1111 / 1111 / 1111",
    ] {
        let (vault, out, audit) = shield(slashed);
        assert_eq!(audit.card, 1, "{slashed} -> {out}");
        assert_eq!(audit.phone, 0, "{slashed} -> {out}");
        assert!(out.starts_with("h1_card_"), "{slashed} -> {out}");
        assert!(!out.contains('/'), "{slashed} -> {out}");
        for group in slashed.split(|ch: char| !ch.is_ascii_digit()) {
            if group.len() >= 4 {
                assert!(hidden(&out, group), "{slashed} -> {out}");
            }
        }
        assert_eq!(vault.restore_write(&out).unwrap(), slashed);
    }
    let sentence = "pay visa 4111/1111/1111/1111 today.";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.card, 1, "{sentence} -> {out}");
    assert!(out.starts_with("pay visa h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(hidden(&out, "4111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let raw = r#"{"visa":"4111/1111/1111/1111"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, "4111"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        "4111/1111/1111/1112",
        "4111/1111/1111/11111",
        "SIN 130/692/544",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn nineteen_digit_card_grouped_in_fours_round_trips() {
    // Both pass Luhn. `pan`'s first 16 digits also pass, so a shorter
    // match would leave the last group in the clear. `other`'s first 16
    // do not, so only the full 19-digit span qualifies.
    let pan = "4111111111111111110";
    let other = "4111111111111100006";
    for grouped in [
        format!(
            "{} {} {} {} {}",
            &pan[..4],
            &pan[4..8],
            &pan[8..12],
            &pan[12..16],
            &pan[16..]
        ),
        format!(
            "{}-{}-{}-{}-{}",
            &pan[..4],
            &pan[4..8],
            &pan[8..12],
            &pan[12..16],
            &pan[16..]
        ),
        format!(
            "{}.{}.{}.{}.{}",
            &pan[..4],
            &pan[4..8],
            &pan[8..12],
            &pan[12..16],
            &pan[16..]
        ),
        format!(
            "{} - {} - {} - {} - {}",
            &pan[..4],
            &pan[4..8],
            &pan[8..12],
            &pan[12..16],
            &pan[16..]
        ),
        format!(
            "{} {}-{}-{}.{}",
            &other[..4],
            &other[4..8],
            &other[8..12],
            &other[12..16],
            &other[16..]
        ),
        format!(
            "{}-{}-{}-{}-{}",
            &other[..4],
            &other[4..8],
            &other[8..12],
            &other[12..16],
            &other[16..]
        ),
    ] {
        let (vault, out, audit) = shield(&grouped);
        assert_eq!(audit.card, 1, "{grouped} -> {out}");
        assert_eq!(audit.phone, 0, "{grouped} -> {out}");
        assert!(out.starts_with("h1_card_"), "{grouped} -> {out}");
        assert!(
            !out.contains(' ') && !out.contains('-') && !out.contains('.'),
            "{grouped} -> {out}"
        );
        assert_eq!(vault.restore_write(&out).unwrap(), grouped);
    }

    let cued = format!(
        "visa {}-{}-{}-{}-{}",
        &other[..4],
        &other[4..8],
        &other[8..12],
        &other[12..16],
        &other[16..]
    );
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert!(hidden(&out, "1100006"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let sentence = format!("pay {cued} today.");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("pay visa h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(hidden(&out, "1100006"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    // A 16-digit card and a three-digit code are not one 19-digit card.
    let with_code = "4111-1111-1111-1111 123";
    let (vault, out, audit) = shield(with_code);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.ends_with(" 123"), "{out}");
    assert!(!out.contains("4111-1111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), with_code);

    let bad = "4111-1111-1111-1100-007";
    let (_vault, out, audit) = shield(bad);
    assert_eq!(out, bad, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let glued = "4111-1111-1111-1111-1101";
    let (vault, out, audit) = shield(glued);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.ends_with("-1101"), "{out}");
    assert!(!out.contains("4111-1111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), glued);

    let raw = format!(
        r#"{{"pan":"{}-{}-{}-{}-{}"}}"#,
        &other[..4],
        &other[4..8],
        &other[8..12],
        &other[12..16],
        &other[16..]
    );
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(!out.contains("1100-006"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn nineteen_digit_card_grouped_as_six_and_thirteen_round_trips() {
    // `4111 1111 1111 1111 110` is already a card. The same digits
    // grouped as six and thirteen stayed in the clear, including
    // beside a card cue. That cue only sees a contiguous digit run.
    let pan = "4111111111111111110";
    let other = "4111111111111100006";
    let en = '\u{2013}';
    for grouped in [
        format!("{} {}", &pan[..6], &pan[6..]),
        format!("{}-{}", &pan[..6], &pan[6..]),
        format!("{}.{}", &pan[..6], &pan[6..]),
        format!("{} - {}", &pan[..6], &pan[6..]),
        format!("{}-{}", &other[..6], &other[6..]),
        format!("{}{en}{}", &pan[..6], &pan[6..]),
    ] {
        let (vault, out, audit) = shield(&grouped);
        assert_eq!(audit.card, 1, "{grouped} -> {out}");
        assert_eq!(audit.phone, 0, "{grouped} -> {out}");
        assert_eq!(audit.sin, 0, "{grouped} -> {out}");
        assert!(out.starts_with("h1_card_"), "{grouped} -> {out}");
        assert!(
            !out.contains(' ') && !out.contains('-') && !out.contains('.') && !out.contains(en),
            "{grouped} -> {out}"
        );
        assert!(hidden(&out, &pan[..6]), "{grouped} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), grouped);
    }

    let cued = format!("card {} {}", &pan[..6], &pan[6..]);
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("card h1_card_"), "{out}");
    assert!(hidden(&out, &pan[..6]), "{out}");
    assert!(hidden(&out, &pan[6..]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let sentence = format!("pay {cued} today.");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("pay card h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(hidden(&out, &pan[..6]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    // A code after the number is not part of the card.
    let with_code = format!("{} {} 123", &pan[..6], &pan[6..]);
    let (vault, out, audit) = shield(&with_code);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.ends_with(" 123"), "{out}");
    assert!(hidden(&out, &pan[..6]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), with_code);

    let bad = format!("{} {}", &pan[..6], "1111111111111");
    let (_vault, out, audit) = shield(&bad);
    assert_eq!(out, bad, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let glued = format!("{} {}1", &pan[..6], &pan[6..]);
    let (_vault, out, audit) = shield(&glued);
    assert_eq!(out, glued, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let leading = format!("9{} {}", &pan[..6], &pan[6..]);
    let (_vault, out, audit) = shield(&leading);
    assert_eq!(out, leading, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let raw = format!(r#"{{"pan":"{} {}"}}"#, &pan[..6], &pan[6..]);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, &pan[..6]), "{raw} -> {out}");
    assert!(hidden(&out, &pan[6..]), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn thirteen_digit_card_grouped_as_four_four_five_round_trips() {
    // A 16-digit card grouped in fours is already a card. A 13-digit
    // Maestro number is printed as four, four, and five. Those groups
    // stayed in the clear, including beside a card cue, because that
    // cue only sees a contiguous digit run.
    let pan = {
        let body = "560000000000";
        format!("{body}{}", luhn_check_digit(body))
    };
    let other = {
        let body = "561111111111";
        format!("{body}{}", luhn_check_digit(body))
    };
    assert_eq!(pan, "5600000000002");
    assert_eq!(other, "5611111111117");
    let en = '\u{2013}';
    for grouped in [
        format!("{} {} {}", &pan[..4], &pan[4..8], &pan[8..]),
        format!("{}-{}-{}", &pan[..4], &pan[4..8], &pan[8..]),
        format!("{}.{}.{}", &pan[..4], &pan[4..8], &pan[8..]),
        format!("{} - {} - {}", &pan[..4], &pan[4..8], &pan[8..]),
        format!("{}-{}-{}", &other[..4], &other[4..8], &other[8..]),
        format!("{}{en}{}{en}{}", &pan[..4], &pan[4..8], &pan[8..]),
    ] {
        let (vault, out, audit) = shield(&grouped);
        assert_eq!(audit.card, 1, "{grouped} -> {out}");
        assert_eq!(audit.phone, 0, "{grouped} -> {out}");
        assert_eq!(audit.sin, 0, "{grouped} -> {out}");
        assert!(out.starts_with("h1_card_"), "{grouped} -> {out}");
        assert!(
            !out.contains(' ') && !out.contains('-') && !out.contains('.') && !out.contains(en),
            "{grouped} -> {out}"
        );
        assert!(hidden(&out, &pan[..4]), "{grouped} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), grouped);
    }

    let cued = format!("card {} {} {}", &pan[..4], &pan[4..8], &pan[8..]);
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("card h1_card_"), "{out}");
    assert!(hidden(&out, &pan[..4]), "{out}");
    assert!(hidden(&out, &pan[8..]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let sentence = format!("pay {cued} today.");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("pay card h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(hidden(&out, &pan[..4]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let with_code = format!("{} {} {} 123", &pan[..4], &pan[4..8], &pan[8..]);
    let (vault, out, audit) = shield(&with_code);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.ends_with(" 123"), "{out}");
    assert!(hidden(&out, &pan[..4]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), with_code);

    let bad = format!("{} {} {}", &pan[..4], &pan[4..8], "00003");
    let (_vault, out, audit) = shield(&bad);
    assert_eq!(out, bad, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let glued = format!("{} {} {}1", &pan[..4], &pan[4..8], &pan[8..]);
    let (_vault, out, audit) = shield(&glued);
    assert_eq!(out, glued, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let leading = format!("9{} {} {}", &pan[..4], &pan[4..8], &pan[8..]);
    let (_vault, out, audit) = shield(&leading);
    assert_eq!(out, leading, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let bare = pan.clone();
    let (_vault, out, audit) = shield(&bare);
    assert_eq!(out, bare, "{out}");
    assert_eq!(audit.card, 0, "{out}");

    let raw = format!(r#"{{"pan":"{} {} {}"}}"#, &pan[..4], &pan[4..8], &pan[8..]);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, &pan[..4]), "{raw} -> {out}");
    assert!(hidden(&out, &pan[8..]), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn sin_needs_a_cue_within_forty_characters() {
    let sin = valid_sin();
    let shaped = format!("SIN {} {} {}", &sin[0..3], &sin[3..6], &sin[6..9]);
    let (vault, out, audit) = shield(&shaped);
    assert_eq!(audit.sin, 1, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), shaped);

    let phrase = format!("numéro d'assurance sociale {sin}");
    let (vault, out, audit) = shield(&phrase);
    assert_eq!(audit.sin, 1, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phrase);

    let close = format!("NAS{}{sin}", ".".repeat(40));
    let (_vault, _out, audit) = shield(&close);
    assert_eq!(audit.sin, 1, "{close}");

    let far = format!("NAS{}{sin}", ".".repeat(41));
    let (_vault, out, audit) = shield(&far);
    assert_eq!(audit.sin, 0, "{out}");
    assert_eq!(out, far);

    let after = format!("{sin}{}social insurance", ".".repeat(40));
    let (_vault, _out, audit) = shield(&after);
    assert_eq!(audit.sin, 1);

    let (_vault, out, audit) = shield(&sin);
    assert_eq!(out, sin);
    assert_eq!(audit.sin, 0);
}

#[test]
fn dotted_sin_cue_still_shields_the_number() {
    let sin = valid_sin();
    for cued in [
        format!("S.I.N. {sin}"),
        format!("S. I. N. {sin}"),
        format!("s.i.n. {sin}"),
        format!("N.A.S. {sin}"),
        format!("N. A. S. {sin}"),
        format!("see S.I.N. {sin} today"),
        format!("S I N {sin}"),
        format!("N A S {sin}"),
        format!("s i n {sin}"),
    ] {
        let (vault, out, audit) = shield(&cued);
        assert_eq!(audit.sin, 1, "{cued} -> {out}");
        assert_eq!(audit.phone, 0, "{cued} -> {out}");
        assert!(hidden(&out, &sin), "{cued} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), cued);
    }

    let close = format!("S.I.N.{}{sin}", " ".repeat(40));
    let (_vault, _out, audit) = shield(&close);
    assert_eq!(audit.sin, 1, "{close}");

    let far = format!("S.I.N.{}{sin}", " ".repeat(41));
    let (_vault, out, audit) = shield(&far);
    assert_eq!(audit.sin, 0, "{far} -> {out}");
    assert_eq!(out, far);

    for bare in [
        sin.clone(),
        format!("S.I.NISTER {sin}"),
        format!("BUS.I.N {sin}"),
        format!("S.I.N. {}", "130692543"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn dots_between_sin_groups_still_shield_the_number() {
    // `SIN 130 692 544` is already a SIN, and so is `130 - 692 - 544`.
    // Dots between those groups are that same number. A card and a phone
    // already treat a dot as a separator. Leaving the dot out sends the
    // digits. A slash is not this separator, and a trailing period stays.
    let sin = valid_sin();
    let dotted = format!("{}.{}.{}", &sin[..3], &sin[3..6], &sin[6..]);
    let spaced_dots = format!("{} . {} . {}", &sin[..3], &sin[3..6], &sin[6..]);
    let mixed = format!("{}.{}-{}", &sin[..3], &sin[3..6], &sin[6..]);
    for text in [
        format!("SIN {dotted}"),
        format!("NAS {dotted}"),
        format!("social insurance {dotted}"),
        format!("numéro d'assurance sociale {dotted}"),
        format!("numero d'assurance sociale {spaced_dots}"),
        format!("SIN {mixed}"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.sin, 1, "{text} -> {out}");
        assert_eq!(audit.phone, 0, "{text} -> {out}");
        assert_eq!(audit.card, 0, "{text} -> {out}");
        assert!(out.contains("h1_sin_"), "{text} -> {out}");
        assert!(hidden(&out, &sin), "{text} -> {out}");
        assert!(hidden(&out, &sin[..3]), "{text} -> {out}");
        assert!(hidden(&out, &sin[3..6]), "{text} -> {out}");
        assert!(hidden(&out, &sin[6..]), "{text} -> {out}");
        assert!(!out.contains(&dotted), "{text} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), text);
    }

    let sentence = format!("the SIN is {dotted} today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.sin, 1, "{sentence} -> {out}");
    assert!(out.starts_with("the SIN is h1_sin_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert!(!out.contains('.'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let ended = format!("see SIN {dotted}.");
    let (vault, out, audit) = shield(&ended);
    assert_eq!(audit.sin, 1, "{ended} -> {out}");
    assert!(out.starts_with("see SIN h1_sin_"), "{ended} -> {out}");
    assert!(out.ends_with('.'), "{ended} -> {out}");
    assert_eq!(
        out.len(),
        "see SIN h1_sin_".len() + 9 + 1,
        "{ended} -> {out}"
    );
    assert_eq!(out.matches('.').count(), 1, "{ended} -> {out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), ended);

    let pair = format!(
        "SIN {dotted} and NAS {} {} {}",
        &sin[..3],
        &sin[3..6],
        &sin[6..]
    );
    let (vault, out, audit) = shield(&pair);
    assert_eq!(audit.sin, 2, "{pair} -> {out}");
    assert!(out.starts_with("SIN h1_sin_"), "{out}");
    assert!(out.contains(" and NAS h1_sin_"), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert!(!out.contains('.'), "{out}");
    assert_eq!(out.matches("h1_sin_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    let mut bad_digits = sin.clone();
    let last = bad_digits.pop().unwrap();
    bad_digits.push(if last == '9' {
        '0'
    } else {
        (last as u8 + 1) as char
    });
    let bad = format!(
        "SIN {}.{}.{}",
        &bad_digits[..3],
        &bad_digits[3..6],
        &bad_digits[6..]
    );
    // Two extra digits are not a 3-3-4 phone and not a 9-digit SIN.
    let glued = format!("SIN {dotted}91");
    let leading = format!("SIN 9{dotted}");
    let one_dot = format!("SIN {}.{}", &sin[..3], &sin[3..]);
    let slashed = format!("SIN {}/{}/{}", &sin[..3], &sin[3..6], &sin[6..]);
    for bare in [
        dotted.clone(),
        format!("call {dotted} today"),
        bad,
        glued,
        leading,
        one_dot,
        slashed,
        format!("SIN {}.{}.{}", &sin[..3], &sin[3..5], &sin[5..]),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    // One extra digit is ten digits in a 3-3-4 shape, so it is a phone.
    // The digits still do not stay.
    let ten = format!("SIN {dotted}1");
    let (vault, out, audit) = shield(&ten);
    assert_eq!(audit.phone, 1, "{ten} -> {out}");
    assert_eq!(audit.sin, 0, "{ten} -> {out}");
    assert!(out.starts_with("SIN h1_phone_"), "{ten} -> {out}");
    assert!(hidden(&out, &sin), "{ten} -> {out}");
    assert!(hidden(&out, &format!("{}1", &sin[6..])), "{ten} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), ten);

    let phone = "415.555.0134";
    let (vault, out, audit) = shield(phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert_eq!(audit.sin, 0, "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let card = "4111.1111.1111.1111";
    let (vault, out, audit) = shield(card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert_eq!(audit.sin, 0, "{card} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let raw = format!(r#"{{"nas":"{dotted}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.sin, 1, "{raw} -> {out}");
    assert!(hidden(&out, &sin), "{raw} -> {out}");
    assert!(!out.contains(&dotted), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let nested = format!(r#"{{"note":"SIN {dotted} today"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &nested).unwrap();
    assert_eq!(audit.sin, 1, "{nested} -> {out}");
    assert!(hidden(&out, &sin), "{nested} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), nested);
}

#[test]
fn whitespace_inside_a_cue_still_shields_the_number() {
    // `SIN 130692544` and `social insurance 130692544` are already SINs.
    // A non-breaking space, a thin space, or a tab between the cue words
    // is still that cue. Leaving it out sends the digits. `american express`
    // before a continuous card is the same gap: `card` is not in that phrase.
    let sin = valid_sin();
    let nbsp = '\u{00a0}';
    let thin = '\u{2009}';
    let narrow = '\u{202f}';
    let pan = "4111111111111111";
    for text in [
        format!("social{nbsp}insurance {sin}"),
        format!("social{thin}insurance {sin}"),
        format!("social{narrow}insurance {sin}"),
        format!("social\tinsurance {sin}"),
        format!("social  insurance {sin}"),
        format!("Social{nbsp}Insurance {sin}"),
        format!("numéro d'assurance{nbsp}sociale {sin}"),
        format!("numero d'assurance{nbsp}sociale {sin}"),
        format!("numéro{nbsp}d'assurance sociale {sin}"),
        format!("social{nbsp}insurance{}{sin}", ".".repeat(40)),
        format!(
            "social{nbsp}insurance {} {} {}",
            &sin[..3],
            &sin[3..6],
            &sin[6..]
        ),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.sin, 1, "{text} -> {out}");
        assert_eq!(audit.card, 0, "{text} -> {out}");
        assert_eq!(audit.phone, 0, "{text} -> {out}");
        assert!(out.contains("h1_sin_"), "{text} -> {out}");
        assert!(hidden(&out, &sin), "{text} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), text);
    }

    let sentence = format!("the social{nbsp}insurance is {sin} today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.sin, 1, "{sentence} -> {out}");
    assert!(out.starts_with("the social"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(nbsp), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let card = format!("american{nbsp}express {pan}");
    let (vault, out, audit) = shield(&card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert_eq!(audit.sin, 0, "{card} -> {out}");
    assert!(
        out.starts_with(&format!("american{nbsp}express h1_card_")),
        "{out}"
    );
    assert!(hidden(&out, pan), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let plain = format!("american express {pan}");
    let (vault, out, audit) = shield(&plain);
    assert_eq!(audit.card, 1, "{plain} -> {out}");
    assert!(hidden(&out, pan), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), plain);

    for bare in [
        format!("socialinsurance {sin}"),
        format!("social{nbsp}insurance"),
        format!("american{nbsp}express"),
        format!("american{nbsp}express 4111111111111112"),
        format!("social{nbsp}insurance{}{sin}", ".".repeat(41)),
        sin.clone(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    let raw = format!("{{\"note\":\"social{nbsp}insurance {sin}\"}}");
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.sin, 1, "{raw} -> {out}");
    assert!(hidden(&out, &sin), "{raw} -> {out}");
    assert!(out.contains(nbsp), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let card_raw = format!("{{\"note\":\"american{nbsp}express {pan}\"}}");
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &card_raw).unwrap();
    assert_eq!(audit.card, 1, "{card_raw} -> {out}");
    assert!(hidden(&out, pan), "{card_raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), card_raw);
}

#[test]
fn hyphen_between_cue_words_still_shields_the_number() {
    // `american express 4111111111111111` is already a card, and
    // `social insurance 130692544` is already a SIN. A hyphen between
    // those words is still that cue. An ASCII hyphen is not the only
    // mark. An en dash, a non-breaking hyphen, a minus sign, or a soft
    // hyphen leaves the digits in the clear. Neither phrase contains a
    // shorter cue.
    let sin = valid_sin();
    let pan = "4111111111111111";
    let marks = [
        '-', '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2212}', '\u{00ad}',
    ];
    for mark in marks {
        let card = format!("american{mark}express {pan}");
        let (vault, out, audit) = shield(&card);
        assert_eq!(audit.card, 1, "{card} -> {out}");
        assert_eq!(audit.sin, 0, "{card} -> {out}");
        assert_eq!(audit.phone, 0, "{card} -> {out}");
        assert!(
            out.starts_with(&format!("american{mark}express h1_card_")),
            "{out}"
        );
        assert!(out.contains(mark), "{card} -> {out}");
        assert!(hidden(&out, pan), "{card} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), card);

        let spaced = format!("american {mark} express {pan}");
        let (vault, out, audit) = shield(&spaced);
        assert_eq!(audit.card, 1, "{spaced} -> {out}");
        assert!(hidden(&out, pan), "{spaced} -> {out}");
        assert!(out.contains(mark), "{spaced} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), spaced);

        let social = format!("social{mark}insurance {sin}");
        let (vault, out, audit) = shield(&social);
        assert_eq!(audit.sin, 1, "{social} -> {out}");
        assert_eq!(audit.card, 0, "{social} -> {out}");
        assert!(
            out.starts_with(&format!("social{mark}insurance h1_sin_")),
            "{out}"
        );
        assert!(out.contains(mark), "{social} -> {out}");
        assert!(hidden(&out, &sin), "{social} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), social);

        let french = format!("numéro{mark}d'assurance{mark}sociale {sin}");
        let (vault, out, audit) = shield(&french);
        assert_eq!(audit.sin, 1, "{french} -> {out}");
        assert!(hidden(&out, &sin), "{french} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), french);

        let plain = format!("numero{mark}d'assurance{mark}sociale {sin}");
        let (vault, out, audit) = shield(&plain);
        assert_eq!(audit.sin, 1, "{plain} -> {out}");
        assert!(hidden(&out, &sin), "{plain} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), plain);
    }

    let sentence = format!("pay with american-express {pan} today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.card, 1, "{sentence} -> {out}");
    assert!(
        out.starts_with("pay with american-express h1_card_"),
        "{out}"
    );
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, pan), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let pair = format!("american-express {pan} and social-insurance {sin}");
    let (vault, out, audit) = shield(&pair);
    assert_eq!(audit.card, 1, "{pair} -> {out}");
    assert_eq!(audit.sin, 1, "{pair} -> {out}");
    assert!(out.starts_with("american-express h1_card_"), "{out}");
    assert!(out.contains(" and social-insurance h1_sin_"), "{out}");
    assert!(hidden(&out, pan), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    let near = format!("american-express{}{pan}", ".".repeat(40));
    let (vault, out, audit) = shield(&near);
    assert_eq!(audit.card, 1, "{near} -> {out}");
    assert!(hidden(&out, pan), "{near} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), near);

    for bare in [
        format!("americanexpress {pan}"),
        format!("american/express {pan}"),
        format!("american_express {pan}"),
        format!("american, express {pan}"),
        format!("american-express{pan}"),
        format!("american-express {}", "4111111111111112"),
        format!("socialinsurance {sin}"),
        format!("social/insurance {sin}"),
        format!("social_insurance {sin}"),
        format!("social-insurance{sin}"),
        format!("american-express{}{pan}", ".".repeat(41)),
        format!("social-insurance{}{sin}", ".".repeat(41)),
        pan.to_string(),
        sin.clone(),
        "american-express".to_string(),
        "social-insurance".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    let raw = format!(r#"{{"american-express":"{pan}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, pan), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let as_number = format!(r#"{{"american-express":{pan}}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &as_number).unwrap();
    assert_eq!(audit.card, 1, "{as_number} -> {out}");
    assert!(hidden(&out, pan), "{as_number} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), as_number);

    let sin_raw = format!(r#"{{"social-insurance":"{sin}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &sin_raw).unwrap();
    assert_eq!(audit.sin, 1, "{sin_raw} -> {out}");
    assert!(hidden(&out, &sin), "{sin_raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), sin_raw);

    let nested = format!(r#"{{"note":"{{\"numéro-d'assurance-sociale\":\"{sin}\"}}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &nested).unwrap();
    assert_eq!(audit.sin, 1, "{nested} -> {out}");
    assert!(hidden(&out, &sin), "{nested} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), nested);
}

#[test]
fn spaces_around_a_group_separator_still_shield_the_value() {
    for phone in [
        "416 - 555 - 0123",
        "(416) 555 - 0123",
        "(416) - 555 - 0123",
        "1 - 800 - 555 - 0199",
        "+1 416 - 555 - 0123",
        "+1 - 416 - 555 - 0123",
        "416  555  0123",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert!(!out.contains('-'), "{phone} -> {out}");
        assert!(!out.contains(' '), "{phone} -> {out}");
        assert!(!out.contains('('), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }
    let sentence = "call 416 - 555 - 0123 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(hidden(&out, "0123"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    for grouped in [
        "4111 - 1111 - 1111 - 1111",
        "3782 - 822463 - 10005",
        "3782 - 8224 - 6310 - 005",
        "3056 - 930902 - 5904",
    ] {
        let (vault, out, audit) = shield(grouped);
        assert_eq!(audit.card, 1, "{grouped} -> {out}");
        assert_eq!(audit.phone, 0, "{grouped} -> {out}");
        assert!(out.starts_with("h1_card_"), "{grouped} -> {out}");
        assert!(!out.contains('-'), "{grouped} -> {out}");
        assert!(!out.contains(' '), "{grouped} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), grouped);
    }
    let bad = "4111 - 1111 - 1111 - 1112";
    let (_vault, out, audit) = shield(bad);
    assert_eq!(out, bad);
    assert_eq!(audit.card, 0);
    let glued = "4111 - 1111 - 1111 - 11111";
    let (_vault, out, audit) = shield(glued);
    assert_eq!(out, glued);
    assert_eq!(audit.card, 0);

    let sin = valid_sin();
    let spaced = format!("{} - {} - {}", &sin[..3], &sin[3..6], &sin[6..9]);
    let cued = format!("SIN {spaced}");
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.sin, 1, "{cued} -> {out}");
    assert_eq!(audit.phone, 0, "{cued} -> {out}");
    assert!(out.starts_with("SIN h1_sin_"), "{out}");
    assert!(!out.contains('-'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);
    let (_vault, out, audit) = shield(&spaced);
    assert_eq!(out, spaced, "{spaced}");
    assert_eq!(audit.sin, 0);

    // A space or a spaced hyphen in only one gap is not the 3-3-4 shape.
    for bare in ["416 - 5550123", "416  5550123", "416 - 555 - 012"] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
    }

    let raw = r#"{"n":"4111 - 1111 - 1111 - 1111"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, "4111"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let sin_raw = format!(r#"{{"nas":"{spaced}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &sin_raw).unwrap();
    assert_eq!(audit.sin, 1, "{sin_raw} -> {out}");
    assert!(!out.contains(&spaced), "{sin_raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), sin_raw);
}

#[test]
fn dash_punctuation_still_separates_a_grouped_number() {
    // U+2012 is the figure dash Unicode assigns to a telephone number.
    // U+2013 is the en dash a word processor inserts for a hyphen.
    // U+2011 already separates a phone. The same mark between card or
    // SIN groups is still that number.
    let figure = '\u{2012}';
    let en = '\u{2013}';
    let nb = '\u{2011}';

    for phone in [
        format!("416{figure}555{figure}0123"),
        format!("416{en}555{en}0123"),
        format!("416 {en} 555 {en} 0123"),
        format!("416{en}555-0123"),
        format!("(416){en}555{en}0123"),
        format!("+1{en}416{en}555{en}0123"),
        format!("1{figure}800{figure}555{figure}0199"),
    ] {
        let (vault, out, audit) = shield(&phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }
    let sentence = format!("call 416{en}555{en}0123 today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(hidden(&out, "0123"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    for grouped in [
        format!("4111{en}1111{en}1111{en}1111"),
        format!("4111{nb}1111{nb}1111{nb}1111"),
        format!("3782{figure}822463{figure}10005"),
        format!("3782{en}8224{en}6310{en}005"),
        format!("3056{en}930902{en}5904"),
        format!("4111{en}1111{en}1111{en}1111{en}110"),
    ] {
        let (vault, out, audit) = shield(&grouped);
        assert_eq!(audit.card, 1, "{grouped} -> {out}");
        assert_eq!(audit.phone, 0, "{grouped} -> {out}");
        assert!(out.starts_with("h1_card_"), "{grouped} -> {out}");
        assert_eq!(out.len(), "h1_card_".len() + 9, "{grouped} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), grouped);
    }
    let cued = format!("visa 4111{en}1111{en}1111{en}1111");
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert!(hidden(&out, "4111"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let sin = valid_sin();
    let dashed = format!("{}{figure}{}{figure}{}", &sin[..3], &sin[3..6], &sin[6..]);
    let cued_sin = format!("SIN {dashed}");
    let (vault, out, audit) = shield(&cued_sin);
    assert_eq!(audit.sin, 1, "{cued_sin} -> {out}");
    assert_eq!(audit.phone, 0, "{cued_sin} -> {out}");
    assert!(out.starts_with("SIN h1_sin_"), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert!(!out.contains(figure), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued_sin);

    for bare in [
        format!("416{en}5550123"),
        format!("416{en}555 office{en}0123"),
        format!("416{figure}555{figure}012"),
        format!("4111{en}1111{en}1111{en}1112"),
        format!("4111{en}1111{en}1111{en}11111"),
        dashed.clone(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
    }

    let raw = format!(r#"{{"n":"416{en}555{en}0123"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "416"), "{raw} -> {out}");
    assert!(!out.contains(en), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let sin_raw = format!(r#"{{"nas":"{dashed}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &sin_raw).unwrap();
    assert_eq!(audit.sin, 1, "{sin_raw} -> {out}");
    assert!(!out.contains(&dashed), "{sin_raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), sin_raw);
}

#[test]
fn minus_sign_or_soft_hyphen_still_separates_a_grouped_number() {
    // `416-555-0123` and `4111-1111-1111-1111` are already grouped
    // numbers when the hyphen is dash punctuation. U+2212 MINUS SIGN
    // and U+00AD SOFT HYPHEN are that same separator. Leaving either
    // one out sends the digits. A bare tail and a single subscriber
    // block stay as written.
    let minus = '\u{2212}';
    let soft = '\u{00ad}';
    for mark in [minus, soft] {
        for phone in [
            format!("416{mark}555{mark}0123"),
            format!("416 {mark} 555 {mark} 0123"),
            format!("(416){mark}555{mark}0123"),
            format!("+1{mark}416{mark}555{mark}0123"),
            format!("+44{mark}20{mark}7946{mark}0958"),
            format!("+44 (20){mark}7946{mark}0958"),
            format!("+33 (0)1{mark}23{mark}45{mark}67{mark}89"),
        ] {
            let (vault, out, audit) = shield(&phone);
            assert_eq!(audit.phone, 1, "{phone} -> {out}");
            assert_eq!(audit.card, 0, "{phone} -> {out}");
            assert_eq!(audit.sin, 0, "{phone} -> {out}");
            assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
            assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
            assert!(!out.contains(mark), "{phone} -> {out}");
            assert_eq!(vault.restore_write(&out).unwrap(), phone);
        }

        let sentence = format!("call 416{mark}555{mark}0123 today");
        let (vault, out, audit) = shield(&sentence);
        assert_eq!(audit.phone, 1, "{sentence} -> {out}");
        assert!(out.starts_with("call h1_phone_"), "{out}");
        assert!(out.ends_with(" today"), "{out}");
        assert!(hidden(&out, "416"), "{out}");
        assert!(hidden(&out, "0123"), "{out}");
        assert!(!out.contains(mark), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), sentence);

        for grouped in [
            format!("4111{mark}1111{mark}1111{mark}1111"),
            format!("3782{mark}822463{mark}10005"),
            format!("4111 {mark} 1111 {mark} 1111 {mark} 1111"),
        ] {
            let (vault, out, audit) = shield(&grouped);
            assert_eq!(audit.card, 1, "{grouped} -> {out}");
            assert_eq!(audit.phone, 0, "{grouped} -> {out}");
            assert!(out.starts_with("h1_card_"), "{grouped} -> {out}");
            assert_eq!(out.len(), "h1_card_".len() + 9, "{grouped} -> {out}");
            assert!(!out.contains(mark), "{grouped} -> {out}");
            assert_eq!(vault.restore_write(&out).unwrap(), grouped);
        }

        let cued = format!("visa 4111{mark}1111{mark}1111{mark}1111");
        let (vault, out, audit) = shield(&cued);
        assert_eq!(audit.card, 1, "{cued} -> {out}");
        assert!(out.starts_with("visa h1_card_"), "{out}");
        assert!(hidden(&out, "4111"), "{out}");
        assert!(!out.contains(mark), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), cued);

        let sin = valid_sin();
        let dashed = format!("{}{mark}{}{mark}{}", &sin[..3], &sin[3..6], &sin[6..]);
        let cued_sin = format!("SIN {dashed}");
        let (vault, out, audit) = shield(&cued_sin);
        assert_eq!(audit.sin, 1, "{cued_sin} -> {out}");
        assert_eq!(audit.phone, 0, "{cued_sin} -> {out}");
        assert!(out.starts_with("SIN h1_sin_"), "{out}");
        assert!(hidden(&out, &sin), "{out}");
        assert!(!out.contains(mark), "{out}");
        assert_eq!(vault.restore_write(&out).unwrap(), cued_sin);

        for bare in [
            format!("416{mark}5550123"),
            format!("416{mark}555 office{mark}0123"),
            format!("+44{mark}7700900123"),
            format!("4111{mark}1111{mark}1111{mark}1112"),
            format!("4111{mark}1111{mark}1111{mark}11111"),
            dashed.clone(),
        ] {
            let (_vault, out, audit) = shield(&bare);
            assert_eq!(out, bare, "{bare} -> {out}");
            assert_eq!(audit.phone, 0, "{bare} -> {out}");
            assert_eq!(audit.card, 0, "{bare} -> {out}");
            assert_eq!(audit.sin, 0, "{bare} -> {out}");
        }

        let raw = format!(r#"{{"n":"416{mark}555{mark}0123"}}"#);
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
        assert_eq!(audit.phone, 1, "{raw} -> {out}");
        assert!(hidden(&out, "416"), "{raw} -> {out}");
        assert!(!out.contains(mark), "{raw} -> {out}");
        assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

        let sin_raw = format!(r#"{{"nas":"{dashed}"}}"#);
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &sin_raw).unwrap();
        assert_eq!(audit.sin, 1, "{sin_raw} -> {out}");
        assert!(!out.contains(&dashed), "{sin_raw} -> {out}");
        assert_eq!(restore_json_write(&vault, &out).unwrap(), sin_raw);
    }
}

#[test]
fn underscore_before_an_api_key_name_still_masks_the_value() {
    let secret = "a".repeat(16);
    for text in [
        format!("MY_API_KEY={secret}"),
        format!("APP_SECRET_KEY={secret}"),
        format!("X_ACCESS_TOKEN={secret}"),
        format!("export MY_API_KEY={secret} please"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(!out.contains(&secret), "{text} -> {out}");
        assert!(out.contains("h1_secret"), "{text} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{text}");
        assert!(!vault.holds_surface(text.as_bytes()), "{text}");
    }
    let exported = format!("export MY_API_KEY={secret} please");
    let (_vault, out, _) = shield(&exported);
    assert_eq!(out, "export h1_secret please");
    let paired = format!("MY_API_KEY={secret} APP_SECRET_KEY={secret}");
    let (vault, out, audit) = shield(&paired);
    assert_eq!(audit.secret, 2, "{paired} -> {out}");
    assert!(!out.contains(&secret), "{paired} -> {out}");
    assert!(!vault.holds_surface(secret.as_bytes()));
    let hyphen = format!("api-key: {secret}");
    let (_vault, out, audit) = shield(&hyphen);
    assert_eq!(audit.secret, 1, "{hyphen} -> {out}");
    assert_eq!(out, "h1_secret");

    for text in [
        format!("MY_API_KEY={}", "a".repeat(15)),
        format!("somethingapi_key={secret}"),
        format!("secret={secret}"),
    ] {
        let (_vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 0, "{text} -> {out}");
        assert_eq!(out, text);
    }
}

#[test]
fn json_quote_between_an_api_key_name_and_the_value_still_masks_it() {
    let secret = "a".repeat(16);
    let raw = format!(r#"{{"api_key":"{secret}"}}"#);
    let (vault, out, audit) = shield(&raw);
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"h1_secret"}"#);
    assert!(!out.contains(&secret), "{out}");
    assert!(!vault.holds_surface(secret.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for raw in [
        format!(r#"{{"api_key": "{secret}"}}"#),
        format!(r#"{{"MY_API_KEY":"{secret}"}}"#),
        format!(r#"{{"api-key":"{secret}"}}"#),
        format!(r#"{{"APP_SECRET_KEY":"{secret}"}}"#),
        format!(r#"{{"X_ACCESS_TOKEN":"{secret}"}}"#),
        format!(r#"{{"auth_token":"{secret}"}}"#),
        format!("{{\n  \"api_key\": \"{secret}\"\n}}"),
    ] {
        let (vault, out, audit) = shield(&raw);
        assert_eq!(audit.secret, 1, "{raw} -> {out}");
        assert!(!out.contains(&secret), "{raw} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{raw}");
    }

    let quoted = format!("api_key=\"{secret}\"");
    let (_vault, out, audit) = shield(&quoted);
    assert_eq!(audit.secret, 1, "{quoted} -> {out}");
    assert_eq!(out, "h1_secret\"");
    let single = format!("api_key='{secret}'");
    let (_vault, out, audit) = shield(&single);
    assert_eq!(audit.secret, 1, "{single} -> {out}");
    assert_eq!(out, "h1_secret'");

    let documents = [
        (
            format!(r#"{{"api_key":"{secret}"}}"#),
            r#"{"api_key":"h1_secret"}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"api_key": "{secret}"}}"#),
            r#"{"api_key": "h1_secret"}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"MY_API_KEY":"{secret}"}}"#),
            r#"{"MY_API_KEY":"h1_secret"}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"api-key":"{secret}"}}"#),
            r#"{"api-key":"h1_secret"}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"APP_SECRET_KEY":"{secret}","X_ACCESS_TOKEN":"{secret}"}}"#),
            r#"{"APP_SECRET_KEY":"h1_secret","X_ACCESS_TOKEN":"h1_secret"}"#.to_string(),
            2,
            0,
        ),
        (
            format!("{{\n  \"auth_token\": \"{secret}\"\n}}"),
            "{\n  \"auth_token\": \"h1_secret\"\n}".to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"cfg":"{{\"api_key\":\"{secret}\"}}"}}"#),
            r#"{"cfg":"{\"api_key\":\"h1_secret\"}"}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"wrap":{{"secret_key":"{secret}"}}}}"#),
            r#"{"wrap":{"secret_key":"h1_secret"}}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"api_key":"{secret} a@b.co"}}"#),
            String::new(),
            1,
            1,
        ),
        (
            r#"{"api_key":"4111-1111-1111-1111"}"#.to_string(),
            r#"{"api_key":"h1_secret"}"#.to_string(),
            1,
            0,
        ),
        (
            format!(r#"{{"api_key":"sk-{}"}}"#, "b".repeat(20)),
            r#"{"api_key":"h1_secret"}"#.to_string(),
            1,
            0,
        ),
        (
            r#"{"api_key":1234567890123456}"#.to_string(),
            r#"{"api_key":"h1_secret"}"#.to_string(),
            1,
            0,
        ),
    ];
    for (input, expect, secrets, emails) in documents {
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &input).unwrap();
        assert_eq!(audit.secret, secrets, "{input} -> {out}");
        assert_eq!(audit.email, emails, "{input} -> {out}");
        assert_eq!(audit.card, 0, "{input} -> {out}");
        assert!(!out.contains(&secret), "{input} -> {out}");
        assert!(!out.contains("4111-1111-1111-1111"), "{input} -> {out}");
        assert!(!out.contains("1234567890123456"), "{input} -> {out}");
        assert!(!out.contains("a@b.co"), "{input} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{input}");
        assert!(!vault.holds_surface(b"4111-1111-1111-1111"), "{input}");
        assert!(!vault.holds_surface(b"1234567890123456"), "{input}");
        if !expect.is_empty() {
            assert_eq!(out, expect, "{input}");
        } else {
            assert!(out.starts_with(r#"{"api_key":"h1_secret "#), "{out}");
            assert!(out.contains("h1_email_"), "{out}");
        }
        assert!(restore_json_write(&vault, &out).is_err(), "{out}");
    }

    for input in [
        format!(r#"{{"api_key":"{}"}}"#, "a".repeat(15)),
        format!(r#"{{"note":"{secret}"}}"#),
        format!(r#"{{"somethingapi_key":"{secret}"}}"#),
        format!(r#"{{"secret":"{secret}"}}"#),
        format!(r#"{{"api_key":"short","n":"{secret}"}}"#),
        r#"{"api_key":12345}"#.to_string(),
    ] {
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &input).unwrap();
        assert_eq!(audit.secret, 0, "{input} -> {out}");
        assert_eq!(audit.email, 0, "{input} -> {out}");
        assert_eq!(out, input);
    }
}

#[test]
fn hyphen_mark_in_an_api_key_name_still_masks_the_value() {
    // `api-key=...` is already a secret. The hyphen in that name may be
    // an en dash, a non-breaking hyphen, a minus sign, or a soft hyphen.
    // Those marks are not an ASCII hyphen. Leaving them out sends the value.
    let secret = "a".repeat(16);
    let marks = [
        '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2212}', '\u{00ad}',
    ];
    for mark in marks {
        for text in [
            format!("api{mark}key={secret}"),
            format!("secret{mark}key: {secret}"),
            format!("access{mark}token={secret}"),
            format!("auth{mark}token: {secret}"),
            format!("APP_API{mark}KEY={secret}"),
            format!("X_ACCESS{mark}TOKEN={secret}"),
            format!("export api{mark}key={secret} please"),
        ] {
            let (vault, out, audit) = shield(&text);
            assert_eq!(audit.secret, 1, "{text} -> {out}");
            assert_eq!(audit.card, 0, "{text} -> {out}");
            assert!(!out.contains(&secret), "{text} -> {out}");
            assert!(out.contains("h1_secret"), "{text} -> {out}");
            assert!(!out.contains(mark), "{text} -> {out}");
            assert!(!vault.holds_surface(secret.as_bytes()), "{text}");
            assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
        }

        let exported = format!("export api{mark}key={secret} please");
        let (_vault, out, _) = shield(&exported);
        assert_eq!(out, "export h1_secret please", "{exported} -> {out}");

        let paired = format!("api{mark}key={secret} secret{mark}key={secret}");
        let (vault, out, audit) = shield(&paired);
        assert_eq!(audit.secret, 2, "{paired} -> {out}");
        assert_eq!(out, "h1_secret h1_secret", "{paired} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()));

        let card = format!("api{mark}key=4111-1111-1111-1111");
        let (vault, out, audit) = shield(&card);
        assert_eq!(audit.secret, 1, "{card} -> {out}");
        assert_eq!(audit.card, 0, "{card} -> {out}");
        assert_eq!(out, "h1_secret", "{card} -> {out}");
        assert!(!vault.holds_surface(b"4111-1111-1111-1111"));

        for text in [
            format!("api{mark}key={}", "a".repeat(15)),
            format!("somethingapi{mark}key={secret}"),
            format!("api{mark}keyboard={secret}"),
            format!("api{mark}key"),
            format!("secret={secret}"),
        ] {
            let (_vault, out, audit) = shield(&text);
            assert_eq!(audit.secret, 0, "{text} -> {out}");
            assert_eq!(out, text, "{text} -> {out}");
        }

        let raw = format!(r#"{{"api{mark}key":"{secret}"}}"#);
        let (vault, out, audit) = shield(&raw);
        assert_eq!(audit.secret, 1, "{raw} -> {out}");
        assert_eq!(out, r#"{"h1_secret"}"#, "{raw} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{raw}");

        let documents = [
            (
                format!(r#"{{"api{mark}key":"{secret}"}}"#),
                format!(r#"{{"api{mark}key":"h1_secret"}}"#),
            ),
            (
                format!(r#"{{"api{mark}key": "{secret}"}}"#),
                format!(r#"{{"api{mark}key": "h1_secret"}}"#),
            ),
            (
                format!(r#"{{"APP_SECRET{mark}KEY":"{secret}"}}"#),
                format!(r#"{{"APP_SECRET{mark}KEY":"h1_secret"}}"#),
            ),
            (
                format!(r#"{{"cfg":"{{\"api{mark}key\":\"{secret}\"}}"}}"#),
                format!(r#"{{"cfg":"{{\"api{mark}key\":\"h1_secret\"}}"}}"#),
            ),
        ];
        for (input, expect) in documents {
            let mut vault = Vault::new();
            let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &input).unwrap();
            assert_eq!(audit.secret, 1, "{input} -> {out}");
            assert_eq!(audit.card, 0, "{input} -> {out}");
            assert_eq!(out, expect, "{input}");
            assert!(!out.contains(&secret), "{input} -> {out}");
            assert!(!vault.holds_surface(secret.as_bytes()), "{input}");
            assert!(restore_json_write(&vault, &out).is_err(), "{out}");
        }

        let short = format!(r#"{{"api{mark}key":"{}"}}"#, "a".repeat(15));
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &short).unwrap();
        assert_eq!(audit.secret, 0, "{short} -> {out}");
        assert_eq!(out, short, "{short} -> {out}");
    }
}

#[test]
fn whitespace_inside_an_api_key_name_still_masks_the_value() {
    // `api_key=...` and `api-key=...` are already secrets. A space, a
    // non-breaking space, or a line break between those words is still
    // that name. Leaving it out sends the value.
    let secret = "a".repeat(16);
    let nbsp = '\u{00a0}'.to_string();
    let gaps = [" ", "  ", nbsp.as_str()];
    for gap in gaps {
        for text in [
            format!("api{gap}key={secret}"),
            format!("secret{gap}key: {secret}"),
            format!("access{gap}token={secret}"),
            format!("auth{gap}token: {secret}"),
            format!("APP_API{gap}KEY={secret}"),
            format!("X_ACCESS{gap}TOKEN={secret}"),
            format!("export api{gap}key={secret} please"),
        ] {
            let (vault, out, audit) = shield(&text);
            assert_eq!(audit.secret, 1, "{text:?} -> {out}");
            assert_eq!(audit.card, 0, "{text:?} -> {out}");
            assert!(!out.contains(&secret), "{text:?} -> {out}");
            assert!(out.contains("h1_secret"), "{text:?} -> {out}");
            if gap != " " {
                assert!(!out.contains(gap), "{text:?} -> {out}");
            }
            assert!(!vault.holds_surface(secret.as_bytes()), "{text:?}");
            assert!(vault.restore_write(&out).is_err(), "{text:?} -> {out}");
        }

        let exported = format!("export api{gap}key={secret} please");
        let (_vault, out, _) = shield(&exported);
        assert_eq!(out, "export h1_secret please", "{exported:?} -> {out}");

        let paired = format!("api{gap}key={secret} secret{gap}key={secret}");
        let (vault, out, audit) = shield(&paired);
        assert_eq!(audit.secret, 2, "{paired:?} -> {out}");
        assert_eq!(out, "h1_secret h1_secret", "{paired:?} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()));

        let card = format!("api{gap}key=4111-1111-1111-1111");
        let (vault, out, audit) = shield(&card);
        assert_eq!(audit.secret, 1, "{card:?} -> {out}");
        assert_eq!(audit.card, 0, "{card:?} -> {out}");
        assert_eq!(out, "h1_secret", "{card:?} -> {out}");
        assert!(!vault.holds_surface(b"4111-1111-1111-1111"));

        for text in [
            format!("api{gap}key={}", "a".repeat(15)),
            format!("somethingapi{gap}key={secret}"),
            format!("api{gap}keyboard={secret}"),
            format!("api{gap}key"),
            format!("secret={secret}"),
            format!("api/{gap}key={secret}"),
            format!("api.{gap}key={secret}"),
        ] {
            let (_vault, out, audit) = shield(&text);
            assert_eq!(audit.secret, 0, "{text:?} -> {out}");
            assert_eq!(out, text, "{text:?} -> {out}");
        }

        let raw = format!(r#"{{"api{gap}key":"{secret}"}}"#);
        let (vault, out, audit) = shield(&raw);
        assert_eq!(audit.secret, 1, "{raw:?} -> {out}");
        assert_eq!(out, r#"{"h1_secret"}"#, "{raw:?} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{raw:?}");

        let documents = [
            (
                format!(r#"{{"api{gap}key":"{secret}"}}"#),
                format!(r#"{{"api{gap}key":"h1_secret"}}"#),
            ),
            (
                format!(r#"{{"api{gap}key": "{secret}"}}"#),
                format!(r#"{{"api{gap}key": "h1_secret"}}"#),
            ),
            (
                format!(r#"{{"APP_SECRET{gap}KEY":"{secret}"}}"#),
                format!(r#"{{"APP_SECRET{gap}KEY":"h1_secret"}}"#),
            ),
            (
                format!(r#"{{"cfg":"{{\"api{gap}key\":\"{secret}\"}}"}}"#),
                format!(r#"{{"cfg":"{{\"api{gap}key\":\"h1_secret\"}}"}}"#),
            ),
        ];
        for (input, expect) in documents {
            let mut vault = Vault::new();
            let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &input).unwrap();
            assert_eq!(audit.secret, 1, "{input:?} -> {out}");
            assert_eq!(audit.card, 0, "{input:?} -> {out}");
            assert_eq!(out, expect, "{input:?}");
            assert!(!out.contains(&secret), "{input:?} -> {out}");
            assert!(!vault.holds_surface(secret.as_bytes()), "{input:?}");
            assert!(restore_json_write(&vault, &out).is_err(), "{out}");
        }

        let short = format!(r#"{{"api{gap}key":"{}"}}"#, "a".repeat(15));
        let mut vault = Vault::new();
        let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &short).unwrap();
        assert_eq!(audit.secret, 0, "{short:?} -> {out}");
        assert_eq!(out, short, "{short:?} -> {out}");
    }

    for gap in ["\t", "\n"] {
        let text = format!("api{gap}key={secret}");
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text:?} -> {out}");
        assert_eq!(out, "h1_secret", "{text:?} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{text:?}");
        let broken = format!("api/{gap}key={secret}");
        let (_vault, out, audit) = shield(&broken);
        assert_eq!(audit.secret, 0, "{broken:?} -> {out}");
        assert_eq!(out, broken, "{broken:?} -> {out}");
    }

    let glued = format!("apikey={secret}");
    let (vault, out, audit) = shield(&glued);
    assert_eq!(audit.secret, 1, "{glued} -> {out}");
    assert_eq!(out, "h1_secret", "{glued} -> {out}");
    assert!(!vault.holds_surface(secret.as_bytes()));

    let mixed = format!("api - key={secret}");
    let (vault, out, audit) = shield(&mixed);
    assert_eq!(audit.secret, 1, "{mixed:?} -> {out}");
    assert_eq!(out, "h1_secret", "{mixed:?} -> {out}");
    assert!(!vault.holds_surface(secret.as_bytes()));

    let as_number = format!(r#"{{"api key":{}}}"#, "1".repeat(16));
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &as_number).unwrap();
    assert_eq!(audit.secret, 1, "{as_number} -> {out}");
    assert_eq!(out, r#"{"api key":"h1_secret"}"#, "{as_number} -> {out}");
    assert!(!out.contains(&"1".repeat(16)), "{as_number} -> {out}");
    assert!(!vault.holds_surface("1".repeat(16).as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err(), "{out}");
}

#[test]
fn secrets_become_one_shared_mark_and_are_not_stored() {
    let key = format!("sk-{}", "a".repeat(20));
    let aws = "AKIAIOSFODNN7EXAMPLE";
    let text = format!("{key} and {aws}");
    let (vault, out, audit) = shield(&text);
    assert_eq!(audit.secret, 2, "{out}");
    assert_eq!(out.matches("h1_secret").count(), 2);
    assert!(!vault.holds_surface(key.as_bytes()));
    assert!(!vault.holds_surface(aws.as_bytes()));
    assert_eq!(vault.restore_display(&out), out);
    assert!(vault.restore_write(&out).is_err());
}

#[test]
fn temporary_aws_access_key_id_is_masked() {
    // `AKIAIOSFODNN7EXAMPLE` is already a secret. The same id with the
    // temporary prefix stays in the clear.
    let key = "ASIAIOSFODNN7EXAMPLE";
    let (vault, out, audit) = shield(key);
    assert_eq!(audit.secret, 1, "{key} -> {out}");
    assert_eq!(out, "h1_secret");
    assert!(!vault.holds_surface(key.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let sentence = format!("export AWS_ACCESS_KEY_ID={key} please");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "export AWS_ACCESS_KEY_ID=h1_secret please");
    assert!(!vault.holds_surface(key.as_bytes()));

    let paired = format!("AKIAIOSFODNN7EXAMPLE {key}");
    let (vault, out, audit) = shield(&paired);
    assert_eq!(audit.secret, 2, "{paired} -> {out}");
    assert_eq!(out, "h1_secret h1_secret");
    assert!(!vault.holds_surface(b"AKIAIOSFODNN7EXAMPLE"));
    assert!(!vault.holds_surface(key.as_bytes()));

    for bare in [
        "ASIAIOSFODNN7EXAMPL",
        "asiaIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLEX",
        "XASIAIOSFODNN7EXAMPLE",
        "ASIA",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare);
    }

    let raw = format!(r#"{{"id":"{key}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"id":"h1_secret"}"#);
    assert!(!vault.holds_surface(key.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());
}

#[test]
fn github_app_installation_token_is_masked() {
    // `ghs_` plus 36 letters is already a secret. A current installation
    // token is `ghs_`, a numeric app id, `_`, and a three-part JWT. The
    // `_` sits against `eyJ`, so the JWT rule does not see it either.
    // The payload stays in the clear.
    let header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload = "PAYLOADPAYLOADPAYLOAD";
    let signature = "S".repeat(40);
    let token = format!("ghs_15368_{header}.{payload}.{signature}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret");
    assert!(hidden(&out, "PAYLOAD"), "{out}");
    assert!(hidden(&out, "15368"), "{out}");
    assert!(!out.contains("eyJ"), "{out}");
    assert!(!out.contains(&signature), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let hyphen_ended = format!("ghs_99_{header}.{payload}.{}-", "S".repeat(39));
    let mixed = format!(
        "ghs_7_{header}.PAY_LOAD-PAYLOADPAYLOAD.SIG_NA-TURE{}",
        "S".repeat(20)
    );
    for text in [
        format!("export GITHUB_TOKEN={token} please"),
        format!("see {token}."),
        format!("see {token}, next"),
        format!("use {hyphen_ended} now"),
        format!("tok {mixed} end"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(hidden(&out, "PAYLOAD"), "{text} -> {out}");
        assert!(hidden(&out, "PAY"), "{text} -> {out}");
        assert!(hidden(&out, "15368"), "{text} -> {out}");
        assert!(!out.contains("eyJ"), "{text} -> {out}");
        assert!(!out.contains("SIG_NA"), "{text} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{text}");
        assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
    }

    let exported = format!("export GITHUB_TOKEN={token} please");
    let (_vault, out, _) = shield(&exported);
    assert_eq!(
        out, "export GITHUB_TOKEN=h1_secret please",
        "{exported} -> {out}"
    );

    let dotted = format!("see {token}.");
    let (_vault, out, _) = shield(&dotted);
    assert_eq!(out, "see h1_secret.", "{dotted} -> {out}");

    let comma = format!("see {token}, next");
    let (_vault, out, _) = shield(&comma);
    assert_eq!(out, "see h1_secret, next", "{comma} -> {out}");

    let ended = format!("use {hyphen_ended} now");
    let (_vault, out, _) = shield(&ended);
    assert_eq!(out, "use h1_secret now", "{ended} -> {out}");
    assert!(!out.contains('-'), "{ended} -> {out}");

    let old = format!("ghs_{}", "a".repeat(36));
    let paired = format!("{token} {old}");
    let (vault, out, audit) = shield(&paired);
    assert_eq!(audit.secret, 2, "{paired} -> {out}");
    assert_eq!(out, "h1_secret h1_secret");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(!vault.holds_surface(old.as_bytes()));

    let old_sentence = format!("use {old}.");
    let (_vault, out, audit) = shield(&old_sentence);
    assert_eq!(audit.secret, 1, "{old_sentence} -> {out}");
    assert_eq!(out, "use h1_secret.");

    let minimum = format!(
        "ghs_42_{}.{}.{}",
        "a".repeat(10),
        "b".repeat(10),
        "c".repeat(10)
    );
    let (vault, out, audit) = shield(&minimum);
    assert_eq!(audit.secret, 1, "{minimum} -> {out}");
    assert_eq!(out, "h1_secret");
    assert!(hidden(&out, &"a".repeat(10)), "{out}");
    assert!(!vault.holds_surface(minimum.as_bytes()));

    for bare in [
        format!("ghs_{}", "a".repeat(35)),
        format!("ghs_{}", "a".repeat(37)),
        "ghs_short".to_string(),
        format!("ghs_15368_{header}.{payload}"),
        format!(
            "ghs_1_{}.{}.{}",
            "a".repeat(9),
            "b".repeat(9),
            "c".repeat(9)
        ),
        format!("xghs_15368_{header}.{payload}.{signature}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "PAYLOAD"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let nested = format!(r#"{{"note":"use {token} today"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &nested).unwrap();
    assert_eq!(audit.secret, 1, "{nested} -> {out}");
    assert_eq!(out, r#"{"note":"use h1_secret today"}"#);
    assert!(hidden(&out, "PAYLOAD"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
}

#[test]
fn gitlab_routable_access_token_is_masked() {
    // `glpat-` plus 20 letters is already a secret. A routable token is
    // that same prefix, a payload of at least 27 characters, a dot, and
    // a 9-character tail. A versioned token puts a 2-character version
    // and a second dot in front of that tail. The payload rule stops at
    // the first dot, so the tail stays in the clear.
    let routable = format!("glpat-{}.aaaaaaaaa", "a".repeat(27));
    let versioned = format!("glpat-{}.01.bbbbbbbbb", "b".repeat(27));
    let mixed = format!(
        "glpat-{}-{}_{}-{}_{}-{}.{}",
        "aaaa", "bbbb", "cccc", "dddd", "eeee", "fff", "ccccccccc"
    );
    let classic = format!("glpat-{}", "d".repeat(20));
    for token in [&routable, &versioned, &mixed, &classic] {
        let (vault, out, audit) = shield(token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, "aaaaaaaaa"), "{token} -> {out}");
        assert!(hidden(&out, "bbbbbbbbb"), "{token} -> {out}");
        assert!(hidden(&out, "ccccccccc"), "{token} -> {out}");
        assert!(hidden(&out, &"a".repeat(27)), "{token} -> {out}");
        assert!(hidden(&out, "bbbb_cccc"), "{token} -> {out}");
        assert!(hidden(&out, &"d".repeat(20)), "{token} -> {out}");
        assert!(!out.contains('.'), "{token} -> {out}");
        assert!(!out.contains('-'), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token} -> {out}");
    }

    for text in [
        format!("export GITLAB_TOKEN={routable} please"),
        format!("see {versioned}."),
        format!("see {routable}, next"),
        format!("use {mixed} now"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(hidden(&out, "aaaaaaaaa"), "{text} -> {out}");
        assert!(hidden(&out, "bbbbbbbbb"), "{text} -> {out}");
        assert!(hidden(&out, "ccccccccc"), "{text} -> {out}");
        assert!(hidden(&out, "bbbb_cccc"), "{text} -> {out}");
        assert!(!vault.holds_surface(routable.as_bytes()), "{text}");
        assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
    }

    let exported = format!("export GITLAB_TOKEN={routable} please");
    let (_vault, out, _) = shield(&exported);
    assert_eq!(
        out, "export GITLAB_TOKEN=h1_secret please",
        "{exported} -> {out}"
    );

    let dotted = format!("see {versioned}.");
    let (_vault, out, _) = shield(&dotted);
    assert_eq!(out, "see h1_secret.", "{dotted} -> {out}");

    let comma = format!("see {routable}, next");
    let (_vault, out, _) = shield(&comma);
    assert_eq!(out, "see h1_secret, next", "{comma} -> {out}");

    let paired = format!("{routable} {classic}");
    let (vault, out, audit) = shield(&paired);
    assert_eq!(audit.secret, 2, "{paired} -> {out}");
    assert_eq!(out, "h1_secret h1_secret");
    assert!(!vault.holds_surface(routable.as_bytes()));
    assert!(!vault.holds_surface(classic.as_bytes()));

    let minimum = format!("glpat-{}.0r03gxo7s", "a".repeat(27));
    let (vault, out, audit) = shield(&minimum);
    assert_eq!(audit.secret, 1, "{minimum} -> {out}");
    assert_eq!(out, "h1_secret");
    assert!(hidden(&out, "0r03gxo7s"), "{out}");
    assert!(!vault.holds_surface(minimum.as_bytes()));

    let word_after_classic = format!("{classic}.something");
    let (vault, out, audit) = shield(&word_after_classic);
    assert_eq!(audit.secret, 1, "{word_after_classic} -> {out}");
    assert_eq!(out, "h1_secret.something", "{word_after_classic} -> {out}");
    assert!(hidden(&out, &"d".repeat(20)), "{out}");
    assert!(out.ends_with(".something"), "{out}");
    assert!(!vault.holds_surface(classic.as_bytes()));

    for bare in [
        format!("glpat-{}", "a".repeat(19)),
        format!("xglpat-{}", "a".repeat(20)),
        format!("x{routable}"),
        "glpat-short".to_string(),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    let raw = format!(r#"{{"token":"{routable}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "aaaaaaaaa"), "{out}");
    assert!(!vault.holds_surface(routable.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let nested = format!(r#"{{"note":"use {versioned} today"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &nested).unwrap();
    assert_eq!(audit.secret, 1, "{nested} -> {out}");
    assert_eq!(out, r#"{"note":"use h1_secret today"}"#);
    assert!(hidden(&out, "bbbbbbbbb"), "{out}");
    assert!(!out.contains("01"), "{out}");
    assert!(!vault.holds_surface(versioned.as_bytes()));
}

#[test]
fn gitlab_slack_and_stripe_prefixes_are_masked() {
    let payload = "a".repeat(20);
    let prefixes = [
        "glagent", "glffct", "glsoat", "glrtr", "glcbt", "glptt", "glimt", "gloas", "gldt", "glft",
        "glrt", "glwt",
    ];
    for prefix in prefixes {
        let token = format!("{prefix}-{payload}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, prefix), "{token} -> {out}");
        assert!(hidden(&out, &payload), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token} -> {out}");
    }

    let runner = format!("glrtr-{payload}");
    let (_vault, out, _) = shield(&format!("export GITLAB_TOKEN={runner} please"));
    assert_eq!(out, "export GITLAB_TOKEN=h1_secret please");

    let followed = format!("gldt-{payload}.something");
    let (_vault, out, audit) = shield(&followed);
    assert_eq!(audit.secret, 1, "{followed} -> {out}");
    assert_eq!(out, "h1_secret.something", "{followed} -> {out}");

    let slack_tail = "a".repeat(10);
    for token in [
        format!("xapp-1-A052FGTS2DL-{slack_tail}"),
        format!("xoxe.xapp-1-{slack_tail}"),
        format!("xoxe.xoxb-{slack_tail}"),
        format!("xoxe.xoxp-{slack_tail}"),
        format!("xoxe-{slack_tail}"),
        format!("xoxb-{slack_tail}"),
    ] {
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        if token.contains("A052FGTS2DL") {
            assert!(hidden(&out, "A052FGTS2DL"), "{token} -> {out}");
        }
        assert!(hidden(&out, &slack_tail), "{token} -> {out}");
        assert!(!out.contains("xox"), "{token} -> {out}");
        assert!(!out.contains("xapp"), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let app = format!("xapp-{slack_tail}");
    let (_vault, out, _) = shield(&format!("see {app}.next"));
    assert_eq!(out, "see h1_secret.next");

    let hook = format!("whsec_{}", "b".repeat(32));
    let (vault, out, audit) = shield(&format!("endpoint {hook} please"));
    assert_eq!(audit.secret, 1, "{hook} -> {out}");
    assert_eq!(out, "endpoint h1_secret please");
    assert!(hidden(&out, "whsec"), "{out}");
    assert!(hidden(&out, &"b".repeat(32)), "{out}");
    assert!(!vault.holds_surface(hook.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let minimum = format!("whsec_{}", "c".repeat(20));
    let (vault, out, audit) = shield(&minimum);
    assert_eq!(out, "h1_secret", "{minimum} -> {out}");
    assert_eq!(audit.secret, 1);
    assert!(!vault.holds_surface(minimum.as_bytes()));

    for bare in [
        format!("gldt-{}", "a".repeat(19)),
        format!("xgldt-{payload}"),
        format!("x{runner}"),
        format!("xapp-{}", "a".repeat(9)),
        format!("xxapp-{slack_tail}"),
        format!("whsec_{}", "b".repeat(19)),
        format!("xwhsec_{}", "b".repeat(20)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    let raw = format!(r#"{{"token":"gldt-{payload}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &payload), "{out}");
    assert!(!vault.holds_surface(format!("gldt-{payload}").as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());
}

#[test]
fn slack_session_tokens_are_masked() {
    let tail = "2468135790";
    for prefix in ["xoxc", "xoxd"] {
        let token = format!("{prefix}-{tail}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, prefix), "{token} -> {out}");
        assert!(hidden(&out, tail), "{token} -> {out}");
        assert!(!out.contains("xox"), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let head = "24681357901";
    let mid = "13579246801";
    let last = "abcdef2468135790";
    let shaped = format!("xoxc-{head}-{mid}-{last}");
    let (vault, out, audit) = shield(&format!("see {shaped}.next"));
    assert_eq!(audit.secret, 1, "{shaped} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{shaped} -> {out}");
    assert!(hidden(&out, head), "{out}");
    assert!(hidden(&out, mid), "{out}");
    assert!(hidden(&out, "2468135790"), "{out}");
    assert!(!vault.holds_surface(shaped.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let cookie = format!("xoxd-{head}-{last}");
    let raw = format!(r#"{{"token":"{cookie}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, head), "{out}");
    assert!(hidden(&out, "2468135790"), "{out}");
    assert!(!vault.holds_surface(cookie.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("xoxc-{}", "246813579"),
        format!("xoxd-{}", "a".repeat(9)),
        format!("wordxoxc-{tail}"),
        format!("wordxoxd-{tail}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn slack_workflow_token_is_masked() {
    let tail = "2468135790";
    let token = format!("xwfp-{tail}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "xwfp"), "{token} -> {out}");
    assert!(hidden(&out, tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let head = "24681357901";
    let mid = "13579246801";
    let last = "abcdef2468135790";
    let shaped = format!("xwfp-{head}-{mid}-{last}");
    let (vault, out, audit) = shield(&format!("see {shaped}.next"));
    assert_eq!(audit.secret, 1, "{shaped} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{shaped} -> {out}");
    assert!(hidden(&out, head), "{out}");
    assert!(hidden(&out, mid), "{out}");
    assert!(hidden(&out, "2468135790"), "{out}");
    assert!(!vault.holds_surface(shaped.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{shaped}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, head), "{out}");
    assert!(hidden(&out, "2468135790"), "{out}");
    assert!(!vault.holds_surface(shaped.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("xwfp-{}", "246813579"),
        format!("xwfp-{}", "a".repeat(9)),
        format!("wordxwfp-{tail}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn stripe_ephemeral_key_is_masked() {
    // `sk_test_` plus 10 letters is already a secret. An ephemeral key
    // is `ek_test_` or `ek_live_`. The published secret is a body of 71,
    // 76, 86, or 92 letters, an underscore, and 10 more letters. The
    // `sk_` rule stops at that underscore, so the secret stays in the
    // clear. A shorter key is letters only, at least 10, like `sk_live_`.
    let tail = "b".repeat(10);
    for mode in ["test", "live"] {
        for n in [71, 76, 86, 92] {
            let body = "A".repeat(n);
            let token = format!("ek_{mode}_{body}_{tail}");
            let (vault, out, audit) = shield(&token);
            assert_eq!(audit.secret, 1, "{token} -> {out}");
            assert_eq!(out, "h1_secret", "{token} -> {out}");
            assert!(hidden(&out, "ek_"), "{token} -> {out}");
            assert!(hidden(&out, &body), "{token} -> {out}");
            assert!(hidden(&out, &tail), "{token} -> {out}");
            assert!(!vault.holds_surface(token.as_bytes()), "{token}");
            assert!(vault.restore_write(&out).is_err(), "{token}");
        }
    }

    let short = format!("ek_test_{}", "d".repeat(10));
    let (vault, out, audit) = shield(&format!("see {short} please"));
    assert_eq!(audit.secret, 1, "{short} -> {out}");
    assert_eq!(out, "see h1_secret please");
    assert!(hidden(&out, "ek_test"), "{out}");
    assert!(hidden(&out, &"d".repeat(10)), "{out}");
    assert!(!vault.holds_surface(short.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let shaped = format!("ek_live_{}_{}", "C".repeat(71), tail);
    let (vault, out, audit) = shield(&format!("see {shaped}.next"));
    assert_eq!(audit.secret, 1, "{shaped} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{shaped} -> {out}");
    assert!(hidden(&out, "ek_live"), "{out}");
    assert!(hidden(&out, &"C".repeat(71)), "{out}");
    assert!(hidden(&out, &tail), "{out}");
    assert!(!vault.holds_surface(shaped.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"secret":"{shaped}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"secret":"h1_secret"}"#);
    assert!(hidden(&out, &tail), "{out}");
    assert!(!vault.holds_surface(shaped.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("ek_test_{}", "d".repeat(9)),
        format!("wordek_test_{}", "d".repeat(10)),
        format!("ek_prod_{}", "d".repeat(10)),
        format!("ek_test_{}_{}", "F".repeat(70), "g".repeat(10)),
        format!("ek_test_{}_{}", "H".repeat(71), "i".repeat(9)),
        format!("ek_test_{}_{}", "p".repeat(10), "q".repeat(10)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn stripe_connection_token_is_masked() {
    // `ek_test_` plus 71 letters, an underscore, and 10 more is already
    // a secret. A Terminal connection token is `pst_test_` or `pst_live_`.
    // The API reference secret is that same body and tail. The OpenAPI
    // fixture is 23 letters and has no underscore. The `ek_` rule does
    // not see this prefix, so the secret stays in the clear. A shorter
    // key is letters only, at least 10, like `sk_live_`.
    let published = "pst_test_YWNjdF8xTTJKVGtMa2RJd0h1N2l4LE81ZEdIalZ6NlVuMUdjM3c3WkRnN0ZYRHZxRURwTXo_00gNK2DWAV";
    let body = "YWNjdF8xTTJKVGtMa2RJd0h1N2l4LE81ZEdIalZ6NlVuMUdjM3c3WkRnN0ZYRHZxRURwTXo";
    let tail = "00gNK2DWAV";
    let (vault, out, audit) = shield(published);
    assert_eq!(audit.secret, 1, "{published} -> {out}");
    assert_eq!(out, "h1_secret", "{published} -> {out}");
    assert!(hidden(&out, "pst_"), "{published} -> {out}");
    assert!(hidden(&out, body), "{published} -> {out}");
    assert!(hidden(&out, tail), "{published} -> {out}");
    assert!(hidden(&out, "81"), "{published} -> {out}");
    assert!(!vault.holds_surface(published.as_bytes()), "{published}");
    assert!(vault.restore_write(&out).is_err(), "{published}");

    let live = format!("pst_live_{}_{}", "C".repeat(71), "b".repeat(10));
    let (vault, out, audit) = shield(&format!("see {live}.next"));
    assert_eq!(audit.secret, 1, "{live} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{live} -> {out}");
    assert!(hidden(&out, "pst_live"), "{out}");
    assert!(hidden(&out, &"C".repeat(71)), "{out}");
    assert!(hidden(&out, &"b".repeat(10)), "{out}");
    assert!(!vault.holds_surface(live.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let fixture = "pst_test_iPPfmBn7kZ0gIJ4xpehqTnC";
    let (vault, out, audit) = shield(&format!("see {fixture} please"));
    assert_eq!(audit.secret, 1, "{fixture} -> {out}");
    assert_eq!(out, "see h1_secret please");
    assert!(hidden(&out, "pst_test"), "{out}");
    assert!(hidden(&out, "iPPfmBn7kZ0gIJ4xpehqTnC"), "{out}");
    assert!(hidden(&out, "0"), "{fixture} -> {out}");
    assert!(!vault.holds_surface(fixture.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let short = format!("pst_test_{}", "d".repeat(10));
    let (vault, out, audit) = shield(&short);
    assert_eq!(audit.secret, 1, "{short} -> {out}");
    assert_eq!(out, "h1_secret");
    assert!(hidden(&out, "pst_test"), "{out}");
    assert!(hidden(&out, &"d".repeat(10)), "{out}");
    assert!(!vault.holds_surface(short.as_bytes()));

    let raw = format!(r#"{{"secret":"{published}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"secret":"h1_secret"}"#);
    assert!(hidden(&out, tail), "{out}");
    assert!(hidden(&out, "81"), "{out}");
    assert!(!vault.holds_surface(published.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("pst_test_{}", "d".repeat(9)),
        "pst_test_123".to_string(),
        format!("wordpst_test_{}", "d".repeat(10)),
        format!("pst_prod_{}", "d".repeat(10)),
        format!("pst_test_{}_{}", "F".repeat(70), "g".repeat(10)),
        format!("pst_test_{}_{}", "H".repeat(76), "i".repeat(10)),
        format!("pst_test_{}_{}", "J".repeat(71), "k".repeat(9)),
        format!("pst_test_{}_{}", "p".repeat(10), "q".repeat(10)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn stripe_organization_key_is_masked() {
    // `sk_live_` plus 10 letters is already a secret. An organization
    // key is `sk_org_` and the same kind of letters. The live and test
    // rule stops before `org`, so the key stays in the clear. There is
    // no `rk_org_` prefix. A short payload stays as written.
    let minimum = format!("sk_org_{}", "a".repeat(10));
    let (vault, out, audit) = shield(&minimum);
    assert_eq!(audit.secret, 1, "{minimum} -> {out}");
    assert_eq!(out, "h1_secret");
    assert!(hidden(&out, "sk_org"), "{out}");
    assert!(hidden(&out, &"a".repeat(10)), "{out}");
    assert!(!vault.holds_surface(minimum.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let classic = format!("sk_org_{}", "4eC39HqLyjWDarjtT1zdp7dc");
    let (vault, out, audit) = shield(&format!("see {classic}.next"));
    assert_eq!(audit.secret, 1, "{classic} -> {out}");
    assert_eq!(out, "see h1_secret.next");
    assert!(hidden(&out, "sk_org"), "{out}");
    assert!(hidden(&out, "4eC39HqLyjWDarjtT1zdp7dc"), "{out}");
    assert!(!vault.holds_surface(classic.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let longer = format!("sk_org_{}", "B".repeat(99));
    let (vault, out, audit) = shield(&format!("keep {longer} please"));
    assert_eq!(audit.secret, 1, "{longer} -> {out}");
    assert_eq!(out, "keep h1_secret please");
    assert!(hidden(&out, "sk_org"), "{out}");
    assert!(hidden(&out, &"B".repeat(99)), "{out}");
    assert!(!vault.holds_surface(longer.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"secret":"{classic}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"secret":"h1_secret"}"#);
    assert!(hidden(&out, "4eC39HqLyjWDarjtT1zdp7dc"), "{out}");
    assert!(!vault.holds_surface(classic.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("sk_org_{}", "a".repeat(9)),
        "sk_org_".to_string(),
        format!("rk_org_{}", "a".repeat(10)),
        format!("pk_org_{}", "a".repeat(10)),
        format!("wordsk_org_{}", "a".repeat(10)),
        format!("sk_org_{}_{}", "abcd", "efghijklmn"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn digitalocean_personal_access_token_is_masked() {
    // `sk_live_` plus 10 letters is already a secret. DigitalOcean
    // documents `dop_v1_` for a control-panel token, `doo_v1_` for an
    // OAuth token, and `dor_v1_` for a refresh token. The published
    // body is 64 letters. A short payload stays as written.
    let body = "a".repeat(64);
    for prefix in ["dop_v1_", "doo_v1_", "dor_v1_"] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(
            hidden(&out, prefix.trim_end_matches('_')),
            "{token} -> {out}"
        );
        assert!(hidden(&out, &body), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }
    let token = format!("dop_v1_{body}");

    let mixed = format!("dop_v1_{}", "A".repeat(56) + "y319b02b");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "dop_v1"), "{out}");
    assert!(hidden(&out, "y319b02b"), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("dop_v1_{}", "a".repeat(63)),
        format!("dop_v1_{}", "a".repeat(9)),
        format!("worddop_v1_{body}"),
        format!("dop_v2_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn secret_access_key_assignment_is_masked() {
    let secret = "a".repeat(16);
    for text in [
        format!("AWS_SECRET_ACCESS_KEY={secret}"),
        format!("secret access key={secret}"),
        format!("secret-access-key={secret}"),
        format!("export AWS_SECRET_ACCESS_KEY={secret} please"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(hidden(&out, &secret), "{text} -> {out}");
        assert!(out.contains("h1_secret"), "{text} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{text}");
        assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
    }
    let exported = format!("export AWS_SECRET_ACCESS_KEY={secret} please");
    let (_vault, out, _) = shield(&exported);
    assert_eq!(out, "export h1_secret please");

    let raw = format!(r#"{{"AWS_SECRET_ACCESS_KEY":"{secret}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"AWS_SECRET_ACCESS_KEY":"h1_secret"}"#);
    assert!(hidden(&out, &secret), "{out}");
    assert!(!vault.holds_surface(secret.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for text in [
        format!("AWS_SECRET_ACCESS_KEY={}", "a".repeat(15)),
        format!("secret/access/key={secret}"),
        format!("secret.access.key={secret}"),
        format!("notSECRET_ACCESS_KEY={secret}"),
        format!("secret access={secret}"),
    ] {
        let (_vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 0, "{text} -> {out}");
        assert_eq!(out, text, "{text} -> {out}");
    }
}

#[test]
fn assignment_value_with_an_interior_dot_is_masked() {
    let head = "a".repeat(16);
    let tail = "QRSTUVWXYZ123456";
    let value = format!("{head}.{tail}");
    for text in [
        format!("api_key={value}"),
        format!("api_key={head}.{tail}.UVWXYZ"),
        format!("api_key=abc.{}", "b".repeat(16)),
        format!("export API_KEY={value} please"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(hidden(&out, &head), "{text} -> {out}");
        assert!(hidden(&out, tail), "{text} -> {out}");
        assert!(hidden(&out, "UVWXYZ"), "{text} -> {out}");
        assert!(!out.contains('.'), "{text} -> {out}");
        assert!(!vault.holds_surface(value.as_bytes()), "{text}");
        assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
    }
    let exported = format!("export API_KEY={value} please");
    let (_vault, out, _) = shield(&exported);
    assert_eq!(out, "export h1_secret please");

    let sentence = format!("see api_key={head}. Next");
    let (_vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret. Next", "{sentence} -> {out}");
    assert!(hidden(&out, &head), "{out}");

    let raw = format!(r#"{{"api_key":"{value}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"api_key":"h1_secret"}"#);
    assert!(hidden(&out, tail), "{out}");
    assert!(!vault.holds_surface(value.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for text in [
        format!("api_key={}", "a".repeat(15)),
        "api_key=abc.def".to_string(),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 0, "{text} -> {out}");
        assert_eq!(out, text, "{text} -> {out}");
    }
}

#[test]
fn session_token_assignment_is_masked() {
    let secret = "a".repeat(20);
    for text in [
        format!("AWS_SESSION_TOKEN={secret}"),
        format!("SESSION_TOKEN={secret}"),
        format!("session token={secret}"),
        format!("session-token={secret}"),
        format!("export AWS_SESSION_TOKEN={secret} please"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(hidden(&out, &secret), "{text} -> {out}");
        assert!(out.contains("h1_secret"), "{text} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{text}");
        assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
    }
    let exported = format!("export AWS_SESSION_TOKEN={secret} please");
    let (_vault, out, _) = shield(&exported);
    assert_eq!(out, "export h1_secret please");

    let raw = format!(r#"{{"AWS_SESSION_TOKEN":"{secret}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"AWS_SESSION_TOKEN":"h1_secret"}"#);
    assert!(hidden(&out, &secret), "{out}");
    assert!(!vault.holds_surface(secret.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for text in [
        format!("AWS_SESSION_TOKEN={}", "a".repeat(15)),
        format!("session/token={secret}"),
        format!("session.token={secret}"),
        format!("notSESSION_TOKEN={secret}"),
        format!("session={secret}"),
    ] {
        let (_vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 0, "{text} -> {out}");
        assert_eq!(out, text, "{text} -> {out}");
    }
}

#[test]
fn fullwidth_plus_still_shields_the_number() {
    let plus = "\u{FF0B}";
    let intl = format!("call {plus}44 20 7946 0958 today");
    let (vault, out, audit) = shield(&intl);
    assert_eq!(audit.phone, 1, "{intl} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "0958"), "{out}");
    assert!(!out.contains(plus), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), intl);

    let spaced = format!("call {plus} 44 20 7946 0958 today");
    let (vault, out, audit) = shield(&spaced);
    assert_eq!(audit.phone, 1, "{spaced} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(hidden(&out, "44"), "{out}");
    assert!(!out.contains(plus), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), spaced);

    let trunk = format!("call {plus}1(416)555-0123 today");
    let (vault, out, audit) = shield(&trunk);
    assert_eq!(audit.phone, 1, "{trunk} -> {out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(hidden(&out, "0123"), "{out}");
    assert!(!out.contains(plus), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), trunk);

    let run = format!("call {plus}14165550123 today");
    let (vault, out, audit) = shield(&run);
    assert_eq!(audit.phone, 1, "{run} -> {out}");
    assert!(hidden(&out, "14165550123"), "{out}");
    assert!(!out.contains(plus), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), run);

    let bare = format!("cost {plus} shipping");
    let (_vault, out, audit) = shield(&bare);
    assert_eq!(audit.phone, 0, "{bare} -> {out}");
    assert_eq!(out, bare);
}

#[test]
fn fullwidth_parentheses_still_shield_the_number() {
    // `(416) 555-0123` is already a phone, and so is `+44 (20) 7946 0958`.
    // A wide keyboard writes the parentheses as U+FF08 and U+FF09. Leaving
    // those marks out sends the number. Five digits glued to the closing
    // mark stay as written, the same as an ASCII parenthesis.
    let open = "\u{FF08}";
    let close = "\u{FF09}";
    for phone in [
        format!("{open}416{close} 555-0123"),
        format!("{open}416{close}555-0123"),
        format!("{open} 416 {close} 555-0123"),
        format!("1{open}416{close}555-0123"),
        format!("+1{open}416{close}555-0123"),
        format!("+44 {open}20{close} 7946 0958"),
        format!("+44{open}20{close}7946 0958"),
    ] {
        let (vault, out, audit) = shield(&phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert!(!out.contains(open), "{phone} -> {out}");
        assert!(!out.contains(close), "{phone} -> {out}");
        for group in ["416", "0123", "7946", "0958"] {
            if phone.contains(group) {
                assert!(hidden(&out, group), "{phone} -> {out}");
            }
        }
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = format!("call {open}416{close}555-0123 today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(hidden(&out, "0123"), "{out}");
    assert!(!out.contains(open), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let raw = format!(r#"{{"tel":"{open}416{close}555-0123"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "416"), "{raw} -> {out}");
    assert!(!out.contains(open), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        format!("{open}416{close}5550123"),
        format!("+44{open}20{close}79460958"),
        format!("cost {open}shipping{close}"),
        format!("{open}see 416{close} 555-0123"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn zero_zero_prefix_still_shields_the_number() {
    // `+44 20 7946 0958` and `+1416-555-0123` are already phones. A `00`
    // dialing prefix is that same leading plus. `0044 20 7946 0958` stayed
    // in the clear. The two zeros are not digits of the number: counting
    // them would keep `0044 20 794` or cut the tail off a 15-digit number.
    // A bare run after `00` stays as written. `00` is not a plus sign.
    let nbsp = '\u{00a0}';
    let en = '\u{2013}';
    let open = "\u{FF08}";
    let close = "\u{FF09}";
    for phone in [
        "0044 20 7946 0958",
        "0044-20-7946-0958",
        "0044 20 - 7946 - 0958",
        "0044/20/7946/0958",
        "00 44 20 7946 0958",
        "0044 (20) 7946 0958",
        "0044(20)7946 0958",
        "0044 (20) 7946-0958",
        "0044 (0)20 7946 0958",
        "0044 (0) 20 7946 0958",
        "0033 (0)1 23 45 67 89",
        "0033 (0) 1 23 45 67 89",
        "0044 7700 900123",
        "0049 30 12345678",
        "0044 20 7946 0958 999",
        "0044 20 7946",
        "001 416 555 0123",
        "001-416-555-0123",
        "001(416)555-0123",
        "001416-555-0123",
        "00 1416-555-0123",
        "00 1 (416) 555-0123",
        &format!("0044{en}20{en}7946{en}0958"),
        &format!("00{nbsp}44 20 7946 0958"),
        "00\t44 20 7946 0958",
        &format!("0044 {open}20{close} 7946 0958"),
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(!out.contains('('), "{phone} -> {out}");
        assert!(!out.contains(')'), "{phone} -> {out}");
        assert!(!out.contains(open), "{phone} -> {out}");
        assert!(!out.contains(close), "{phone} -> {out}");
        assert!(!out.contains(nbsp), "{phone} -> {out}");
        for group in [
            "7946", "0958", "7700", "900123", "12345678", "416", "0123", "23 45",
        ] {
            if phone.contains(group) {
                assert!(hidden(&out, group), "{phone} -> {out}");
            }
        }
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = "call 0044 20 7946 0958 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "0958"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let glued_letter = "x0044 20 7946 0958";
    let (vault, out, audit) = shield(glued_letter);
    assert_eq!(audit.phone, 1, "{glued_letter} -> {out}");
    assert!(out.starts_with("xh1_phone_"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), glued_letter);

    let pair = "call 0044 20 7946 0958 or 001 416 555 0123 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    let longer = "0044 20 7946 0958 9999";
    let (vault, out, audit) = shield(longer);
    assert_eq!(audit.phone, 1, "{longer} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(out.ends_with(" 9999"), "{out}");
    assert!(visible(&out).contains("9999"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), longer);

    for bare in [
        "00442079460958",
        "0014165550123",
        "0044 (20)79460958",
        "0044 (20)79460 958",
        "0044 20 794",
        "0044 20 12",
        "0044 7700 9001239999",
        "90044 20 7946 0958",
        "100 20 7946 0958",
        "44 20 7946 0958",
        "00",
        "00 44",
        "call 20 7946 0958 today",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"0044 20 7946 0958"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "7946"), "{raw} -> {out}");
    assert!(hidden(&out, "0958"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

#[test]
fn nanp_exit_prefix_still_shields_the_number() {
    for phone in [
        "011 44 20 7946 0958",
        "01144 20 7946 0958",
        "01144-20-7946-0958",
        "011 44 20 7946",
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(hidden(&out, "7946"), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = "call 011 44 20 7946 0958 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "0958"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let longer = "011 44 20 7946 0958 9999";
    let (vault, out, audit) = shield(longer);
    assert_eq!(audit.phone, 1, "{longer} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(out.ends_with(" 9999"), "{out}");
    assert!(visible(&out).contains("9999"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), longer);

    let raw = r#"{"tel":"011 44 20 7946 0958"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "7946"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        "011442079460958",
        "011 44 20 794",
        "1011 44 20 7946 0958",
        "44 20 7946 0958",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn separator_after_a_dialing_prefix_still_shields_the_number() {
    // `0044-20-7946-0958` and `00 44 20 7946 0958` are already phones.
    // A hyphen, a dot, or a slash already separates groups. That same
    // mark between the `00` or `011` prefix and the country code left
    // `00-44-20-7946-0958` in the clear. `00-1-416-555-0123` kept the
    // prefix and shielded only the tail. The prefix digits are not part
    // of the number. A bare run after the prefix stays as written. A
    // plus still takes only whitespace before the country code.
    let en = '\u{2013}';
    let wide_00 = widen_digits("00");
    let wide_011 = widen_digits("011");
    for phone in [
        "00-44-20-7946-0958",
        "00.44.20.7946.0958",
        "00/44/20/7946/0958",
        "00 - 44 - 20 - 7946 - 0958",
        "011-44-20-7946-0958",
        "011.44.20.7946.0958",
        "011/44/20/7946/0958",
        "011 - 44 - 20 - 7946 - 0958",
        "00-44 (20) 7946 0958",
        "011-44 (20) 7946 0958",
        "00-44-7700-900123",
        "00-1-416-555-0123",
        "00-1416-555-0123",
        "00.1.416.555.0123",
        "011-1-416-555-0123",
        "011-1416-555-0123",
        "00-1(416)555-0123",
        &format!("00{en}44{en}20{en}7946{en}0958"),
        &format!("{wide_00}-44-20-7946-0958"),
        &format!("{wide_011}-1-416-555-0123"),
    ] {
        let (vault, out, audit) = shield(phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(!out.contains('('), "{phone} -> {out}");
        assert!(!out.contains(' '), "{phone} -> {out}");
        for group in ["7946", "0958", "7700", "900123", "416", "0123", "555"] {
            if phone.contains(group) {
                assert!(hidden(&out, group), "{phone} -> {out}");
            }
        }
        if phone.contains(&wide_00) {
            assert!(hidden(&out, &wide_00), "{phone} -> {out}");
        }
        if phone.contains(&wide_011) {
            assert!(hidden(&out, &wide_011), "{phone} -> {out}");
        }
        if phone.contains("00") {
            assert!(hidden(&out, "00"), "{phone} -> {out}");
        }
        if phone.contains("011") {
            assert!(hidden(&out, "011"), "{phone} -> {out}");
        }
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = "call 00-44-20-7946-0958 today";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "0958"), "{out}");
    assert!(hidden(&out, "00"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let glued_letter = "x00-44-20-7946-0958";
    let (vault, out, audit) = shield(glued_letter);
    assert_eq!(audit.phone, 1, "{glued_letter} -> {out}");
    assert!(out.starts_with("xh1_phone_"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "00"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), glued_letter);

    let pair = "call 00-44-20-7946-0958 or 011-1-416-555-0123 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "416"), "{out}");
    assert!(hidden(&out, "00"), "{out}");
    assert!(hidden(&out, "011"), "{out}");
    assert_eq!(out.matches("h1_phone_").count(), 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    let longer = "00-44-20-7946-0958-9999";
    let (vault, out, audit) = shield(longer);
    assert_eq!(audit.phone, 1, "{longer} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(out.ends_with("-9999"), "{out}");
    assert!(visible(&out).contains("9999"), "{out}");
    assert!(hidden(&out, "7946"), "{out}");
    assert!(hidden(&out, "00"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), longer);

    for bare in [
        "00-442079460958",
        "011-442079460958",
        "00-14165550123",
        "011-14165550123",
        "00-44-20-794",
        "00-44-20-12",
        "00-44",
        "100-44-20-7946-0958",
        "90044-20-7946-0958",
        "+-44-20-7946-0958",
        "00-44 (20)79460958",
        "44-20-7946-0958",
        "011442079460958",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(out, bare, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
    }

    let raw = r#"{"tel":"00-44-20-7946-0958"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, "7946"), "{raw} -> {out}");
    assert!(hidden(&out, "0958"), "{raw} -> {out}");
    assert!(hidden(&out, "00"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
}

fn widen_digits(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '0'..='9' => char::from_u32(0xFF10 + (ch as u32 - '0' as u32)).unwrap(),
            _ => ch,
        })
        .collect()
}

#[test]
fn fullwidth_digits_still_shield_the_number() {
    let phone = format!("+{}", widen_digits("44 20 7946 0958"));
    let (vault, out, audit) = shield(&phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(hidden(&out, &widen_digits("7946")), "{out}");
    assert!(hidden(&out, &widen_digits("0958")), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let card = format!("visa {}", widen_digits("4111 1111 1111 1111"));
    let (vault, out, audit) = shield(&card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert!(hidden(&out, &widen_digits("4111")), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let sin = widen_digits("130692544");
    let cued = format!("SIN {sin}");
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.sin, 1, "{cued} -> {out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let raw = format!(r#"{{"tel":"{phone}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, &widen_digits("7946")), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        widen_digits("(416) 555-01234"),
        format!("visa {}", widen_digits("4111 1111 1111 1112")),
        widen_digits("130692544"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn fullwidth_dialing_prefix_still_shields_the_number() {
    // `011 44 20 7946 0958` and `0044 20 7946 0958` are already phones.
    // A wide keyboard writes the prefix digits fullwidth. The prefix
    // is still the ASCII characters `011` and `00`, so the number stays
    // in the clear. Those digits are not part of the number. Counting
    // them would keep `0044 20 794`, or cut the tail off a 15-digit
    // number. A bare run stays as written.
    for phone in [
        widen_digits("011 44 20 7946 0958"),
        widen_digits("01144 20 7946 0958"),
        widen_digits("0044 20 7946 0958"),
        widen_digits("00 44 20 7946 0958"),
        widen_digits("0044 20 7946 0958 999"),
        format!("{} 44 20 7946 0958", widen_digits("011")),
    ] {
        let (vault, out, audit) = shield(&phone);
        assert_eq!(audit.phone, 1, "{phone} -> {out}");
        assert_eq!(audit.card, 0, "{phone} -> {out}");
        assert_eq!(audit.sin, 0, "{phone} -> {out}");
        assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
        assert_eq!(out.len(), "h1_phone_".len() + 9, "{phone} -> {out}");
        assert!(hidden(&out, &widen_digits("7946")), "{phone} -> {out}");
        assert!(hidden(&out, "7946"), "{phone} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), phone);
    }

    let sentence = format!("call {} today", widen_digits("011 44 20 7946 0958"));
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.phone, 1, "{sentence} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, &widen_digits("7946")), "{out}");
    assert!(hidden(&out, &widen_digits("0958")), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let longer = widen_digits("011 44 20 7946 0958 9999");
    let (vault, out, audit) = shield(&longer);
    assert_eq!(audit.phone, 1, "{longer} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(out.ends_with(&widen_digits(" 9999")), "{out}");
    assert!(visible(&out).contains(&widen_digits("9999")), "{out}");
    assert!(hidden(&out, &widen_digits("7946")), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), longer);

    let raw = format!(r#"{{"tel":"{}"}}"#, widen_digits("011 44 20 7946 0958"));
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.phone, 1, "{raw} -> {out}");
    assert!(hidden(&out, &widen_digits("7946")), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        widen_digits("011442079460958"),
        widen_digits("0044 20 794"),
        widen_digits("1011 44 20 7946 0958"),
        widen_digits("44 20 7946 0958"),
        widen_digits("00"),
        widen_digits("011 44"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn dot_between_cue_words_still_shields_the_number() {
    let sin = valid_sin();
    for cued in [
        format!("social.insurance {sin}"),
        format!("social. insurance {sin}"),
        format!("SOCIAL.INSURANCE {sin}"),
    ] {
        let (vault, out, audit) = shield(&cued);
        assert_eq!(audit.sin, 1, "{cued} -> {out}");
        assert!(hidden(&out, &sin), "{cued} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), cued);
    }

    let card = "american.express 4111111111111111";
    let (vault, out, audit) = shield(card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(hidden(&out, "4111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let far = format!("social.insurance{}{sin}", " ".repeat(41));
    let (_vault, out, audit) = shield(&far);
    assert_eq!(audit.sin, 0, "{far} -> {out}");
    assert_eq!(out, far);

    for bare in [
        sin.clone(),
        format!("social.security {sin}"),
        format!("insurance {sin}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn glossary_uses_word_boundaries_and_loses_to_email() {
    let glossary = Glossary::from_terms(["Marie", "Jean Pierre"]);
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, "Marie met Jean Pierre").unwrap();
    assert_eq!(audit.glossary, 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), "Marie met Jean Pierre");

    let (out, audit) = shield_text(&mut vault, &glossary, "Marielle marine").unwrap();
    assert_eq!(out, "Marielle marine");
    assert_eq!(audit.glossary, 0);

    let (out, audit) = shield_text(&mut vault, &glossary, "Mail Marie@example.com today").unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert_eq!(audit.glossary, 0, "{out}");
    assert_eq!(
        vault.restore_write(&out).unwrap(),
        "Mail Marie@example.com today"
    );
    assert_eq!(out.matches("h1_").count(), 1);
}

#[test]
fn secret_span_hides_a_card_inside_it() {
    let text = "api_key=4111-1111-1111-1111";
    let (vault, out, audit) = shield(text);
    assert_eq!(audit.secret, 1, "{out}");
    assert_eq!(audit.card, 0);
    assert_eq!(out, "h1_secret");
    assert!(!vault.holds_surface(b"4111-1111-1111-1111"));
}

#[test]
fn repeated_email_gets_two_tokens() {
    let (vault, out, audit) = shield("a@b.co and a@b.co");
    assert_eq!(audit.email, 2, "{out}");
    let tokens: Vec<_> = out
        .split_whitespace()
        .filter(|part| part.starts_with("h1_"))
        .collect();
    assert_eq!(tokens.len(), 2);
    assert_ne!(tokens[0], tokens[1]);
    assert_eq!(vault.restore_write(&out).unwrap(), "a@b.co and a@b.co");
}

#[test]
fn email_token_uses_the_email_kind() {
    let (_vault, out, _) = shield("a@b.co");
    assert!(out.starts_with("h1_email_"), "{out}");
}

#[test]
fn pgp_private_key_block_is_masked() {
    let body = "abcdefghijklmnopqrstuvwxyz";
    let block = format!(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG\n\n{body}\n-----END PGP PRIVATE KEY BLOCK-----"
    );
    let wrapped = format!("keep {block} please");
    let (vault, out, audit) = shield(&wrapped);
    assert_eq!(audit.secret, 1, "{wrapped} -> {out}");
    assert_eq!(out, "keep h1_secret please");
    assert!(hidden(&out, body), "{out}");
    assert!(!out.contains("BEGIN"), "{out}");
    assert!(!vault.holds_surface(block.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let second = block.replace(body, "ZYXWVUTSRQPONMLKJIHGFEDCBA");
    let pair = format!("{block}\n{second}");
    let (vault, out, audit) = shield(&pair);
    assert_eq!(audit.secret, 2, "{pair} -> {out}");
    assert_eq!(out, "h1_secret\nh1_secret");
    assert!(hidden(&out, body), "{out}");
    assert!(!vault.holds_surface(second.as_bytes()));

    for token in [
        format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"),
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"),
        format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"),
    ] {
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret");
        assert!(hidden(&out, body), "{out}");
        assert!(!vault.holds_surface(token.as_bytes()));
    }

    for bare in [
        format!("-----BEGIN PGP PUBLIC KEY BLOCK-----\n{body}\n-----END PGP PUBLIC KEY BLOCK-----"),
        format!("-----BEGIN PGP MESSAGE-----\n{body}\n-----END PGP MESSAGE-----"),
        format!("-----BEGIN PGP PRIVATE KEY BLOCK-----\n{body}"),
        "not a key".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }

    let encoded = block.replace('\n', "\\n");
    let raw = format!(r#"{{"key":"{encoded}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"key":"h1_secret"}"#);
    assert!(hidden(&out, body), "{out}");
    assert!(!vault.holds_surface(block.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());
}

fn wide_dot(text: &str) -> String {
    text.replace('.', "\u{FF0E}")
}

#[test]
fn fullwidth_full_stop_still_shields_the_value() {
    // `user@example.com` is already an email, and `.` already splits a
    // phone, a card, a SIN, and cue words such as `social.insurance`.
    // A wide keyboard writes that dot as U+FF0E. Leaving the stop out
    // sends the value. A short tail, `social.security`, and a cue 41
    // characters away stay as written.
    let stop = '\u{FF0E}';
    let email = wide_dot("user@example.com");
    let (vault, out, audit) = shield(&email);
    assert_eq!(audit.email, 1, "{email} -> {out}");
    assert_eq!(audit.phone, 0, "{email} -> {out}");
    assert!(out.starts_with("h1_email_"), "{email} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
    assert!(!out.contains(stop), "{email} -> {out}");
    assert!(hidden(&out, "user"), "{email} -> {out}");
    assert!(hidden(&out, "example"), "{email} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), email);

    let local = wide_dot("user.name@example.com");
    let (vault, out, audit) = shield(&local);
    assert_eq!(audit.email, 1, "{local} -> {out}");
    assert!(!out.contains(stop), "{local} -> {out}");
    assert!(hidden(&out, "user"), "{local} -> {out}");
    assert!(hidden(&out, "name"), "{local} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), local);

    let uk = wide_dot("user@example.co.uk");
    let (vault, out, audit) = shield(&uk);
    assert_eq!(audit.email, 1, "{uk} -> {out}");
    assert!(!out.contains(stop), "{uk} -> {out}");
    assert!(hidden(&out, "example"), "{uk} -> {out}");
    assert!(hidden(&out, "uk"), "{uk} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), uk);

    let sentence = format!("mail {} today", wide_dot("user@example.com"));
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains(stop), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let ended = format!("mail {}{stop}", wide_dot("user@example.com"));
    let (vault, out, audit) = shield(&ended);
    assert_eq!(audit.email, 1, "{ended} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(stop), "{out}");
    assert_eq!(out.matches(stop).count(), 1, "{ended} -> {out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), ended);

    let phone = wide_dot("416.555.0123");
    let (vault, out, audit) = shield(&phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert_eq!(audit.card, 0, "{phone} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
    assert!(!out.contains(stop), "{phone} -> {out}");
    assert!(hidden(&out, "555"), "{phone} -> {out}");
    assert!(hidden(&out, "0123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let wide_phone = widen_digits("416.555.0123").replace('.', "\u{FF0E}");
    let (vault, out, audit) = shield(&wide_phone);
    assert_eq!(audit.phone, 1, "{wide_phone} -> {out}");
    assert!(hidden(&out, &widen_digits("555")), "{wide_phone} -> {out}");
    assert!(hidden(&out, &widen_digits("0123")), "{wide_phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), wide_phone);

    let intl = wide_dot("+44.20.7946.0958");
    let (vault, out, audit) = shield(&intl);
    assert_eq!(audit.phone, 1, "{intl} -> {out}");
    assert!(hidden(&out, "7946"), "{intl} -> {out}");
    assert!(hidden(&out, "0958"), "{intl} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), intl);

    let card = wide_dot("4111.1111.1111.1111");
    let (vault, out, audit) = shield(&card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert_eq!(audit.phone, 0, "{card} -> {out}");
    assert!(out.starts_with("h1_card_"), "{card} -> {out}");
    assert!(!out.contains(stop), "{card} -> {out}");
    assert!(hidden(&out, "4111"), "{card} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let sin = valid_sin();
    let grouped = wide_dot(&format!("{}.{}.{}", &sin[..3], &sin[3..6], &sin[6..]));
    let cued_sin = format!("SIN {grouped}");
    let (vault, out, audit) = shield(&cued_sin);
    assert_eq!(audit.sin, 1, "{cued_sin} -> {out}");
    assert_eq!(audit.phone, 0, "{cued_sin} -> {out}");
    assert!(hidden(&out, &sin), "{cued_sin} -> {out}");
    assert!(hidden(&out, &sin[..3]), "{cued_sin} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued_sin);

    for cued in [
        format!("social{stop}insurance {sin}"),
        format!("social{stop} insurance {sin}"),
        wide_dot(&format!("S.I.N. {sin}")),
        wide_dot(&format!("N.A.S. {sin}")),
    ] {
        let (vault, out, audit) = shield(&cued);
        assert_eq!(audit.sin, 1, "{cued} -> {out}");
        assert!(hidden(&out, &sin), "{cued} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), cued);
    }

    let amex = format!("american{stop}express 4111111111111111");
    let (vault, out, audit) = shield(&amex);
    assert_eq!(audit.card, 1, "{amex} -> {out}");
    assert!(hidden(&out, "4111"), "{amex} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), amex);

    let head = "a".repeat(16);
    let tail = "QRSTUVWXYZ123456";
    let assigned = format!("api_key={head}{stop}{tail}");
    let (vault, out, audit) = shield(&assigned);
    assert_eq!(audit.secret, 1, "{assigned} -> {out}");
    assert!(hidden(&out, &head), "{assigned} -> {out}");
    assert!(hidden(&out, tail), "{assigned} -> {out}");
    assert!(!out.contains(stop), "{assigned} -> {out}");
    assert!(!vault.holds_surface(assigned.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"to":"{}"}}"#, wide_dot("user@example.com"));
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{raw} -> {out}");
    assert!(hidden(&out, "example"), "{raw} -> {out}");
    assert!(!out.contains(stop), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let far = format!("social{stop}insurance{}{sin}", " ".repeat(41));
    let (_vault, out, audit) = shield(&far);
    assert_eq!(audit.sin, 0, "{far} -> {out}");
    assert_eq!(out, far);

    let ended_secret = format!("see api_key={head}{stop} Next");
    let (_vault, out, audit) = shield(&ended_secret);
    assert_eq!(audit.secret, 1, "{ended_secret} -> {out}");
    assert_eq!(
        out,
        format!("see h1_secret{stop} Next"),
        "{ended_secret} -> {out}"
    );
    assert!(hidden(&out, &head), "{out}");

    for bare in [
        wide_dot("user@example.c"),
        wide_dot("user@.example.com"),
        format!("social{stop}security {sin}"),
        grouped.clone(),
        wide_dot("4111.1111.1111.1112"),
        wide_dot(&format!("S.I.NISTER {sin}")),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn decomposed_accent_in_the_sin_cue_still_shields_the_number() {
    // `numéro d'assurance sociale 130692544` is already a SIN. The é in
    // numéro may be a combining acute. Leaving that form out sends the
    // digits. The phrase has no shorter cue. A cue 41 characters away
    // stays as written.
    let sin = valid_sin();
    let acute = '\u{0301}';
    let cue = format!("nume{acute}ro d'assurance sociale");
    let text = format!("{cue} {sin}");
    let (vault, out, audit) = shield(&text);
    assert_eq!(audit.sin, 1, "{text} -> {out}");
    assert_eq!(audit.card, 0, "{text} -> {out}");
    assert_eq!(audit.phone, 0, "{text} -> {out}");
    assert!(out.starts_with(&format!("{cue} h1_sin_")), "{out}");
    assert!(out.contains(acute), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);

    let upper = format!("NUME{acute}RO D'ASSURANCE SOCIALE {sin}");
    let (vault, out, audit) = shield(&upper);
    assert_eq!(audit.sin, 1, "{upper} -> {out}");
    assert!(
        out.starts_with(&format!("NUME{acute}RO D'ASSURANCE SOCIALE h1_sin_")),
        "{out}"
    );
    assert!(out.contains(acute), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), upper);

    let grouped = format!("{cue} {} {} {}", &sin[..3], &sin[3..6], &sin[6..]);
    let (vault, out, audit) = shield(&grouped);
    assert_eq!(audit.sin, 1, "{grouped} -> {out}");
    assert_eq!(audit.phone, 0, "{grouped} -> {out}");
    assert!(out.starts_with(&format!("{cue} h1_sin_")), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert!(hidden(&out, &sin[..3]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), grouped);

    let sentence = format!("the {cue} is {sin} today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.sin, 1, "{sentence} -> {out}");
    assert!(out.starts_with(&format!("the {cue} is h1_sin_")), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(acute), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let quote = format!("nume{acute}ro d\u{2018}assurance sociale {sin}");
    let (vault, out, audit) = shield(&quote);
    assert_eq!(audit.sin, 1, "{quote} -> {out}");
    assert!(out.contains('\u{2018}'), "{out}");
    assert!(out.contains(acute), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), quote);

    let near = format!("{cue}{}{sin}", ".".repeat(40));
    let (vault, out, audit) = shield(&near);
    assert_eq!(audit.sin, 1, "{near} -> {out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), near);

    let after = format!("{sin}{}{cue}", ".".repeat(40));
    let (vault, out, audit) = shield(&after);
    assert_eq!(audit.sin, 1, "{after} -> {out}");
    assert!(out.starts_with("h1_sin_"), "{out}");
    assert!(out.ends_with(&cue), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), after);

    let raw = format!(r#"{{"note":"{cue} {sin}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.sin, 1, "{raw} -> {out}");
    assert!(out.contains(acute), "{out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let far = format!("{cue}{}{sin}", ".".repeat(41));
    let (_vault, out, audit) = shield(&far);
    assert_eq!(audit.sin, 0, "{far} -> {out}");
    assert_eq!(out, far);

    for bare in [
        sin.clone(),
        format!("nume{acute}ro d'assurance {sin}"),
        format!("nume{acute}rod'assurance sociale {sin}"),
        format!("nume{acute}security {sin}"),
        format!("{cue} {}", "130692543"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn fullwidth_digits_still_shield_the_address() {
    // `user1@example.com` is already an email, in the local part or the
    // domain. A wide keyboard writes those digits as U+FF10 through
    // U+FF19. Leaving them out sends the address. A short tail, a
    // missing domain, and a digit glued to the final label stay as
    // written, same as an ASCII digit in that spot.
    let digit = '\u{FF11}';
    let cases = [
        (
            format!("user{digit}@example.com"),
            "user".to_string(),
            "example".to_string(),
        ),
        (
            widen_digits("123@example.com"),
            widen_digits("123"),
            "example".to_string(),
        ),
        (
            format!("{digit}@b.co"),
            digit.to_string(),
            "b.co".to_string(),
        ),
        (
            format!("user@ex{digit}ample.com"),
            "user".to_string(),
            "ample".to_string(),
        ),
        (
            format!("user@{digit}example.com"),
            "user".to_string(),
            "example".to_string(),
        ),
        (
            format!("user@example{digit}.com"),
            "user".to_string(),
            "example".to_string(),
        ),
        (
            widen_digits("user@123.com"),
            "user".to_string(),
            "com".to_string(),
        ),
        (
            format!("user@ex{digit}ample.co.uk"),
            "user".to_string(),
            "uk".to_string(),
        ),
        (
            format!("user.{digit}.name@example.com"),
            "user".to_string(),
            "name".to_string(),
        ),
        (
            format!("o'brien{digit}@example.com"),
            "brien".to_string(),
            "example".to_string(),
        ),
        (
            format!("josé{digit}@société.fr"),
            "josé".to_string(),
            "société".to_string(),
        ),
        (
            format!("Jean-Luc{digit}@Example.COM"),
            "Jean".to_string(),
            "Example".to_string(),
        ),
        (
            format!("user{digit}\u{FF20}example.com"),
            "user".to_string(),
            "example".to_string(),
        ),
        (
            format!("user{digit}@example\u{FF0E}com"),
            "user".to_string(),
            "example".to_string(),
        ),
    ];
    for (email, local, domain) in cases {
        let (vault, out, audit) = shield(&email);
        assert_eq!(audit.email, 1, "{email} -> {out}");
        assert_eq!(audit.phone, 0, "{email} -> {out}");
        assert_eq!(audit.card, 0, "{email} -> {out}");
        assert_eq!(audit.sin, 0, "{email} -> {out}");
        assert!(out.starts_with("h1_email_"), "{email} -> {out}");
        assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
        assert!(!out.contains('@'), "{email} -> {out}");
        assert!(!out.contains('\u{FF20}'), "{email} -> {out}");
        assert!(
            !out.chars()
                .any(|ch| ('\u{FF10}'..='\u{FF19}').contains(&ch)),
            "{email} -> {out}"
        );
        assert!(hidden(&out, &local), "{email} -> {out}");
        assert!(hidden(&out, &domain), "{email} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), email);
    }

    let sentence = format!("mail user{digit}@example.com today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let dotted = format!("mail user{digit}@example.com.");
    let (vault, out, audit) = shield(&dotted);
    assert_eq!(audit.email, 1, "{dotted} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with('.'), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), dotted);

    let wrapped = format!("(user{digit}@example.com)");
    let (vault, out, audit) = shield(&wrapped);
    assert_eq!(audit.email, 1, "{wrapped} -> {out}");
    assert!(out.starts_with("(h1_email_"), "{out}");
    assert!(out.ends_with(')'), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), wrapped);

    let pair = format!("a@b.co and user{digit}@example.com");
    let (vault, out, audit) = shield(&pair);
    assert_eq!(audit.email, 2, "{pair} -> {out}");
    assert_eq!(out.matches("h1_email_").count(), 2, "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert!(hidden(&out, "b.co"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), pair);

    let raw = format!(r#"{{"to":"user{digit}@example.com"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{raw} -> {out}");
    assert!(!out.contains('@'), "{raw} -> {out}");
    assert!(hidden(&out, "example"), "{raw} -> {out}");
    assert!(
        !out.chars()
            .any(|ch| ('\u{FF10}'..='\u{FF19}').contains(&ch)),
        "{raw} -> {out}"
    );
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let prose = format!("user{digit} wrote a@b.co");
    let (vault, out, audit) = shield(&prose);
    assert_eq!(audit.email, 1, "{prose} -> {out}");
    assert!(
        out.starts_with(&format!("user{digit} wrote h1_email_")),
        "{out}"
    );
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), prose);

    let spaced = format!("note{digit} a@b.co");
    let (vault, out, audit) = shield(&spaced);
    assert_eq!(audit.email, 1, "{spaced} -> {out}");
    assert!(out.starts_with(&format!("note{digit} h1_email_")), "{out}");
    assert!(!out.contains('@'), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), spaced);

    for bare in [
        format!("user{digit}@example"),
        format!("user{digit}@example.c"),
        format!("user{digit}@.com"),
        format!("user{digit}@home"),
        format!("{digit}@example.c"),
        format!("user@example.co{digit}"),
        format!("user@example.com{digit}"),
        widen_digits("12345"),
        format!("see {digit} please"),
        format!("user {digit} example.com"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn vault_token_is_masked() {
    // Vault documents `hvs.` for a service token, `hvb.` for a batch
    // token, and `hvr.` for a recovery token. After that prefix, 24 or
    // more characters are appended. A longer token may contain an
    // underscore or a hyphen. A short payload stays as written. The
    // earlier `s.`, `b.`, and `r.` prefixes stay too.
    let body = "a".repeat(24);
    for prefix in ["hvs.", "hvb.", "hvr."] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(
            hidden(&out, prefix.trim_end_matches('.')),
            "{token} -> {out}"
        );
        assert!(hidden(&out, &body), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let token = format!("hvs.{body}");
    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "hvs"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let mixed = format!("hvs.aaaaaaa_{}", "b".repeat(16));
    let (vault, out, audit) = shield(&mixed);
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "h1_secret", "{mixed} -> {out}");
    assert!(hidden(&out, "aaaaaaa"), "{out}");
    assert!(hidden(&out, &"b".repeat(16)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));

    let hyphenated = format!("hvb.{}-{}", "c".repeat(12), "d".repeat(12));
    let (vault, out, audit) = shield(&hyphenated);
    assert_eq!(audit.secret, 1, "{hyphenated} -> {out}");
    assert_eq!(out, "h1_secret", "{hyphenated} -> {out}");
    assert!(hidden(&out, &"c".repeat(12)), "{out}");
    assert!(hidden(&out, &"d".repeat(12)), "{out}");
    assert!(!vault.holds_surface(hyphenated.as_bytes()));

    let token = format!("hvs.{body}");
    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("hvs.{}", "a".repeat(23)),
        format!("hvs.{}", "a".repeat(9)),
        format!("hvs.{}-{}", "a".repeat(10), "b".repeat(10)),
        format!("wordhvs.{body}"),
        format!("hvx.{body}"),
        format!("s.{body}"),
        format!("b.{body}"),
        format!("r.{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn pypi_api_token_is_masked() {
    // `npm_` plus 36 letters is already a secret. PyPI documents an API
    // token as `pypi-` plus a URL-safe base64 macaroon. The published
    // body is at least 85 characters and may contain an underscore or
    // a hyphen, including at the end. A shorter body stays as written.
    // A trailing `=` is padding and stays outside the token.
    let body = "a".repeat(85);
    let token = format!("pypi-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pypi"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let hyphen_tail = format!("pypi-{}-", "b".repeat(84));
    let (vault, out, audit) = shield(&hyphen_tail);
    assert_eq!(audit.secret, 1, "{hyphen_tail} -> {out}");
    assert_eq!(out, "h1_secret", "{hyphen_tail} -> {out}");
    assert!(hidden(&out, &"b".repeat(84)), "{out}");
    assert!(!vault.holds_surface(hyphen_tail.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let mixed = format!("pypi-a1_{}-{}", "b".repeat(40), "c".repeat(41));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "pypi"), "{out}");
    assert!(hidden(&out, "a1"), "{out}");
    assert!(hidden(&out, &"b".repeat(40)), "{out}");
    assert!(hidden(&out, &"c".repeat(41)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let padded = format!("pypi-{body}=");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret=", "{padded} -> {out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(padded.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("pypi-{}", "a".repeat(84)),
        format!("pypi-{}-", "a".repeat(83)),
        format!("pypi-{}", "a".repeat(9)),
        format!("wordpypi-{body}"),
        format!("PyPI-{body}"),
        format!("pypi_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn onepassword_service_account_token_is_masked() {
    // `eyJ` plus two dotted segments is already a secret. 1Password
    // documents a service account token as `ops_` plus the URL-safe
    // base64 of a JSON object, so the body starts with `eyJ`. The
    // underscore sits against that `e`, and the JWT rule does not see
    // it. The published example is 630 characters after `ops_`. The
    // same JSON with the sign-in address `my.1password.com` and a
    // one-character email local part is 604. A shorter body stays as
    // written. A
    // trailing `=` is padding and stays outside the token.
    let body = format!("eyJ{}", "a".repeat(601));
    let token = format!("ops_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "ops"), "{token} -> {out}");
    assert!(hidden(&out, "eyJ"), "{token} -> {out}");
    assert!(hidden(&out, &"a".repeat(601)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let hyphen_tail = format!("ops_eyJ{}-", "b".repeat(626));
    let (vault, out, audit) = shield(&hyphen_tail);
    assert_eq!(audit.secret, 1, "{hyphen_tail} -> {out}");
    assert_eq!(out, "h1_secret", "{hyphen_tail} -> {out}");
    assert!(hidden(&out, &"b".repeat(626)), "{out}");
    assert!(!vault.holds_surface(hyphen_tail.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let mixed = format!("ops_eyJa1_{}-{}", "c".repeat(300), "d".repeat(323));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "ops"), "{out}");
    assert!(hidden(&out, "a1"), "{out}");
    assert!(hidden(&out, &"c".repeat(300)), "{out}");
    assert!(hidden(&out, &"d".repeat(323)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let padded = format!("ops_{body}=");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret=", "{padded} -> {out}");
    assert!(hidden(&out, &"a".repeat(601)), "{out}");
    assert!(!vault.holds_surface(padded.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &"a".repeat(601)), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let published = format!("ops_eyJ{}", "a".repeat(627));
    let (vault, out, audit) = shield(&published);
    assert_eq!(audit.secret, 1, "{published} -> {out}");
    assert_eq!(out, "h1_secret", "{published} -> {out}");
    assert!(hidden(&out, &"a".repeat(627)), "{out}");
    assert!(!vault.holds_surface(published.as_bytes()));

    for bare in [
        format!("ops_eyJ{}", "a".repeat(600)),
        format!("ops_eyJ{}", "a".repeat(20)),
        format!("ops_{}", "a".repeat(630)),
        format!("wordops_{body}"),
        format!("OPS_{body}"),
        format!("ops_eyj{}", "a".repeat(627)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn ideographic_full_stop_still_shields_the_address() {
    // `user@example.com` is already an email. An ideographic full stop,
    // U+3002, is that same dot in the local part or the domain. Leaving
    // it out sends the address. A stop with no final label, and a domain
    // with no local part, stay as written.
    let domain = "user@example\u{3002}com";
    let (vault, out, audit) = shield(domain);
    assert_eq!(audit.email, 1, "{domain} -> {out}");
    assert_eq!(audit.phone, 0, "{domain} -> {out}");
    assert!(out.starts_with("h1_email_"), "{domain} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{domain} -> {out}");
    assert!(!out.contains('\u{3002}'), "{domain} -> {out}");
    assert!(hidden(&out, "user"), "{domain} -> {out}");
    assert!(hidden(&out, "example"), "{domain} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), domain);

    let local = "user\u{3002}name@example.com";
    let (vault, out, audit) = shield(local);
    assert_eq!(audit.email, 1, "{local} -> {out}");
    assert_eq!(audit.phone, 0, "{local} -> {out}");
    assert!(out.starts_with("h1_email_"), "{local} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{local} -> {out}");
    assert!(!out.contains('\u{3002}'), "{local} -> {out}");
    assert!(hidden(&out, "user"), "{local} -> {out}");
    assert!(hidden(&out, "name"), "{local} -> {out}");
    assert!(hidden(&out, "example"), "{local} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), local);

    let sentence = "see user@example\u{3002}co\u{3002}uk next";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("see h1_email_"), "{out}");
    assert!(out.ends_with(" next"), "{out}");
    assert!(!out.contains('\u{3002}'), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    for bare in [
        "user@example\u{3002}",
        "example\u{3002}com",
        "not an address",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn shopify_access_token_is_masked() {
    // Shopify documents an access token as `shpat_` (public and online
    // admin), `shpca_` (custom apps), `shppa_` (legacy private apps),
    // or `shpss_` (app secret). The body is 32 letters or digits. A
    // shorter body stays as written. A longer body stays too. The value
    // is not stored.
    let body = "a".repeat(32);
    for prefix in ["shpat_", "shpca_", "shppa_", "shpss_"] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(
            hidden(&out, prefix.trim_end_matches('_')),
            "{token} -> {out}"
        );
        assert!(hidden(&out, &body), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let published = "shpat_r8TRc9ZXAvcVvcrmtr7qoVw69WeeY1ex";
    let (vault, out, audit) = shield(&format!("see {published}.next"));
    assert_eq!(audit.secret, 1, "{published} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{published} -> {out}");
    assert!(hidden(&out, "shpat"), "{out}");
    assert!(hidden(&out, "r8TRc9ZXAvcVvcrmtr7qoVw69WeeY1ex"), "{out}");
    assert!(!vault.holds_surface(published.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("shpat_{}", "a".repeat(31)),
        format!("shpat_{}", "a".repeat(33)),
        format!("wordshpat_{body}"),
        format!("SHPAT_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn middle_dot_between_groups_still_shields_the_number() {
    // U+30FB and U+00B7 sit between groups the way a hyphen does.
    // Leaving either mark out sends the number. A slash is still not
    // a SIN separator.
    let phone = "416\u{30FB}555\u{30FB}0123";
    round_trip(phone, |audit| audit.phone);
    let (vault, out, audit) = shield(phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert!(hidden(&out, "416"), "{phone} -> {out}");
    assert!(hidden(&out, "555"), "{phone} -> {out}");
    assert!(hidden(&out, "0123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let international = "+44\u{00B7}20\u{00B7}7946\u{00B7}0958";
    round_trip(international, |audit| audit.phone);
    let (vault, out, audit) = shield(international);
    assert_eq!(audit.phone, 1, "{international} -> {out}");
    assert!(hidden(&out, "44"), "{international} -> {out}");
    assert!(hidden(&out, "7946"), "{international} -> {out}");
    assert!(hidden(&out, "0958"), "{international} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), international);

    let card = "4111\u{30FB}1111\u{30FB}1111\u{30FB}1111";
    round_trip(card, |audit| audit.card);
    let (vault, out, audit) = shield(card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(hidden(&out, "4111"), "{card} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let sin = "SIN 130\u{30FB}692\u{30FB}544";
    let (vault, out, audit) = shield(sin);
    assert_eq!(audit.sin, 1, "{sin} -> {out}");
    assert!(out.starts_with("SIN h1_sin_"), "{sin} -> {out}");
    assert!(hidden(&out, "130"), "{sin} -> {out}");
    assert!(hidden(&out, "692"), "{sin} -> {out}");
    assert!(hidden(&out, "544"), "{sin} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sin);

    for bare in [
        "not\u{30FB}a\u{30FB}phone",
        "4111\u{30FB}1111\u{30FB}1111\u{30FB}1112",
        "130\u{30FB}692\u{30FB}544",
        "SIN 130/692/544",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

fn arabic_indic_digits(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '0'..='9' => char::from_u32(0x0660 + (ch as u32 - '0' as u32)).unwrap(),
            _ => ch,
        })
        .collect()
}

#[test]
fn arabic_indic_digits_still_shield_the_number() {
    // +44 20 7946 0958 in Arabic-Indic digits. Shield and restore.
    // One more digit still fits in that phone. A failed Luhn card, a
    // bare SIN, and a 3-3-4 line with a fifth digit glued on stay.
    let phone = "+\u{0664}\u{0664} \u{0662}\u{0660} \u{0667}\u{0669}\u{0664}\u{0666} \u{0660}\u{0669}\u{0665}\u{0668}";
    let (vault, out, audit) = shield(phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(hidden(&out, &arabic_indic_digits("7946")), "{out}");
    assert!(hidden(&out, &arabic_indic_digits("0958")), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let longer = format!("{phone}{}", arabic_indic_digits("1"));
    let (vault, out, audit) = shield(&longer);
    assert_eq!(audit.phone, 1, "{longer} -> {out}");
    assert_eq!(audit.card, 0, "{longer} -> {out}");
    assert_eq!(audit.sin, 0, "{longer} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{out}");
    assert!(hidden(&out, &arabic_indic_digits("09581")), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), longer);

    let card = format!("visa {}", arabic_indic_digits("4111111111111111"));
    let (vault, out, audit) = shield(&card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(out.starts_with("visa h1_card_"), "{out}");
    assert!(
        hidden(&out, &arabic_indic_digits("4111111111111111")),
        "{out}"
    );
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let sin = arabic_indic_digits("130692544");
    let cued = format!("SIN {sin}");
    let (vault, out, audit) = shield(&cued);
    assert_eq!(audit.sin, 1, "{cued} -> {out}");
    assert!(hidden(&out, &sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    for bare in [
        arabic_indic_digits("(416) 555-01234"),
        format!("visa {}", arabic_indic_digits("4111111111111112")),
        arabic_indic_digits("130692544"),
        "not a number".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn fullwidth_slash_between_groups_still_shields_the_number() {
    // `416/555/0123` and `4111/1111/1111/1111` are already a phone and
    // a card. A wide keyboard writes that slash as U+FF0F. Leaving the
    // mark out sends the number. A slash is still not a SIN separator.
    let slash = '\u{FF0F}';
    let phone = format!("416{slash}555{slash}0123");
    round_trip(&phone, |audit| audit.phone);
    let (vault, out, audit) = shield(&phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert_eq!(audit.card, 0, "{phone} -> {out}");
    assert!(out.starts_with("h1_phone_"), "{phone} -> {out}");
    assert!(!out.contains(slash), "{phone} -> {out}");
    assert!(hidden(&out, "416"), "{phone} -> {out}");
    assert!(hidden(&out, "555"), "{phone} -> {out}");
    assert!(hidden(&out, "0123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let mixed = format!("416{slash}555-0123");
    round_trip(&mixed, |audit| audit.phone);
    let (vault, out, audit) = shield(&mixed);
    assert_eq!(audit.phone, 1, "{mixed} -> {out}");
    assert!(hidden(&out, "416"), "{mixed} -> {out}");
    assert!(hidden(&out, "0123"), "{mixed} -> {out}");
    assert!(!out.contains(slash), "{mixed} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), mixed);

    let trunk = format!("1{slash}800{slash}555-0199");
    round_trip(&trunk, |audit| audit.phone);
    let (vault, out, audit) = shield(&trunk);
    assert_eq!(audit.phone, 1, "{trunk} -> {out}");
    assert!(hidden(&out, "800"), "{trunk} -> {out}");
    assert!(hidden(&out, "0199"), "{trunk} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), trunk);

    let international = format!("+44{slash}20{slash}7946{slash}0958");
    round_trip(&international, |audit| audit.phone);
    let (vault, out, audit) = shield(&international);
    assert_eq!(audit.phone, 1, "{international} -> {out}");
    assert!(hidden(&out, "44"), "{international} -> {out}");
    assert!(hidden(&out, "7946"), "{international} -> {out}");
    assert!(hidden(&out, "0958"), "{international} -> {out}");
    assert!(!out.contains(slash), "{international} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), international);

    let prefixed = format!("00{slash}44{slash}20{slash}7946{slash}0958");
    round_trip(&prefixed, |audit| audit.phone);
    let (vault, out, audit) = shield(&prefixed);
    assert_eq!(audit.phone, 1, "{prefixed} -> {out}");
    assert!(hidden(&out, "7946"), "{prefixed} -> {out}");
    assert!(hidden(&out, "0958"), "{prefixed} -> {out}");
    assert!(!out.contains(slash), "{prefixed} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), prefixed);

    let wide_phone = widen_digits("416/555/0123").replace('/', "\u{FF0F}");
    let (vault, out, audit) = shield(&wide_phone);
    assert_eq!(audit.phone, 1, "{wide_phone} -> {out}");
    assert!(hidden(&out, &widen_digits("555")), "{wide_phone} -> {out}");
    assert!(hidden(&out, &widen_digits("0123")), "{wide_phone} -> {out}");
    assert!(!out.contains(slash), "{wide_phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), wide_phone);

    for slashed in [
        format!("4111{slash}1111{slash}1111{slash}1111"),
        format!("3782{slash}8224{slash}6310{slash}005"),
        format!("3056{slash}930902{slash}5904"),
        format!("4111 {slash} 1111 {slash} 1111 {slash} 1111"),
    ] {
        let (vault, out, audit) = shield(&slashed);
        assert_eq!(audit.card, 1, "{slashed} -> {out}");
        assert_eq!(audit.phone, 0, "{slashed} -> {out}");
        assert!(out.starts_with("h1_card_"), "{slashed} -> {out}");
        assert!(!out.contains(slash), "{slashed} -> {out}");
        for group in slashed.split(|ch: char| !ch.is_ascii_digit()) {
            if group.len() >= 4 {
                assert!(hidden(&out, group), "{slashed} -> {out}");
            }
        }
        assert_eq!(vault.restore_write(&out).unwrap(), slashed);
    }

    let sentence = format!("pay visa 4111{slash}1111{slash}1111{slash}1111 today.");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.card, 1, "{sentence} -> {out}");
    assert!(out.starts_with("pay visa h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(!out.contains(slash), "{out}");
    assert!(hidden(&out, "4111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let raw = format!(r#"{{"visa":"4111{slash}1111{slash}1111{slash}1111"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.card, 1, "{raw} -> {out}");
    assert!(hidden(&out, "4111"), "{raw} -> {out}");
    assert!(!out.contains(slash), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    for bare in [
        format!("416{slash}5550123"),
        format!("+1{slash}4165550123"),
        format!("4111{slash}1111{slash}1111{slash}1112"),
        format!("4111{slash}1111{slash}1111{slash}11111"),
        format!("SIN 130{slash}692{slash}544"),
        format!("not{slash}a{slash}phone"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn fullwidth_plus_in_the_local_part_still_shields_the_address() {
    // `user+tag@example.com` is already an email. A wide keyboard writes
    // that plus as U+FF0B. Leaving the sign out sends the head and keeps
    // the tail. A plus in the domain, and a plus with no address, stay
    // as written. A fullwidth plus before digits is still a phone.
    let plus = '\u{FF0B}';
    let email = format!("user{plus}tag@example.com");
    let (vault, out, audit) = shield(&email);
    assert_eq!(audit.email, 1, "{email} -> {out}");
    assert_eq!(audit.phone, 0, "{email} -> {out}");
    assert!(out.starts_with("h1_email_"), "{email} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
    assert!(!out.contains(plus), "{email} -> {out}");
    assert!(!out.contains('@'), "{email} -> {out}");
    assert!(hidden(&out, "user"), "{email} -> {out}");
    assert!(hidden(&out, "tag"), "{email} -> {out}");
    assert!(hidden(&out, "example"), "{email} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), email);

    let sentence = format!("mail user{plus}tag@example.com today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("mail h1_email_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains(plus), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "tag"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let wide_at = format!("user{plus}tag\u{FF20}example.com");
    let (vault, out, audit) = shield(&wide_at);
    assert_eq!(audit.email, 1, "{wide_at} -> {out}");
    assert!(!out.contains(plus), "{wide_at} -> {out}");
    assert!(!out.contains('\u{FF20}'), "{wide_at} -> {out}");
    assert!(hidden(&out, "user"), "{wide_at} -> {out}");
    assert!(hidden(&out, "example"), "{wide_at} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), wide_at);

    let raw = format!(r#"{{"to":"user{plus}tag@example.com"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{raw} -> {out}");
    assert!(!out.contains(plus), "{raw} -> {out}");
    assert!(hidden(&out, "user"), "{raw} -> {out}");
    assert!(hidden(&out, "tag"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);

    let phone = format!("{plus}14165550123");
    let (vault, out, audit) = shield(&phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert_eq!(audit.email, 0, "{phone} -> {out}");
    assert!(hidden(&out, "4165550123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    for bare in [
        format!("user{plus}example.com"),
        format!("user@ex{plus}ample.com"),
        format!("cost {plus} shipping"),
        format!("{plus}not-an-address"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn telegram_bot_token_is_masked() {
    // The Bot API describes a bot token as digits, a colon, and a
    // secret. The id can be 5 to 16 digits. The secret is 35
    // characters. A final hyphen stays inside the mark. A shorter
    // tail stays as written. A bare number stays as written.
    let token = format!("12345678:{}", "a".repeat(35));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "12345678"), "{token} -> {out}");
    assert!(hidden(&out, &"a".repeat(35)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let ten = format!("1234567890:{}", "b".repeat(35));
    let (vault, out, audit) = shield(&ten);
    assert_eq!(audit.secret, 1, "{ten} -> {out}");
    assert_eq!(out, "h1_secret", "{ten} -> {out}");
    assert!(hidden(&out, "1234567890"), "{ten} -> {out}");
    assert!(hidden(&out, &"b".repeat(35)), "{ten} -> {out}");
    assert!(!vault.holds_surface(ten.as_bytes()), "{ten}");
    assert!(vault.restore_write(&out).is_err(), "{ten}");

    let five = format!("12345:{}", "d".repeat(35));
    let sixteen = format!("{}:{}", "1".repeat(16), "e".repeat(35));
    let dashed = format!("1234567:{}-", "f".repeat(34));
    for token in [&five, &sixteen, &dashed] {
        let (vault, out, audit) = shield(token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let tail = "c".repeat(35);
    let embedded_token = format!("123456789:{tail}");
    let embedded = format!("see {embedded_token}.next");
    let (vault, out, audit) = shield(&embedded);
    assert_eq!(audit.secret, 1, "{embedded} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{embedded} -> {out}");
    assert!(hidden(&out, "123456789"), "{embedded} -> {out}");
    assert!(hidden(&out, &tail), "{embedded} -> {out}");
    assert!(
        !vault.holds_surface(embedded_token.as_bytes()),
        "{embedded}"
    );
    assert!(vault.restore_write(&out).is_err(), "{embedded}");

    // `AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw` is 34 characters. The Bot
    // API sample secret is 34 too. This keeps that alphabet and is
    // exactly 35.
    let mixed_body = "ABC-DEF1234ghIkl-zyx57W2v1u123ew11A";
    assert_eq!(mixed_body.len(), 35);
    let mixed = format!("123456789:{mixed_body}");
    let (vault, out, audit) = shield(&mixed);
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "h1_secret", "{mixed} -> {out}");
    assert!(hidden(&out, "123456789"), "{mixed} -> {out}");
    assert!(hidden(&out, mixed_body), "{mixed} -> {out}");
    assert!(!vault.holds_surface(mixed.as_bytes()), "{mixed}");
    assert!(vault.restore_write(&out).is_err(), "{mixed}");

    for bare in [
        format!("1234:{}", "a".repeat(35)),
        format!("{}:{}", "1".repeat(17), "a".repeat(35)),
        format!("123456789:{}", "a".repeat(34)),
        format!("123456789:{}", "a".repeat(36)),
        "123456789".to_string(),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn numero_sign_in_the_sin_cue_still_shields_the_number() {
    // `n°` and `nº` are that same cue. Leaving the sign out sends the number.
    let sin = "130692544";
    let degree = '\u{00B0}';
    let ordinal = '\u{00BA}';
    let cue = format!("n{degree} d'assurance sociale");

    let text = format!("{cue} {sin}");
    let (vault, out, audit) = shield(&text);
    assert_eq!(audit.sin, 1, "{text} -> {out}");
    assert!(out.starts_with(&format!("{cue} h1_sin_")), "{out}");
    assert!(out.contains(degree), "{out}");
    assert!(hidden(&out, sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);

    let grouped = format!(
        "n{ordinal} d'assurance sociale {} {} {}",
        &sin[..3],
        &sin[3..6],
        &sin[6..]
    );
    let (vault, out, audit) = shield(&grouped);
    assert_eq!(audit.sin, 1, "{grouped} -> {out}");
    assert!(
        out.starts_with(&format!("n{ordinal} d'assurance sociale h1_sin_")),
        "{out}"
    );
    assert!(out.contains(ordinal), "{out}");
    assert!(hidden(&out, sin), "{out}");
    assert!(hidden(&out, &sin[..3]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), grouped);

    let sentence = format!("the {cue} is {sin} today");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.sin, 1, "{sentence} -> {out}");
    assert!(out.starts_with(&format!("the {cue} is h1_sin_")), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(degree), "{out}");
    assert!(hidden(&out, sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    for bare in [
        sin.to_string(),
        format!("{cue} 130692545"),
        format!("{cue}{}{sin}", " ".repeat(41)),
        format!("note {sin}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn halfwidth_middle_dot_between_groups_still_shields_the_number() {
    // U+FF65 sits between groups the way a hyphen does. Leaving that
    // halfwidth middle dot out sends the number. A slash is still not
    // a SIN separator.
    let phone = "416\u{FF65}555\u{FF65}0123";
    round_trip(phone, |audit| audit.phone);
    let (vault, out, audit) = shield(phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert!(hidden(&out, "416"), "{phone} -> {out}");
    assert!(hidden(&out, "555"), "{phone} -> {out}");
    assert!(hidden(&out, "0123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let international = "+44\u{FF65}20\u{FF65}7946\u{FF65}0958";
    round_trip(international, |audit| audit.phone);
    let (vault, out, audit) = shield(international);
    assert_eq!(audit.phone, 1, "{international} -> {out}");
    assert!(hidden(&out, "44"), "{international} -> {out}");
    assert!(hidden(&out, "20"), "{international} -> {out}");
    assert!(hidden(&out, "7946"), "{international} -> {out}");
    assert!(hidden(&out, "0958"), "{international} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), international);

    let card = "4111\u{FF65}1111\u{FF65}1111\u{FF65}1111";
    round_trip(card, |audit| audit.card);
    let (vault, out, audit) = shield(card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(hidden(&out, "4111"), "{card} -> {out}");
    assert!(hidden(&out, "1111"), "{card} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    let sin = "SIN 130\u{FF65}692\u{FF65}544";
    let (vault, out, audit) = shield(sin);
    assert_eq!(audit.sin, 1, "{sin} -> {out}");
    assert!(out.starts_with("SIN h1_sin_"), "{sin} -> {out}");
    assert!(hidden(&out, "130"), "{sin} -> {out}");
    assert!(hidden(&out, "692"), "{sin} -> {out}");
    assert!(hidden(&out, "544"), "{sin} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sin);

    for bare in [
        "not\u{FF65}a\u{FF65}phone",
        "4111\u{FF65}1111\u{FF65}1111\u{FF65}1112",
        "130\u{FF65}692\u{FF65}544",
        "SIN 130/692/544",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn halfwidth_full_stop_still_shields_the_address() {
    // `user@example.com` is already an email. A halfwidth ideographic
    // full stop, U+FF61, is that same dot in the local part or the
    // domain. Leaving it out sends the address. A stop with no final
    // label, and a domain with no local part, stay as written.
    let domain = "user@example\u{FF61}com";
    let (vault, out, audit) = shield(domain);
    assert_eq!(audit.email, 1, "{domain} -> {out}");
    assert_eq!(audit.phone, 0, "{domain} -> {out}");
    assert!(out.starts_with("h1_email_"), "{domain} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{domain} -> {out}");
    assert!(!out.contains('\u{FF61}'), "{domain} -> {out}");
    assert!(hidden(&out, "user"), "{domain} -> {out}");
    assert!(hidden(&out, "example"), "{domain} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), domain);

    let local = "user\u{FF61}name@example.com";
    let (vault, out, audit) = shield(local);
    assert_eq!(audit.email, 1, "{local} -> {out}");
    assert_eq!(audit.phone, 0, "{local} -> {out}");
    assert!(out.starts_with("h1_email_"), "{local} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{local} -> {out}");
    assert!(!out.contains('\u{FF61}'), "{local} -> {out}");
    assert!(hidden(&out, "user"), "{local} -> {out}");
    assert!(hidden(&out, "name"), "{local} -> {out}");
    assert!(hidden(&out, "example"), "{local} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), local);

    let sentence = "see user@example\u{FF61}co\u{FF61}uk next";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("see h1_email_"), "{out}");
    assert!(out.ends_with(" next"), "{out}");
    assert!(!out.contains('\u{FF61}'), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    for bare in [
        "user@example\u{FF61}",
        "example\u{FF61}com",
        "not an address",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn postman_api_key_is_masked() {
    // Postman's authentication page shows an API key as `PMAK-`,
    // 24 hex characters, a hyphen, and 34 hex characters. A shorter
    // body stays as written. The value is not stored.
    let head = "a".repeat(24);
    let tail = "b".repeat(34);
    let body = format!("{head}-{tail}");
    let token = format!("PMAK-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "PMAK"), "{token} -> {out}");
    assert!(hidden(&out, &head), "{token} -> {out}");
    assert!(hidden(&out, &tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "PMAK"), "{out}");
    assert!(hidden(&out, &head), "{out}");
    assert!(hidden(&out, &tail), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("PMAK-{}-{}", "a".repeat(24), "b".repeat(33)),
        format!("wordPMAK-{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn small_commercial_at_still_shields_the_address() {
    // `user@example.com` is already an email. A small commercial at,
    // U+FE6B, is that sign. Leaving it out sends the address. A sign
    // with no domain, a domain with no local part, and a space around
    // the sign stay as written.
    let email = "user\u{FE6B}example.com";
    let (vault, out, audit) = shield(email);
    assert_eq!(audit.email, 1, "{email} -> {out}");
    assert_eq!(audit.phone, 0, "{email} -> {out}");
    assert_eq!(audit.card, 0, "{email} -> {out}");
    assert_eq!(audit.sin, 0, "{email} -> {out}");
    assert!(out.starts_with("h1_email_"), "{email} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
    assert!(!out.contains('\u{FE6B}'), "{email} -> {out}");
    assert!(hidden(&out, "user"), "{email} -> {out}");
    assert!(hidden(&out, "example"), "{email} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), email);

    let sentence = "see user\u{FE6B}example.com next";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("see h1_email_"), "{out}");
    assert!(out.ends_with(" next"), "{out}");
    assert!(!out.contains('\u{FE6B}'), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    for bare in [
        "user\u{FE6B}",
        "example.com",
        "not an address",
        "user \u{FE6B} example.com",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn fullwidth_low_line_still_shields_the_address() {
    // `user_tag@example.com` is already an email. A wide keyboard writes
    // that underscore as U+FF3F. Leaving the mark out sends the head.
    // A local part may start on `_`, so it may start on this mark too.
    // The same mark in a domain stays as written.
    let email = "user\u{FF3F}tag@example.com";
    let (vault, out, audit) = shield(email);
    assert_eq!(audit.email, 1, "{email} -> {out}");
    assert_eq!(audit.phone, 0, "{email} -> {out}");
    assert!(out.starts_with("h1_email_"), "{email} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{email} -> {out}");
    assert!(!out.contains('\u{FF3F}'), "{email} -> {out}");
    assert!(!out.contains('@'), "{email} -> {out}");
    assert!(hidden(&out, "user"), "{email} -> {out}");
    assert!(hidden(&out, "tag"), "{email} -> {out}");
    assert!(hidden(&out, "example"), "{email} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), email);

    let sentence = "see user\u{FF3F}name@example.com next";
    let (vault, out, audit) = shield(sentence);
    assert_eq!(audit.email, 1, "{sentence} -> {out}");
    assert!(out.starts_with("see h1_email_"), "{out}");
    assert!(out.ends_with(" next"), "{out}");
    assert!(!out.contains('\u{FF3F}'), "{out}");
    assert!(hidden(&out, "user"), "{out}");
    assert!(hidden(&out, "name"), "{out}");
    assert!(hidden(&out, "example"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let leading = "\u{FF3F}tag@example.com";
    let (vault, out, audit) = shield(leading);
    assert_eq!(audit.email, 1, "{leading} -> {out}");
    assert!(out.starts_with("h1_email_"), "{leading} -> {out}");
    assert_eq!(out.len(), "h1_email_".len() + 9, "{leading} -> {out}");
    assert!(!out.contains('\u{FF3F}'), "{leading} -> {out}");
    assert!(hidden(&out, "tag"), "{leading} -> {out}");
    assert!(hidden(&out, "example"), "{leading} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), leading);

    for bare in ["user@ex\u{FF3F}ample.com", "not an address"] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.email, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn small_parentheses_still_shield_the_number() {
    // `(416) 555-0123` is already a phone, and so is `+44 (20) 7946 0958`.
    // A small parenthesis is that mark. Leaving it out sends the number.
    // Five digits glued to the closing mark stay as written.
    let open = "\u{FE59}";
    let close = "\u{FE5A}";
    let local = format!("{open}416{close} 555-0123");
    let (vault, out, audit) = shield(&local);
    assert_eq!(audit.phone, 1, "{local} -> {out}");
    assert!(hidden(&out, "416"), "{local} -> {out}");
    assert!(hidden(&out, "555"), "{local} -> {out}");
    assert!(hidden(&out, "0123"), "{local} -> {out}");
    assert!(!out.contains(open), "{local} -> {out}");
    assert!(!out.contains(close), "{local} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), local);

    let intl = format!("+44 {open}20{close} 7946 0958");
    let (vault, out, audit) = shield(&intl);
    assert_eq!(audit.phone, 1, "{intl} -> {out}");
    assert!(hidden(&out, "44"), "{intl} -> {out}");
    assert!(hidden(&out, "20"), "{intl} -> {out}");
    assert!(hidden(&out, "7946"), "{intl} -> {out}");
    assert!(hidden(&out, "0958"), "{intl} -> {out}");
    assert!(!out.contains(open), "{intl} -> {out}");
    assert!(!out.contains(close), "{intl} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), intl);

    for bare in [
        format!("{open}416{close}55501234"),
        format!("+44{open}20{close}79460958"),
        "not a phone".to_string(),
        "555-0123".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn de_l_assurance_cue_still_shields_the_number() {
    // `de l'assurance` is that same cue. Leaving it out sends the number.
    let sin = "130692544";
    let cue = "numéro de l'assurance sociale";
    let text = format!("{cue} {sin}");
    let (vault, out, audit) = shield(&text);
    assert_eq!(audit.sin, 1, "{text} -> {out}");
    assert!(out.starts_with(&format!("{cue} h1_sin_")), "{out}");
    assert!(hidden(&out, sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);

    let plain = format!(
        "numero de l'assurance sociale {} {} {}",
        &sin[..3],
        &sin[3..6],
        &sin[6..]
    );
    let (vault, out, audit) = shield(&plain);
    assert_eq!(audit.sin, 1, "{plain} -> {out}");
    assert!(
        out.starts_with("numero de l'assurance sociale h1_sin_"),
        "{out}"
    );
    assert!(hidden(&out, sin), "{out}");
    assert!(hidden(&out, &sin[..3]), "{out}");
    assert!(hidden(&out, &sin[3..6]), "{out}");
    assert!(hidden(&out, &sin[6..]), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), plain);

    let curly = format!("numéro de l\u{2019}assurance sociale {sin}");
    let (vault, out, audit) = shield(&curly);
    assert_eq!(audit.sin, 1, "{curly} -> {out}");
    assert!(
        out.starts_with("numéro de l\u{2019}assurance sociale h1_sin_"),
        "{out}"
    );
    assert!(out.contains('\u{2019}'), "{out}");
    assert!(hidden(&out, sin), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), curly);

    for bare in [
        sin.to_string(),
        format!("{cue} 130692545"),
        format!("{cue}{}{sin}", " ".repeat(41)),
        format!("note {sin}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn comma_between_groups_still_shields_the_number() {
    // A comma is that separator. Leaving it out sends the number.
    let phone = "416,555,0123";
    round_trip(phone, |audit| audit.phone);
    let (vault, out, audit) = shield(phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert!(hidden(&out, "416"), "{phone} -> {out}");
    assert!(hidden(&out, "555"), "{phone} -> {out}");
    assert!(hidden(&out, "0123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let fullwidth = "416\u{FF0C}555\u{FF0C}0123";
    round_trip(fullwidth, |audit| audit.phone);
    let (vault, out, audit) = shield(fullwidth);
    assert_eq!(audit.phone, 1, "{fullwidth} -> {out}");
    assert!(hidden(&out, "416"), "{fullwidth} -> {out}");
    assert!(hidden(&out, "555"), "{fullwidth} -> {out}");
    assert!(hidden(&out, "0123"), "{fullwidth} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), fullwidth);

    let card = "4111,1111,1111,1111";
    round_trip(card, |audit| audit.card);
    let (vault, out, audit) = shield(card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(hidden(&out, "4111"), "{card} -> {out}");
    assert!(hidden(&out, "1111"), "{card} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    for bare in [
        "not,a,phone",
        "4111,1111,1111,1112",
        "SIN 130,692,544",
        "130,692,544",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn square_access_token_is_masked() {
    // Square's access tokens page is where these credentials are
    // issued. An older access token is `sq0atp-` plus 22 characters.
    // An older application secret is `sq0csp-` plus 43. The `sk-`
    // rule does not see those prefixes, so the token stays in the
    // clear. A shorter body stays as written. A longer body stays
    // too. The value is not stored.
    let atp_body = "a".repeat(22);
    let atp = format!("sq0atp-{atp_body}");
    let (vault, out, audit) = shield(&atp);
    assert_eq!(audit.secret, 1, "{atp} -> {out}");
    assert_eq!(out, "h1_secret", "{atp} -> {out}");
    assert!(hidden(&out, "sq0atp"), "{atp} -> {out}");
    assert!(hidden(&out, &atp_body), "{atp} -> {out}");
    assert!(!vault.holds_surface(atp.as_bytes()), "{atp}");
    assert!(vault.restore_write(&out).is_err(), "{atp}");

    let csp_body = "b".repeat(43);
    let csp = format!("sq0csp-{csp_body}");
    let (vault, out, audit) = shield(&csp);
    assert_eq!(audit.secret, 1, "{csp} -> {out}");
    assert_eq!(out, "h1_secret", "{csp} -> {out}");
    assert!(hidden(&out, "sq0csp"), "{csp} -> {out}");
    assert!(hidden(&out, &csp_body), "{csp} -> {out}");
    assert!(!vault.holds_surface(csp.as_bytes()), "{csp}");
    assert!(vault.restore_write(&out).is_err(), "{csp}");

    let mixed = format!("sq0atp-a1_{}-{}", "c".repeat(8), "d".repeat(10));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "sq0atp"), "{out}");
    assert!(hidden(&out, "a1"), "{out}");
    assert!(hidden(&out, &"c".repeat(8)), "{out}");
    assert!(hidden(&out, &"d".repeat(10)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("sq0atp-{}", "a".repeat(21)),
        format!("sq0csp-{}", "b".repeat(42)),
        format!("sq0atp-{}", "a".repeat(23)),
        format!("sq0csp-{}", "b".repeat(44)),
        format!("wordsq0atp-{atp_body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn notion_integration_token_is_masked() {
    // Notion's authentication page sends a bearer token. New tokens
    // start with `ntn_` so scanners can find them. The published body
    // is 11 digits and 35 letters or digits, 46 characters. A shorter
    // body stays as written. The older `secret_` prefix is a common
    // word and stays as written. The value is not stored.
    let digits = "1".repeat(11);
    let tail = "a".repeat(35);
    let body = format!("{digits}{tail}");
    let token = format!("ntn_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "ntn"), "{token} -> {out}");
    assert!(hidden(&out, &digits), "{token} -> {out}");
    assert!(hidden(&out, &tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed_tail = "aBcDeFgHiJkLmNoPqRsT1234567890abcde";
    let mixed = format!("ntn_12345678901{mixed_tail}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "ntn"), "{out}");
    assert!(hidden(&out, "12345678901"), "{out}");
    assert!(hidden(&out, mixed_tail), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &digits), "{out}");
    assert!(hidden(&out, &tail), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("ntn_{}{}", "1".repeat(11), "a".repeat(34)),
        format!("wordntn_{body}"),
        format!("secret_{}", "b".repeat(50)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn fullwidth_assignment_sign_still_masks_the_value() {
    // ASCII `=` and `:` already separate the name from the value. A
    // fullwidth equals or colon is that separator. Leaving it out sends
    // the value. A short value and the name with no value stay as written.
    let secret = "abcdefghijklmnopqrstuvwxyz";
    for text in [
        format!("api_key\u{FF1D}{secret}"),
        format!("api_key\u{FF1A}{secret}"),
    ] {
        let (vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 1, "{text} -> {out}");
        assert!(out.contains("h1_secret"), "{text} -> {out}");
        assert!(hidden(&out, secret), "{text} -> {out}");
        assert!(!vault.holds_surface(secret.as_bytes()), "{text}");
        assert!(vault.restore_write(&out).is_err(), "{text} -> {out}");
    }

    for text in [
        "api_key\u{FF1D}short".to_string(),
        "not a secret".to_string(),
        "api_key".to_string(),
    ] {
        let (_vault, out, audit) = shield(&text);
        assert_eq!(audit.secret, 0, "{text} -> {out}");
        assert_eq!(out, text, "{text} -> {out}");
    }
}

#[test]
fn groq_api_key_is_masked() {
    // Groq's API keys page issues a key as `gsk_` plus a body. The
    // published body is 52 letters or digits. A shorter body stays as
    // written. A longer body stays too. The value is not stored.
    let body = "a".repeat(52);
    let token = format!("gsk_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "gsk"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("gsk_a1B{}", "c".repeat(49));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "gsk"), "{out}");
    assert!(hidden(&out, "a1B"), "{out}");
    assert!(hidden(&out, &"c".repeat(49)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("gsk_{}", "a".repeat(51)),
        format!("gsk_{}", "a".repeat(53)),
        format!("wordgsk_{body}"),
        format!("GSK_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn xai_api_key_is_masked() {
    // The management API example is `xai-` plus 80 letters or digits.
    // A shorter body stays as written. A longer body stays too. The
    // value is not stored.
    let body = format!("{}{}", "a".repeat(70), "1234567890");
    let token = format!("xai-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "xai"), "{token} -> {out}");
    assert!(hidden(&out, "1234567890"), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("xai-a12B{}", "c".repeat(76));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "xai"), "{out}");
    assert!(hidden(&out, "a12B"), "{out}");
    assert!(hidden(&out, &"c".repeat(76)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "1234567890"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let (vault, out, audit) = shield(&format!("{token}-next"));
    assert_eq!(audit.secret, 1, "{token}-next -> {out}");
    assert_eq!(out, "h1_secret-next", "{token}-next -> {out}");
    assert!(hidden(&out, "1234567890"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("xai-{}", "a".repeat(79)),
        format!("xai-{}", "a".repeat(81)),
        format!("wordxai-{body}"),
        format!("XAI-{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn supabase_secret_key_is_masked() {
    // The self-hosted key generator builds `sb_secret_`, 22 URL-safe
    // characters, `_`, and an 8-character checksum. A publishable key
    // uses the same body and stays as written. A shorter body and a
    // longer body stay as written. The value is not stored.
    let random = "a1234567890bcdefghijkL";
    let checksum = "Ab12cd3Z";
    assert_eq!(random.len(), 22);
    assert_eq!(checksum.len(), 8);
    let token = format!("sb_secret_{random}_{checksum}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "sb_secret"), "{token} -> {out}");
    assert!(hidden(&out, "1234567890"), "{token} -> {out}");
    assert!(hidden(&out, "Ab12"), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let dashed = format!("sb_secret_abcdefghij-lmnopqrstuv_{checksum}");
    assert_eq!("abcdefghij-lmnopqrstuv".len(), 22);
    let (vault, out, audit) = shield(&format!("see {dashed}.next"));
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{dashed} -> {out}");
    assert!(hidden(&out, "sb_secret"), "{out}");
    assert!(hidden(&out, "Ab12"), "{out}");
    assert!(!vault.holds_surface(dashed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let (vault, out, audit) = shield(&format!("{token}-next"));
    assert_eq!(audit.secret, 1, "{token}-next -> {out}");
    assert_eq!(out, "h1_secret-next", "{token}-next -> {out}");
    assert!(hidden(&out, "1234567890"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let hyphen_tail = "Ab12cd3-";
    let underscore_tail = "Ab12cd3_";
    assert_eq!(hyphen_tail.len(), 8);
    assert_eq!(underscore_tail.len(), 8);
    for tail in [hyphen_tail, underscore_tail] {
        let ended = format!("sb_secret_{random}_{tail}");
        let (vault, out, audit) = shield(&format!("{ended}.next"));
        assert_eq!(audit.secret, 1, "{ended} -> {out}");
        assert_eq!(out, "h1_secret.next", "{ended} -> {out}");
        assert!(hidden(&out, "1234567890"), "{out}");
        assert!(hidden(&out, "Ab12"), "{out}");
        assert!(!vault.holds_surface(ended.as_bytes()));
        assert!(vault.restore_write(&out).is_err());
    }

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "1234567890"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let public = format!("sb_publishable_{random}_{checksum}");
    for bare in [
        format!("sb_secret_{}_Ab12cd3Z", "a1234567890bcdefghijk"),
        format!("sb_secret_{random}_Ab12cd3"),
        format!("sb_secret_{random}_Ab12cd3ZZ"),
        format!("sb_secret_{}_Ab12cd3Z", "a1234567890bcdefghijkLM"),
        public,
        format!("wordsb_secret_{random}_{checksum}"),
        format!("SB_SECRET_{random}_{checksum}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn supabase_access_token_is_masked() {
    // The CLI accepts `sbp_`, `sbp_oauth_`, or `sbp_v0_` plus 40
    // lowercase hex characters. Uppercase hex stays as written. A
    // shorter body and a longer body stay as written. The value is
    // not stored.
    let body = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(body.len(), 40);
    for prefix in ["sbp_", "sbp_oauth_", "sbp_v0_"] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, "sbp_"), "{token} -> {out}");
        assert!(hidden(&out, "0123456789"), "{token} -> {out}");
        assert!(hidden(&out, "abcdef"), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let token = format!("sbp_{body}");
    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "0123456789"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "0123456789"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("sbp_{}", &body[..39]),
        format!("sbp_{body}a"),
        format!("sbp_oauth_{}", &body[..39]),
        format!("sbp_v0_{body}a"),
        format!("sbp_v1_{body}"),
        format!("sbp_{}", body.to_ascii_uppercase()),
        format!("SBP_{body}"),
        format!("wordsbp_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn docker_hub_access_token_is_masked() {
    // TruffleHog's dockerhub detector matches `dckr_pat_` plus 27
    // letters, digits, underscores, or hyphens, and `dckr_oat_` plus
    // 32 of those characters. A shorter body and a longer body stay
    // as written. The value is not stored.
    let pat_body = "a90B2c3D4e5F6g7H8i9J0k1L2mN";
    let oat_body = "b90C8d7E6f5G4h3I2j1K0l9M8n7O6pQ4";
    assert_eq!(pat_body.len(), 27);
    assert_eq!(oat_body.len(), 32);
    for (prefix, body) in [("dckr_pat_", pat_body), ("dckr_oat_", oat_body)] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, prefix), "{token} -> {out}");
        assert!(hidden(&out, "90"), "{token} -> {out}");
        assert!(hidden(&out, &body[..8]), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let pat = format!("dckr_pat_{pat_body}");
    let (vault, out, audit) = shield(&format!("see {pat}.next"));
    assert_eq!(audit.secret, 1, "{pat} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{pat} -> {out}");
    assert!(hidden(&out, "dckr_pat"), "{out}");
    assert!(hidden(&out, "90"), "{out}");
    assert!(!vault.holds_surface(pat.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let underscored_body = "a90B2c3D4e5F6g7H8i9J0k1L2_N";
    assert_eq!(underscored_body.len(), 27);
    let underscored = format!("dckr_pat_{underscored_body}");
    let (vault, out, audit) = shield(&format!("{underscored}-next"));
    assert_eq!(audit.secret, 1, "{underscored} -> {out}");
    assert_eq!(out, "h1_secret-next", "{underscored} -> {out}");
    assert!(hidden(&out, "90"), "{out}");
    assert!(!vault.holds_surface(underscored.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let hyphen_tail = format!("dckr_pat_{}-", &pat_body[..26]);
    assert_eq!(pat_body[..26].len() + 1, 27);
    let (vault, out, audit) = shield(&format!("{hyphen_tail}.next"));
    assert_eq!(audit.secret, 1, "{hyphen_tail} -> {out}");
    assert_eq!(out, "h1_secret.next", "{hyphen_tail} -> {out}");
    assert!(hidden(&out, "90"), "{out}");
    assert!(!vault.holds_surface(hyphen_tail.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let oat_hyphen = format!("dckr_oat_{}-", &oat_body[..31]);
    assert_eq!(oat_body[..31].len() + 1, 32);
    let (vault, out, audit) = shield(&format!("{oat_hyphen}.next"));
    assert_eq!(audit.secret, 1, "{oat_hyphen} -> {out}");
    assert_eq!(out, "h1_secret.next", "{oat_hyphen} -> {out}");
    assert!(hidden(&out, "90"), "{out}");
    assert!(!vault.holds_surface(oat_hyphen.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let oat = format!("dckr_oat_{oat_body}");
    let raw = format!(r#"{{"token":"{oat}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "90"), "{out}");
    assert!(!vault.holds_surface(oat.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("dckr_pat_{}", &pat_body[..26]),
        format!("dckr_pat_{pat_body}a"),
        format!("dckr_oat_{}", &oat_body[..31]),
        format!("dckr_oat_{oat_body}a"),
        format!("dckr_pat_{oat_body}"),
        format!("dckr_oat_{pat_body}"),
        format!("DCKR_PAT_{pat_body}"),
        format!("worddckr_pat_{pat_body}"),
        "dckr_pat_124509ugsdjga93".to_string(),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn linear_api_key_is_masked() {
    // Working with the GraphQL API sends a personal API key. The key
    // is `lin_api_` plus 40 characters. A shorter body stays as
    // written. The value is not stored.
    let body = "a".repeat(40);
    let token = format!("lin_api_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "lin_api"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("lin_api_a1B{}", "c".repeat(37));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "lin_api"), "{out}");
    assert!(hidden(&out, "a1B"), "{out}");
    assert!(hidden(&out, &"c".repeat(37)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("lin_api_{}", "a".repeat(39)),
        format!("wordlin_api_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn doppler_token_is_masked() {
    // A Doppler service token is `dp.st.` and a personal token is
    // `dp.pt.`. The auth token formats page publishes a body of 40
    // to 44 letters or digits. A service token may put a config name
    // of 2 to 35 characters between that prefix and the body. The
    // service tokens page shows `dp.st.`. The rules above do not see
    // those prefixes, so the token stays in the clear. A shorter body
    // stays as written. A longer body stays too. The value is not
    // stored.
    for prefix in ["dp.st.", "dp.pt."] {
        for n in [40usize, 44] {
            let body = "a".repeat(n);
            let token = format!("{prefix}{body}");
            let (vault, out, audit) = shield(&token);
            assert_eq!(audit.secret, 1, "{token} -> {out}");
            assert_eq!(out, "h1_secret", "{token} -> {out}");
            assert!(hidden(&out, "dp"), "{token} -> {out}");
            assert!(hidden(&out, &body), "{token} -> {out}");
            assert!(!vault.holds_surface(token.as_bytes()), "{token}");
            assert!(vault.restore_write(&out).is_err(), "{token}");
        }
    }

    let body = "bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";
    assert_eq!(body.len(), 43);
    let personal = format!("dp.pt.{body}");
    let (vault, out, audit) = shield(&personal);
    assert_eq!(audit.secret, 1, "{personal} -> {out}");
    assert_eq!(out, "h1_secret", "{personal} -> {out}");
    assert!(hidden(&out, "dp"), "{personal} -> {out}");
    assert!(hidden(&out, "pt"), "{personal} -> {out}");
    assert!(hidden(&out, body), "{personal} -> {out}");
    assert!(!vault.holds_surface(personal.as_bytes()), "{personal}");
    assert!(vault.restore_write(&out).is_err(), "{personal}");

    let configured = format!("dp.st.ab_c-1.{body}");
    let (vault, out, audit) = shield(&configured);
    assert_eq!(audit.secret, 1, "{configured} -> {out}");
    assert_eq!(out, "h1_secret", "{configured} -> {out}");
    assert!(hidden(&out, "dp.st"), "{configured} -> {out}");
    assert!(hidden(&out, "ab_c-1"), "{configured} -> {out}");
    assert!(hidden(&out, body), "{configured} -> {out}");
    assert!(!vault.holds_surface(configured.as_bytes()), "{configured}");
    assert!(vault.restore_write(&out).is_err(), "{configured}");

    let service = format!("dp.st.dev.{body}");
    let (vault, out, audit) = shield(&format!("see {service}.next"));
    assert_eq!(audit.secret, 1, "{service} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{service} -> {out}");
    assert!(hidden(&out, "dp"), "{out}");
    assert!(hidden(&out, "dev"), "{out}");
    assert!(hidden(&out, body), "{out}");
    assert!(!vault.holds_surface(service.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{personal}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, body), "{out}");
    assert!(!vault.holds_surface(personal.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let config_min = format!("dp.st.ab.{}", "c".repeat(40));
    let (vault, out, audit) = shield(&config_min);
    assert_eq!(audit.secret, 1, "{config_min} -> {out}");
    assert_eq!(out, "h1_secret", "{config_min} -> {out}");
    assert!(hidden(&out, &"c".repeat(40)), "{out}");
    assert!(!vault.holds_surface(config_min.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let config_max = format!("dp.st.{}.{}", "d".repeat(35), "e".repeat(44));
    let (vault, out, audit) = shield(&config_max);
    assert_eq!(audit.secret, 1, "{config_max} -> {out}");
    assert_eq!(out, "h1_secret", "{config_max} -> {out}");
    assert!(hidden(&out, &"d".repeat(35)), "{out}");
    assert!(hidden(&out, &"e".repeat(44)), "{out}");
    assert!(!vault.holds_surface(config_max.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("dp.st.{}", "a".repeat(39)),
        format!("dp.pt.{}", "a".repeat(39)),
        format!("dp.st.{}", "a".repeat(45)),
        format!("dp.pt.{}", "a".repeat(45)),
        format!("dp.st.dev.{}", "a".repeat(39)),
        format!("dp.st.a.{}", "a".repeat(40)),
        format!("dp.st.{}.{}", "a".repeat(36), "b".repeat(40)),
        format!("worddp.st.{}", "a".repeat(40)),
        format!("DP.ST.{}", "a".repeat(40)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn doppler_cli_token_is_masked() {
    // A Doppler CLI token is `dp.ct.` plus 40 to 44 letters or
    // digits. The auth token formats page publishes that shape.
    // The service and personal rules do not see `ct`, so the
    // token stays in the clear. A CLI token has no config name.
    // A shorter body stays as written. A longer body stays too.
    // The value is not stored.
    let body = "bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";
    assert_eq!(body.len(), 43);
    let token = format!("dp.ct.{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "dp.ct"), "{token} -> {out}");
    assert!(hidden(&out, body), "{token} -> {out}");
    assert!(hidden(&out, "0Ve6w5"), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let digits = format!("0123456789{}", "a".repeat(30));
    assert_eq!(digits.len(), 40);
    let numbered = format!("dp.ct.{digits}");
    let (vault, out, audit) = shield(&format!("see {numbered}.next"));
    assert_eq!(audit.secret, 1, "{numbered} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{numbered} -> {out}");
    assert!(hidden(&out, "dp.ct"), "{out}");
    assert!(hidden(&out, "0123456789"), "{out}");
    assert!(hidden(&out, &"a".repeat(30)), "{out}");
    assert!(!vault.holds_surface(numbered.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let long = "b".repeat(44);
    let wide = format!("dp.ct.{long}");
    let (vault, out, audit) = shield(&wide);
    assert_eq!(audit.secret, 1, "{wide} -> {out}");
    assert_eq!(out, "h1_secret", "{wide} -> {out}");
    assert!(hidden(&out, &long), "{out}");
    assert!(!vault.holds_surface(wide.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let configured = format!("dp.st.ct.{body}");
    let (vault, out, audit) = shield(&configured);
    assert_eq!(audit.secret, 1, "{configured} -> {out}");
    assert_eq!(out, "h1_secret", "{configured} -> {out}");
    assert!(hidden(&out, "dp.st"), "{configured} -> {out}");
    assert!(hidden(&out, "ct"), "{configured} -> {out}");
    assert!(hidden(&out, body), "{configured} -> {out}");
    assert!(!vault.holds_surface(configured.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, body), "{out}");
    assert!(hidden(&out, "0Ve6w5"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("dp.ct.{}", "a".repeat(39)),
        format!("dp.ct.{}", "a".repeat(45)),
        format!("dp.ct.dev.{}", "a".repeat(40)),
        format!("worddp.ct.{}", "a".repeat(40)),
        format!("DP.CT.{}", "a".repeat(40)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn doppler_service_account_scim_and_audit_token_is_masked() {
    // A Doppler service account token is `dp.sa.`. A service account
    // identity token is `dp.said.`. A SCIM token is `dp.scim.`. An
    // audit token is `dp.audit.`. The auth token formats page
    // publishes a body of 40 to 44 letters or digits. Those formats
    // have no config name. The service and CLI rules do not see these
    // prefixes, so the token stays in the clear. A shorter body stays
    // as written. A longer body stays too. The value is not stored.
    let body = "bAqhcVzrhy5cRHkOlNTc0Ve6w5NUDCpcutm8vGE9myi";
    assert_eq!(body.len(), 43);
    for prefix in ["dp.sa.", "dp.said.", "dp.scim.", "dp.audit."] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(
            hidden(&out, prefix.trim_end_matches('.')),
            "{token} -> {out}"
        );
        assert!(hidden(&out, body), "{token} -> {out}");
        assert!(hidden(&out, "0Ve6w5"), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    for prefix in ["dp.sa.", "dp.said.", "dp.scim.", "dp.audit."] {
        for n in [40usize, 44] {
            let payload = "c".repeat(n);
            let token = format!("{prefix}{payload}");
            let (vault, out, audit) = shield(&token);
            assert_eq!(audit.secret, 1, "{token} -> {out}");
            assert_eq!(out, "h1_secret", "{token} -> {out}");
            assert!(
                hidden(&out, prefix.trim_end_matches('.')),
                "{token} -> {out}"
            );
            assert!(hidden(&out, &payload), "{token} -> {out}");
            assert!(!vault.holds_surface(token.as_bytes()), "{token}");
            assert!(vault.restore_write(&out).is_err(), "{token}");
        }
    }

    let digits = format!("0123456789{}", "a".repeat(30));
    assert_eq!(digits.len(), 40);
    let numbered = format!("dp.scim.{digits}");
    let (vault, out, audit) = shield(&format!("see {numbered}.next"));
    assert_eq!(audit.secret, 1, "{numbered} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{numbered} -> {out}");
    assert!(hidden(&out, "dp.scim"), "{out}");
    assert!(hidden(&out, "0123456789"), "{out}");
    assert!(hidden(&out, &"a".repeat(30)), "{out}");
    assert!(!vault.holds_surface(numbered.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let configured = format!("dp.st.sa.{body}");
    let (vault, out, audit) = shield(&configured);
    assert_eq!(audit.secret, 1, "{configured} -> {out}");
    assert_eq!(out, "h1_secret", "{configured} -> {out}");
    assert!(hidden(&out, "dp.st"), "{configured} -> {out}");
    assert!(hidden(&out, "sa"), "{configured} -> {out}");
    assert!(hidden(&out, body), "{configured} -> {out}");
    assert!(!vault.holds_surface(configured.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let audit_token = format!("dp.audit.{body}");
    let raw = format!(r#"{{"token":"{audit_token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, "dp.audit"), "{out}");
    assert!(hidden(&out, body), "{out}");
    assert!(hidden(&out, "0Ve6w5"), "{out}");
    assert!(!vault.holds_surface(audit_token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let mut stays = Vec::new();
    for prefix in ["dp.sa.", "dp.said.", "dp.scim.", "dp.audit."] {
        stays.push(format!("{prefix}{}", "a".repeat(39)));
        stays.push(format!("{prefix}{}", "a".repeat(45)));
        stays.push(format!("{prefix}dev.{}", "a".repeat(40)));
        stays.push(format!("word{prefix}{}", "a".repeat(40)));
        stays.push(format!("{}{}", prefix.to_ascii_uppercase(), "a".repeat(40)));
        stays.push(format!(
            "{}{}",
            prefix.trim_end_matches('.'),
            "a".repeat(40)
        ));
    }
    stays.push("not a token".to_string());
    for bare in stays {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn ideographic_comma_between_groups_still_shields_the_number() {
    // An ideographic comma is that separator. Leaving it out sends the number.
    let phone = "416\u{3001}555\u{3001}0123";
    round_trip(phone, |audit| audit.phone);
    let (vault, out, audit) = shield(phone);
    assert_eq!(audit.phone, 1, "{phone} -> {out}");
    assert!(hidden(&out, "416"), "{phone} -> {out}");
    assert!(hidden(&out, "555"), "{phone} -> {out}");
    assert!(hidden(&out, "0123"), "{phone} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let halfwidth = "416\u{FF64}555\u{FF64}0123";
    round_trip(halfwidth, |audit| audit.phone);
    let (vault, out, audit) = shield(halfwidth);
    assert_eq!(audit.phone, 1, "{halfwidth} -> {out}");
    assert!(hidden(&out, "416"), "{halfwidth} -> {out}");
    assert!(hidden(&out, "555"), "{halfwidth} -> {out}");
    assert!(hidden(&out, "0123"), "{halfwidth} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), halfwidth);

    let card = "4111\u{3001}1111\u{3001}1111\u{3001}1111";
    round_trip(card, |audit| audit.card);
    let (vault, out, audit) = shield(card);
    assert_eq!(audit.card, 1, "{card} -> {out}");
    assert!(hidden(&out, "4111"), "{card} -> {out}");
    assert!(hidden(&out, "1111"), "{card} -> {out}");
    assert_eq!(vault.restore_write(&out).unwrap(), card);

    for bare in [
        "not\u{3001}a\u{3001}phone",
        "4111\u{3001}1111\u{3001}1111\u{3001}1112",
        "SIN 130\u{3001}692\u{3001}544",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.phone, 0, "{bare} -> {out}");
        assert_eq!(audit.card, 0, "{bare} -> {out}");
        assert_eq!(audit.sin, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn sentry_auth_token_is_masked() {
    // The token formats page publishes a personal auth token as
    // `sntryu_` plus 64 hex characters, and an organization auth
    // token as `sntrys_`, a base64 payload, `_`, and 43 base64
    // characters. An organization token runs about 180 to 250
    // characters, so the payload length is not fixed. A shorter
    // body stays as written. A longer personal token stays too.
    // The value is not stored.
    let body = "a".repeat(64);
    let token = format!("sntryu_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "sntryu"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let payload = "ab+cd/ef=";
    let tail = format!("{}+", "A".repeat(42));
    assert_eq!(tail.len(), 43);
    let org = format!("sntrys_{payload}_{tail}");
    let (vault, out, audit) = shield(&org);
    assert_eq!(audit.secret, 1, "{org} -> {out}");
    assert_eq!(out, "h1_secret", "{org} -> {out}");
    assert!(hidden(&out, "sntrys"), "{org} -> {out}");
    assert!(hidden(&out, payload), "{org} -> {out}");
    assert!(hidden(&out, &tail), "{org} -> {out}");
    assert!(!vault.holds_surface(org.as_bytes()), "{org}");
    assert!(vault.restore_write(&out).is_err(), "{org}");

    let mixed_body = format!("a1b{}", "c".repeat(61));
    let mixed = format!("sntryu_{mixed_body}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "sntryu"), "{out}");
    assert!(hidden(&out, "a1b"), "{out}");
    assert!(hidden(&out, &"c".repeat(61)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("sntryu_{}", "a".repeat(63)),
        format!("sntryu_{}", "a".repeat(65)),
        format!("sntryu_{}", "A".repeat(64)),
        format!("sntrys_{payload}_{}", "A".repeat(42)),
        format!("wordsntryu_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn resend_api_key_is_masked() {
    // A Resend API key is `re_` plus a body. Manage API keys is the
    // page for these keys. The create API key response is 8 letters
    // or digits, an underscore, and 24 more. A shorter body stays as
    // written. The value is not stored.
    let body = format!("{}_{}", "a".repeat(8), "b".repeat(24));
    assert_eq!(body.len(), 33);
    let token = format!("re_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "re"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("re_a1BcDeF2_{}", "c".repeat(24));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "re"), "{out}");
    assert!(hidden(&out, "a1"), "{out}");
    assert!(hidden(&out, &"c".repeat(24)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("re_{}_{}", "a".repeat(8), "b".repeat(23)),
        format!("wordre_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn grafana_token_is_masked() {
    // gitleaks grafana-service-account-token is `glsa_`, 32 letters
    // or digits, an underscore, and 8 hex characters.
    // grafana-cloud-api-token is `glc_` plus at least 32 base64
    // characters. A trailing `+` or `/` is part of the body, and `=`
    // padding is part of the token. The rules above do not see those
    // prefixes, so the token stays in the clear. A shorter body stays
    // as written. The value is not stored.
    let body = "a".repeat(32);
    let tail = "abcdef12";
    let token = format!("glsa_{body}_{tail}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "glsa"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(hidden(&out, tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let cloud_body = "b".repeat(32);
    let cloud = format!("glc_{cloud_body}");
    let (vault, out, audit) = shield(&cloud);
    assert_eq!(audit.secret, 1, "{cloud} -> {out}");
    assert_eq!(out, "h1_secret", "{cloud} -> {out}");
    assert!(hidden(&out, "glc"), "{cloud} -> {out}");
    assert!(hidden(&out, &cloud_body), "{cloud} -> {out}");
    assert!(!vault.holds_surface(cloud.as_bytes()), "{cloud}");
    assert!(vault.restore_write(&out).is_err(), "{cloud}");

    let plus_body = format!("{}+", "c".repeat(31));
    let plus_tail = format!("glc_{plus_body}");
    let (vault, out, audit) = shield(&plus_tail);
    assert_eq!(audit.secret, 1, "{plus_tail} -> {out}");
    assert_eq!(out, "h1_secret", "{plus_tail} -> {out}");
    assert!(hidden(&out, &"c".repeat(31)), "{out}");
    assert!(!vault.holds_surface(plus_tail.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let slash_body = format!("{}/", "d".repeat(31));
    let slash_tail = format!("glc_{slash_body}");
    let (vault, out, audit) = shield(&format!("see {slash_tail} next"));
    assert_eq!(audit.secret, 1, "{slash_tail} -> {out}");
    assert_eq!(out, "see h1_secret next", "{slash_tail} -> {out}");
    assert!(hidden(&out, "glc"), "{out}");
    assert!(hidden(&out, &"d".repeat(31)), "{out}");
    assert!(!vault.holds_surface(slash_tail.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let padded = format!("glc_{cloud_body}==");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, &cloud_body), "{out}");
    assert!(!vault.holds_surface(padded.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(hidden(&out, tail), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    for bare in [
        format!("glsa_{}_{tail}", "a".repeat(31)),
        format!("wordglsa_{body}_{tail}"),
        format!("glc_{}", "b".repeat(31)),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn heroku_api_key_is_masked() {
    // gitleaks heroku-api-key-v2 is `HRKU-AA` plus 58 letters, digits,
    // underscores, or hyphens. A shorter body stays as written. The
    // value is not stored.
    let body = "a".repeat(58);
    let token = format!("HRKU-AA{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "HRKU"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "HRKU"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("HRKU-AA{}", "a".repeat(57)),
        format!("wordHRKU-AA{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn planetscale_api_token_is_masked() {
    // gitleaks planetscale-api-token. The token is `pscale_tkn_` plus
    // 32 to 64 characters. A shorter body stays as written. A trailing
    // `=` is part of the token. The value is not stored.
    let body = "a".repeat(32);
    let token = format!("pscale_tkn_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pscale_tkn"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let wide = "b".repeat(64);
    let token64 = format!("pscale_tkn_{wide}");
    let (vault, out, audit) = shield(&token64);
    assert_eq!(audit.secret, 1, "{token64} -> {out}");
    assert_eq!(out, "h1_secret", "{token64} -> {out}");
    assert!(hidden(&out, "pscale_tkn"), "{token64} -> {out}");
    assert!(hidden(&out, &wide), "{token64} -> {out}");
    assert!(!vault.holds_surface(token64.as_bytes()), "{token64}");
    assert!(vault.restore_write(&out).is_err(), "{token64}");

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#);
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(restore_json_write(&vault, &out).is_err());

    let padded = format!("pscale_tkn_{body}=");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!out.contains('='), "{padded} -> {out}");
    assert!(!vault.holds_surface(padded.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("pscale_tkn_{}", "a".repeat(31)),
        format!("wordpscale_tkn_{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn perplexity_api_key_is_masked() {
    // A Perplexity API key is `pplx-` plus 48 letters or digits. The
    // value is not stored. A shorter body and a longer body stay as
    // written.
    let body = "a".repeat(48);
    assert_eq!(body.len(), 48);
    let token = format!("pplx-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pplx"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("pplx-{}", "a1BcDeF2".repeat(6));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "pplx"), "{out}");
    assert!(hidden(&out, "a1"), "{out}");
    assert!(hidden(&out, &"a1BcDeF2".repeat(6)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("pplx-{}", "a".repeat(47)),
        format!("pplx-{}", "b".repeat(49)),
        format!("wordpplx-{body}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn artifactory_token_is_masked() {
    // An Artifactory API key is `AKCp` plus 69 letters or digits. A
    // reference token is `cmVmd` plus 59 letters or digits. The value
    // is not stored. A shorter body and a longer body stay as written.
    let body = "a".repeat(69);
    assert_eq!(body.len(), 69);
    let token = format!("AKCp{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "AKCp"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let ref_body = "b".repeat(59);
    assert_eq!(ref_body.len(), 59);
    let reference = format!("cmVmd{ref_body}");
    let (vault, out, audit) = shield(&reference);
    assert_eq!(audit.secret, 1, "{reference} -> {out}");
    assert_eq!(out, "h1_secret", "{reference} -> {out}");
    assert!(hidden(&out, "cmVmd"), "{reference} -> {out}");
    assert!(hidden(&out, &ref_body), "{reference} -> {out}");
    assert!(!vault.holds_surface(reference.as_bytes()), "{reference}");
    assert!(vault.restore_write(&out).is_err(), "{reference}");

    let mixed_body = format!("a1Bc{}", "d".repeat(65));
    assert_eq!(mixed_body.len(), 69);
    let mixed = format!("AKCp{mixed_body}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "AKCp"), "{out}");
    assert!(hidden(&out, "a1Bc"), "{out}");
    assert!(hidden(&out, &"d".repeat(65)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("AKCp{}", "a".repeat(68)),
        format!("AKCp{}", "a".repeat(70)),
        format!("cmVmd{}", "b".repeat(58)),
        format!("wordAKCp{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn age_secret_key_is_masked() {
    // An age identity file secret is `AGE-SECRET-KEY-1` plus 58
    // Bech32 characters. The value is not stored. A shorter body
    // stays as written. A character outside that alphabet stays
    // outside the key.
    let body = "Q".repeat(58);
    assert_eq!(body.len(), 58);
    let token = format!("AGE-SECRET-KEY-1{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "AGE-SECRET-KEY"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "AGE"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let with_q = format!("{}q{}", "Q".repeat(28), "Q".repeat(29));
    for bare in [
        format!("AGE-SECRET-KEY-1{}", "Q".repeat(57)),
        format!("AGE-SECRET-KEY-1{with_q}"),
        format!("wordAGE-SECRET-KEY-1{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn pulumi_api_token_is_masked() {
    // A Pulumi access token is `pul-` plus 40 hex characters. The
    // value is not stored. A shorter body, a longer body, and an
    // uppercase hex body stay as written.
    let digits = "a1b2c3d4e5";
    let body = digits.repeat(4);
    assert_eq!(body.len(), 40);
    let token = format!("pul-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pul"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(hidden(&out, digits), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "pul"), "{out}");
    assert!(hidden(&out, digits), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("pul-{}", "a".repeat(39)),
        format!("pul-{}", "a".repeat(41)),
        format!("pul-{}", "A".repeat(40)),
        format!("wordpul-{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn brevo_api_key_is_masked() {
    // A Brevo API key is `xkeysib-`, 64 lowercase hex characters, a
    // hyphen, and 16 more letters or digits. The value is not stored.
    // A shorter body stays as written. The tail may be uppercase.
    let hex = "a".repeat(64);
    let tail = "b".repeat(16);
    assert_eq!(hex.len(), 64);
    assert_eq!(tail.len(), 16);
    let token = format!("xkeysib-{hex}-{tail}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "xkeysib"), "{token} -> {out}");
    assert!(hidden(&out, &hex), "{token} -> {out}");
    assert!(hidden(&out, &tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let upper_tail = "C".repeat(16);
    let mixed = format!("xkeysib-{hex}-{upper_tail}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "xkeysib"), "{out}");
    assert!(hidden(&out, &hex), "{out}");
    assert!(hidden(&out, &upper_tail), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let upper_hex = "A".repeat(64);
    for bare in [
        format!("xkeysib-{}-{tail}", "a".repeat(63)),
        format!("xkeysib-{hex}-{}", "b".repeat(15)),
        format!("xkeysib-{upper_hex}-{tail}"),
        format!("wordxkeysib-{hex}-{tail}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn dynatrace_api_token_is_masked() {
    // A Dynatrace token is `dt0c01.`, 24 letters or digits, a dot,
    // and 64 lowercase hex characters. The value is not stored. A
    // shorter body stays as written. The prefix is case sensitive.
    let head = "a1".repeat(12);
    assert_eq!(head.len(), 24);
    let tail = "abcdef01".repeat(8);
    assert_eq!(tail.len(), 64);
    let token = format!("dt0c01.{head}.{tail}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "dt0c01"), "{token} -> {out}");
    assert!(hidden(&out, &head), "{token} -> {out}");
    assert!(hidden(&out, &tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let upper_head = "A1B2C3D4E5F6".repeat(2);
    assert_eq!(upper_head.len(), 24);
    let upper_tail = "ABCDEF01".repeat(8);
    assert_eq!(upper_tail.len(), 64);
    let mixed = format!("dt0c01.{upper_head}.{upper_tail}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "dt0c01"), "{out}");
    assert!(hidden(&out, &upper_head), "{out}");
    assert!(hidden(&out, &upper_tail), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("dt0c01.{}.{tail}", "a".repeat(23)),
        format!("dt0c01.{head}.{}", "b".repeat(63)),
        format!("worddt0c01.{head}.{tail}"),
        format!("DT0C01.{head}.{tail}"),
        "not a token".to_string(),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn easypost_api_token_is_masked() {
    // An EasyPost production key is `EZAK` plus 54 letters or digits.
    // A test key is `EZTK` plus 54. The value is not stored. A shorter
    // body and a longer body stay as written.
    let body = "a".repeat(54);
    assert_eq!(body.len(), 54);
    let token = format!("EZAK{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "EZAK"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let test_body = "b".repeat(54);
    assert_eq!(test_body.len(), 54);
    let test_token = format!("EZTK{test_body}");
    let (vault, out, audit) = shield(&test_token);
    assert_eq!(audit.secret, 1, "{test_token} -> {out}");
    assert_eq!(out, "h1_secret", "{test_token} -> {out}");
    assert!(hidden(&out, "EZTK"), "{test_token} -> {out}");
    assert!(hidden(&out, &test_body), "{test_token} -> {out}");
    assert!(!vault.holds_surface(test_token.as_bytes()), "{test_token}");
    assert!(vault.restore_write(&out).is_err(), "{test_token}");

    let mixed_body = format!("a1Bc{}", "d".repeat(50));
    assert_eq!(mixed_body.len(), 54);
    let mixed = format!("EZAK{mixed_body}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "EZAK"), "{out}");
    assert!(hidden(&out, "a1Bc"), "{out}");
    assert!(hidden(&out, &"d".repeat(50)), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("EZAK{}", "a".repeat(53)),
        format!("EZAK{}", "a".repeat(55)),
        format!("ezak{}", "a".repeat(54)),
        format!("wordEZAK{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn rubygems_api_token_is_masked() {
    // A RubyGems API token is `rubygems_` plus 48 lowercase hex
    // characters. The value is not stored. A shorter body, a longer
    // body, and an uppercase hex body stay as written.
    let body = "a".repeat(48);
    assert_eq!(body.len(), 48);
    let token = format!("rubygems_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "rubygems"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "rubygems"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("rubygems_{}", "a".repeat(47)),
        format!("rubygems_{}", "a".repeat(49)),
        format!("rubygems_{}", "A".repeat(48)),
        format!("wordrubygems_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn prefect_api_token_is_masked() {
    // A Prefect API token is `pnu_` plus 36 letters or digits. The
    // value is not stored. A shorter body and a longer body stay as
    // written.
    let body = "a".repeat(36);
    assert_eq!(body.len(), 36);
    let token = format!("pnu_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pnu"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "pnu"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("pnu_{}", "a".repeat(35)),
        format!("pnu_{}", "a".repeat(37)),
        format!("wordpnu_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn readme_api_token_is_masked() {
    // A ReadMe API token is `rdme_` plus 70 lowercase letters or digits characters.
    // The value is not stored. A shorter body, a longer body, and an
    // uppercase body stay as written.
    let digits = "0123456789";
    let body = format!("{}z{}", "a".repeat(59), digits);
    assert_eq!(body.len(), 70);
    let token = format!("rdme_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "rdme"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(hidden(&out, digits), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "rdme"), "{out}");
    assert!(hidden(&out, digits), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("rdme_{}", "a".repeat(69)),
        format!("rdme_{}", "a".repeat(71)),
        format!("rdme_{}", "ABCDEF0123456789".repeat(4) + "ABCDEF"),
        format!("wordrdme_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn huggingface_org_token_is_masked() {
    // A Hugging Face organization token is `api_org_` plus 34 letters.
    // The value is not stored. A shorter body, a longer body, a digit
    // in the body, and an uppercase prefix stay as written.
    let body = "a".repeat(34);
    assert_eq!(body.len(), 34);
    let token = format!("api_org_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "api_org"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("api_org_{}", "Ab".repeat(17));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "api_org"), "{out}");
    assert!(hidden(&out, "Ab"), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("api_org_{}", "a".repeat(33)),
        format!("api_org_{}", "a".repeat(35)),
        format!("api_org_{}", "a".repeat(33) + "1"),
        format!("API_ORG_{body}"),
        format!("wordapi_org_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn adobe_client_secret_is_masked() {
    // An Adobe client secret is `p8e-` plus 32 letters or digits.
    // The value is not stored. A shorter body, a longer body, and
    // an uppercase prefix stay as written.
    let body = "a".repeat(32);
    assert_eq!(body.len(), 32);
    let token = format!("p8e-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "p8e-"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("p8e-{}", "A1".repeat(16));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "p8e-"), "{out}");
    assert!(hidden(&out, "A1"), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("p8e-{}", "a".repeat(31)),
        format!("p8e-{}", "a".repeat(33)),
        format!("P8E-{body}"),
        format!("wordp8e-{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn alibaba_access_key_is_masked() {
    // An Alibaba Cloud access key id is `LTAI` plus 20 letters or
    // digits. The value is not stored. A shorter body, a longer body,
    // and a lowercase prefix stay as written.
    let body = "a".repeat(20);
    assert_eq!(body.len(), 20);
    let token = format!("LTAI{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "LTAI"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("LTAI{}", "A1".repeat(10));
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "LTAI"), "{out}");
    assert!(hidden(&out, "A1"), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("LTAI{}", "a".repeat(19)),
        format!("LTAI{}", "a".repeat(21)),
        format!("ltai{body}"),
        format!("wordLTAI{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn shippo_api_token_is_masked() {
    // A Shippo token is `shippo_live_` or `shippo_test_` plus 40 hex
    // characters. The value is not stored. A shorter body, a longer
    // body, and another prefix stay as written.
    let body = "ab".repeat(20);
    assert_eq!(body.len(), 40);
    let token = format!("shippo_live_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "shippo_live"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let test_token = format!("shippo_test_{}", "CD".repeat(20));
    let (vault, out, audit) = shield(&format!("see {test_token}.next"));
    assert_eq!(audit.secret, 1, "{test_token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{test_token} -> {out}");
    assert!(hidden(&out, "shippo_test"), "{out}");
    assert!(hidden(&out, "CD"), "{out}");
    assert!(!vault.holds_surface(test_token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("shippo_live_{}", "ab".repeat(19)),
        format!("shippo_live_{}", "ab".repeat(21)),
        format!("shippo_prod_{body}"),
        format!("wordshippo_live_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn frameio_api_token_is_masked() {
    // A Frame.io token is `fio-u-` plus 64 letters, digits, `_`, `-`,
    // or `=`. The value is not stored. A shorter body, a longer body,
    // and an uppercase prefix stay as written. A final `=` stays
    // inside the mark.
    let body = "a".repeat(64);
    assert_eq!(body.len(), 64);
    let token = format!("fio-u-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "fio-u-"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let padded = format!("fio-u-{}=", "A".repeat(63));
    let (vault, out, audit) = shield(&format!("see {padded}.next"));
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{padded} -> {out}");
    assert!(hidden(&out, "fio-u-"), "{out}");
    assert!(!out.contains('='), "{out}");
    assert!(!vault.holds_surface(padded.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("fio-u-{}", "a".repeat(63)),
        format!("fio-u-{}", "a".repeat(65)),
        format!("FIO-U-{body}"),
        format!("wordfio-u-{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn duffel_api_token_is_masked() {
    // A Duffel token is `duffel_test_` or `duffel_live_` plus 43 token
    // characters. The value is not stored. A shorter body stays as
    // written. `duffel_prod_` stays as written.
    let body = "a".repeat(43);
    assert_eq!(body.len(), 43);
    let token = format!("duffel_test_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "duffel"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let live = format!("duffel_live_{}", "b".repeat(43));
    let (vault, out, audit) = shield(&format!("see {live}.next"));
    assert_eq!(audit.secret, 1, "{live} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{live} -> {out}");
    assert!(hidden(&out, "duffel"), "{out}");
    assert!(hidden(&out, "live"), "{out}");
    assert!(hidden(&out, &"b".repeat(43)), "{out}");
    assert!(!vault.holds_surface(live.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("duffel_test_{}", "a".repeat(42)),
        format!("duffel_prod_{body}"),
        format!("wordduffel_test_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn square_eaaa_token_is_masked() {
    // A Square access token may be `EAAA` plus 22 to 60 token
    // characters. The existing `sq0atp` rule is a different shape.
    // The value is not stored. A shorter body stays as written. A
    // final hyphen stays inside the mark.
    let body = "a".repeat(22);
    let token = format!("EAAA{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "EAAA"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "EAAA"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let hyphenated = format!("EAAA{}-", "b".repeat(21));
    let (vault, out, audit) = shield(&hyphenated);
    assert_eq!(audit.secret, 1, "{hyphenated} -> {out}");
    assert_eq!(out, "h1_secret", "{hyphenated} -> {out}");
    assert!(hidden(&out, "EAAA"), "{out}");
    assert!(hidden(&out, "-"), "{out}");
    assert!(hidden(&out, &"b".repeat(21)), "{out}");
    assert!(!vault.holds_surface(hyphenated.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [format!("EAAA{}", "a".repeat(21)), format!("wordEAAA{body}")] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn clojars_api_token_is_masked() {
    // A Clojars token is `CLOJARS_` plus 60 letters or digits. The
    // prefix may be any case. The value is not stored. A shorter body
    // and a longer body stay as written.
    let body = "a".repeat(60);
    assert_eq!(body.len(), 60);
    let token = format!("CLOJARS_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "CLOJARS_"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let lower = format!("clojars_{}", "b".repeat(60));
    let (vault, out, audit) = shield(&format!("see {lower}.next"));
    assert_eq!(audit.secret, 1, "{lower} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{lower} -> {out}");
    assert!(hidden(&out, "clojars_"), "{out}");
    assert!(hidden(&out, &"b".repeat(60)), "{out}");
    assert!(!vault.holds_surface(lower.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("CLOJARS_{}", "a".repeat(59)),
        format!("CLOJARS_{}", "a".repeat(61)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn infracost_api_token_is_masked() {
    // An Infracost token is `ico-` plus 32 letters or digits. The
    // value is not stored. A shorter body and a longer body stay as
    // written.
    let body = "a".repeat(32);
    assert_eq!(body.len(), 32);
    let token = format!("ico-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "ico"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "ico"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("ico-{}", "a".repeat(31)),
        format!("ico-{}", "a".repeat(33)),
        format!("wordico-{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn settlemint_token_is_masked() {
    // A Settlemint token is `sm_aat_`, `sm_pat_`, or `sm_sat_` plus 16
    // letters or digits. The value is not stored. A shorter body stays
    // as written.
    let body = "Ab12Cd34Ef56Gh78".to_string();
    assert_eq!(body.len(), 16);
    let token = format!("sm_aat_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "sm_aat_"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "sm_aat_"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let pat_body = "Zy98Xw76Vu54Ts32".to_string();
    let pat = format!("sm_pat_{pat_body}");
    let (vault, out, audit) = shield(&pat);
    assert_eq!(audit.secret, 1, "{pat} -> {out}");
    assert_eq!(out, "h1_secret", "{pat} -> {out}");
    assert!(hidden(&out, "sm_pat_"), "{pat} -> {out}");
    assert!(hidden(&out, &pat_body), "{pat} -> {out}");
    assert!(!vault.holds_surface(pat.as_bytes()), "{pat}");
    assert!(vault.restore_write(&out).is_err(), "{pat}");

    let sat_body = "aB3cD4eF5gH6iJ7k".to_string();
    let sat = format!("sm_sat_{sat_body}");
    let (vault, out, audit) = shield(&sat);
    assert_eq!(audit.secret, 1, "{sat} -> {out}");
    assert_eq!(out, "h1_secret", "{sat} -> {out}");
    assert!(hidden(&out, "sm_sat_"), "{sat} -> {out}");
    assert!(hidden(&out, &sat_body), "{sat} -> {out}");
    assert!(!vault.holds_surface(sat.as_bytes()), "{sat}");
    assert!(vault.restore_write(&out).is_err(), "{sat}");

    for bare in [
        format!("sm_pat_{}", "a".repeat(15)),
        format!("wordsm_aat_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn flyio_access_token_is_masked() {
    // A Fly.io deploy token is `fo1_` plus 43 token characters. A
    // macaroon token is `fm1a_`, `fm1r_`, or `fm2_` plus at least 100
    // base64 characters. The value is not stored. A shorter `fo1_`
    // body stays as written.
    let body = format!("{}b", "A".repeat(42));
    assert_eq!(body.len(), 43);
    let token = format!("fo1_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "fo1"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed_body = format!("{}xY9", "a1BcDe_-".repeat(5));
    assert_eq!(mixed_body.len(), 43);
    let mixed = format!("fo1_{mixed_body}");
    let (vault, out, audit) = shield(&format!("see {mixed}.next"));
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{mixed} -> {out}");
    assert!(hidden(&out, "fo1"), "{out}");
    assert!(hidden(&out, "a1Bc"), "{out}");
    assert!(hidden(&out, "xY9"), "{out}");
    assert!(!vault.holds_surface(mixed.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let mac_body = "A".repeat(100);
    let mac = format!("fm2_{mac_body}");
    let (vault, out, audit) = shield(&mac);
    assert_eq!(audit.secret, 1, "{mac} -> {out}");
    assert_eq!(out, "h1_secret", "{mac} -> {out}");
    assert!(hidden(&out, "fm2"), "{mac} -> {out}");
    assert!(hidden(&out, &mac_body), "{mac} -> {out}");
    assert!(!vault.holds_surface(mac.as_bytes()), "{mac}");
    assert!(vault.restore_write(&out).is_err(), "{mac}");

    let padded = format!("{mac}=");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, "fm2"), "{out}");
    assert!(hidden(&out, &mac_body), "{out}");
    assert!(hidden(&out, "="), "{out}");
    assert!(!vault.holds_surface(padded.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [format!("fo1_{}", "A".repeat(42)), format!("wordfo1_{body}")] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn bedrock_long_lived_key_is_masked() {
    // A Bedrock long-lived key is `ABSK` plus 109 to 269 base64
    // characters, with optional `=` padding. The value is not stored.
    // A shorter body stays as written.
    let body = "A".repeat(109);
    assert_eq!(body.len(), 109);
    let token = format!("ABSK{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "ABSK"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "ABSK"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let padded = format!("{token}=");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, "ABSK"), "{padded} -> {out}");
    assert!(hidden(&out, &body), "{padded} -> {out}");
    assert!(hidden(&out, "="), "{padded} -> {out}");
    assert!(!vault.holds_surface(padded.as_bytes()), "{padded}");
    assert!(vault.restore_write(&out).is_err(), "{padded}");

    for bare in [
        format!("ABSK{}", "A".repeat(108)),
        format!("wordABSK{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn onepassword_a3_secret_is_masked() {
    // A 1Password secret key starts with `A3-` and then the published
    // groups of uppercase letters and digits. The value is not stored.
    // A shorter group stays as written.
    let token = "A3-ABCDEF-ABCDEFGHIJK-ABCDE-ABCDE-ABCDE";
    let (vault, out, audit) = shield(token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "A3"), "{token} -> {out}");
    assert!(hidden(&out, "ABCDEFGHIJK"), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "A3"), "{out}");
    assert!(hidden(&out, "ABCDEFGHIJK"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let other = "A3-ABCDEF-ABCDEF-ABCDE-ABCDE-ABCDE-ABCDE";
    let (vault, out, audit) = shield(other);
    assert_eq!(audit.secret, 1, "{other} -> {out}");
    assert_eq!(out, "h1_secret", "{other} -> {out}");
    assert!(hidden(&out, "A3"), "{other} -> {out}");
    assert!(hidden(&out, "ABCDEF-ABCDE"), "{other} -> {out}");
    assert!(!vault.holds_surface(other.as_bytes()), "{other}");
    assert!(vault.restore_write(&out).is_err(), "{other}");

    let short = "A3-ABCDEF-ABCDEFGHIJK-ABCDE-ABCDE-ABCD";
    let (_vault, out, audit) = shield(short);
    assert_eq!(audit.secret, 0, "{short} -> {out}");
    assert_eq!(out, short, "{short} -> {out}");
}

#[test]
fn flutterwave_test_key_is_masked() {
    // A Flutterwave test secret or public key is `FLWSECK_TEST-` or
    // `FLWPUBK_TEST-`, 32 hex characters from a through h, and `-X`.
    // The encryption key is `FLWSECK_TEST-` plus 12 of those
    // characters. The value is not stored. A shorter body stays as
    // written.
    let body = "a".repeat(32);
    let token = format!("FLWSECK_TEST-{body}-X");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "FLWSECK_TEST"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let public = format!("FLWPUBK_TEST-{body}-X");
    let (vault, out, audit) = shield(&format!("see {public}.next"));
    assert_eq!(audit.secret, 1, "{public} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{public} -> {out}");
    assert!(hidden(&out, "FLWPUBK_TEST"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(public.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let enc_body = "b".repeat(12);
    let enc = format!("FLWSECK_TEST-{enc_body}");
    let (vault, out, audit) = shield(&enc);
    assert_eq!(audit.secret, 1, "{enc} -> {out}");
    assert_eq!(out, "h1_secret", "{enc} -> {out}");
    assert!(hidden(&out, "FLWSECK_TEST"), "{enc} -> {out}");
    assert!(hidden(&out, &enc_body), "{enc} -> {out}");
    assert!(!vault.holds_surface(enc.as_bytes()), "{enc}");
    assert!(vault.restore_write(&out).is_err(), "{enc}");

    let short = format!("FLWSECK_TEST-{}", "a".repeat(11));
    let (_vault, out, audit) = shield(&short);
    assert_eq!(audit.secret, 0, "{short} -> {out}");
    assert_eq!(out, short, "{short} -> {out}");
    assert!(!hidden(&out, "FLWSECK_TEST"), "{short} -> {out}");
}

#[test]
fn grafana_eyj_api_key_is_masked() {
    // A Grafana API key starts with `eyJrIjoi` and then 70 to 400
    // letters or digits, with optional `=` padding. The value is not
    // stored. A shorter body stays as written. This is not the
    // `glsa_` or `glc_` token.
    let body = "A".repeat(70);
    assert_eq!(body.len(), 70);
    let token = format!("eyJrIjoi{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "eyJrIjoi"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "eyJrIjoi"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let short = format!("eyJrIjoi{}", "A".repeat(69));
    let (_vault, out, audit) = shield(&short);
    assert_eq!(audit.secret, 0, "{short} -> {out}");
    assert_eq!(out, short, "{short} -> {out}");
}

#[test]
fn intra42_client_secret_is_masked() {
    // An intra42 client secret is `s-s4t2ud-` or `s-s4t2af-` plus 64
    // hex characters. The hex may be any case. The value is not stored.
    // A shorter body stays as written.
    let body = "a".repeat(64);
    assert_eq!(body.len(), 64);
    for prefix in ["s-s4t2ud-", "s-s4t2af-"] {
        let token = format!("{prefix}{body}");
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, prefix), "{token} -> {out}");
        assert!(hidden(&out, &body), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");

        let (vault, out, audit) = shield(&format!("see {token}.next"));
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
        assert!(hidden(&out, prefix), "{out}");
        assert!(hidden(&out, &body), "{out}");
        assert!(!vault.holds_surface(token.as_bytes()));
        assert!(vault.restore_write(&out).is_err());
    }

    let short = format!("s-s4t2ud-{}", "a".repeat(63));
    let (_vault, out, audit) = shield(&short);
    assert_eq!(audit.secret, 0, "{short} -> {out}");
    assert_eq!(out, short, "{short} -> {out}");
}

#[test]
fn scalingo_api_token_is_masked() {
    // A Scalingo token is `tk-us-` plus 48 token characters. The value
    // is not stored. A shorter body stays as written. A final hyphen
    // stays inside the mark.
    let body = "a".repeat(48);
    assert_eq!(body.len(), 48);
    let token = format!("tk-us-{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "tk-us-"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "tk-us-"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let hyphenated = format!("tk-us-{}-", "b".repeat(47));
    let (vault, out, audit) = shield(&hyphenated);
    assert_eq!(audit.secret, 1, "{hyphenated} -> {out}");
    assert_eq!(out, "h1_secret", "{hyphenated} -> {out}");
    assert!(hidden(&out, "tk-us-"), "{out}");
    assert!(hidden(&out, "-"), "{out}");
    assert!(hidden(&out, &"b".repeat(47)), "{out}");
    assert!(!vault.holds_surface(hyphenated.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("tk-us-{}", "a".repeat(47)),
        format!("wordtk-us-{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn maxmind_license_key_is_masked() {
    // A MaxMind license key is 6 letters or digits, `_`, 29 letters or
    // digits, and `_mmk`. The value is not stored. A shorter middle
    // stays as written.
    let middle = "A".repeat(29);
    assert_eq!(middle.len(), 29);
    let token = format!("abcdef_{middle}_mmk");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "abcdef"), "{token} -> {out}");
    assert!(hidden(&out, &middle), "{token} -> {out}");
    assert!(hidden(&out, "_mmk"), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "abcdef"), "{out}");
    assert!(hidden(&out, &middle), "{out}");
    assert!(hidden(&out, "_mmk"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let bare = format!("abcdef_{}_mmk", "A".repeat(28));
    let (_vault, out, audit) = shield(&bare);
    assert_eq!(audit.secret, 0, "{bare} -> {out}");
    assert_eq!(out, bare, "{bare} -> {out}");
}

#[test]
fn sourcegraph_access_token_is_masked() {
    // A Sourcegraph token is `sgp_` plus 40 hex characters, or `sgp_`
    // plus 16 hex characters or `local`, then `_`, then 40 hex
    // characters. The value is not stored. A bare 40 hex run with no
    // `sgp_` prefix stays as written. A shorter `sgp_` body stays as
    // written.
    let body = "a".repeat(40);
    assert_eq!(body.len(), 40);
    let token = format!("sgp_{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "sgp"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "sgp"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    let local_body = "b".repeat(40);
    let local = format!("sgp_local_{local_body}");
    let (vault, out, audit) = shield(&local);
    assert_eq!(audit.secret, 1, "{local} -> {out}");
    assert_eq!(out, "h1_secret", "{local} -> {out}");
    assert!(hidden(&out, "sgp"), "{local} -> {out}");
    assert!(hidden(&out, "local"), "{local} -> {out}");
    assert!(hidden(&out, &local_body), "{local} -> {out}");
    assert!(!vault.holds_surface(local.as_bytes()), "{local}");
    assert!(vault.restore_write(&out).is_err(), "{local}");

    let (vault, out, audit) = shield(&format!("see {local}.next"));
    assert_eq!(audit.secret, 1, "{local} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{local} -> {out}");
    assert!(hidden(&out, "sgp"), "{out}");
    assert!(hidden(&out, &local_body), "{out}");
    assert!(!vault.holds_surface(local.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [format!("sgp_{}", "a".repeat(39)), "c".repeat(40)] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn terraform_atlasv1_token_is_masked() {
    // A Terraform API token is 14 letters or digits, `.atlasv1.`, and
    // 60 to 70 token characters. `atlasv1` stays lowercase. The value
    // is not stored. A shorter tail stays as written.
    let head = "a".repeat(14);
    let tail = "b".repeat(60);
    let token = format!("{head}.atlasv1.{tail}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "atlasv1"), "{token} -> {out}");
    assert!(hidden(&out, &head), "{token} -> {out}");
    assert!(hidden(&out, &tail), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "atlasv1"), "{out}");
    assert!(hidden(&out, &head), "{out}");
    assert!(hidden(&out, &tail), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("{head}.atlasv1.{}", "b".repeat(59)),
        format!("{head}.ATLASV1.{tail}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn databricks_api_token_is_masked() {
    // A Databricks token is `dapi` plus 32 lowercase hex characters,
    // with an optional hyphen and one digit. The value is not stored.
    // A shorter body stays as written. Uppercase hex stays as written.
    let body = "a".repeat(32);
    let token = format!("dapi{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "dapi"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let dashed = format!("{token}-1");
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, "dapi"), "{dashed} -> {out}");
    assert!(hidden(&out, &body), "{dashed} -> {out}");
    assert!(hidden(&out, "-1"), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");
    assert!(vault.restore_write(&out).is_err(), "{dashed}");

    let (vault, out, audit) = shield(&format!("see {token}.next"));
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{token} -> {out}");
    assert!(hidden(&out, "dapi"), "{out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));
    assert!(vault.restore_write(&out).is_err());

    for bare in [
        format!("dapi{}", "a".repeat(31)),
        format!("dapi{}", "A".repeat(32)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn openshift_user_token_is_masked() {
    // An OpenShift user token is `sha256~` plus 43 token characters.
    // The value is not stored. A shorter body stays as written.
    let body = "a".repeat(43);
    let token = format!("sha256~{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "sha256"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let dashed = format!("sha256~{}-", "b".repeat(42));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, "sha256"), "{dashed} -> {out}");
    assert!(hidden(&out, &"b".repeat(42)), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "sha256"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("sha256~{}", "a".repeat(42)),
        format!("sha256~{}", "a".repeat(44)),
        format!("xsha256~{}", "a".repeat(43)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn other_aws_access_key_prefixes_are_masked() {
    // ABIA, ACCA, and A3T are access key ids the AKIA/ASIA rule does
    // not see. The value is not stored. A shorter id stays as written.
    for key in [
        "ABIAIOSFODNN7EXAMPLE",
        "ACCAIOSFODNN7EXAMPLE",
        "A3TAIOSFODNN7EXAMPLE",
    ] {
        let (vault, out, audit) = shield(key);
        assert_eq!(audit.secret, 1, "{key} -> {out}");
        assert_eq!(out, "h1_secret", "{key} -> {out}");
        assert!(hidden(&out, key), "{key} -> {out}");
        assert!(!vault.holds_surface(key.as_bytes()), "{key}");
        assert!(vault.restore_write(&out).is_err(), "{key}");
    }

    let key = "ABIAIOSFODNN7EXAMPLE";
    let sentence = format!("export AWS_ACCESS_KEY_ID={key} please");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "export AWS_ACCESS_KEY_ID=h1_secret please");
    assert!(hidden(&out, key), "{out}");
    assert!(!vault.holds_surface(key.as_bytes()));

    for bare in [
        "ABIAIOSFODNN7EXAMPL",
        "abiaIOSFODNN7EXAMPLE",
        "ABIAIOSFODNN7EXAMPLEX",
        "A3TAIOSFODNN0EXAMPLE",
        "A3TAIOSFODNN7EXAMPL",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn new_relic_api_keys_are_masked() {
    // New Relic keys start with NRJS-, NRAK-, or NRII-. The value is
    // not stored. A shorter body stays as written.
    let nrjs = format!("NRJS-{}", "a".repeat(19));
    let nrak = format!("NRAK-{}", "b".repeat(27));
    let nrii = format!("NRII-{}", "c".repeat(32));
    let nrii_dash = format!("NRII-{}-", "d".repeat(31));
    for token in [&nrjs, &nrak, &nrii, &nrii_dash] {
        let (vault, out, audit) = shield(token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, token), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let sentence = format!("see {nrjs}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, &nrjs), "{out}");
    assert!(!vault.holds_surface(nrjs.as_bytes()));

    for bare in [
        format!("NRJS-{}", "a".repeat(18)),
        format!("NRJS-{}", "A".repeat(19)),
        format!("NRJS-{}", "a".repeat(20)),
        format!("NRAK-{}", "b".repeat(26)),
        format!("NRAK-{}", "b".repeat(28)),
        format!("NRII-{}", "c".repeat(31)),
        format!("NRII-{}", "c".repeat(33)),
        format!("x{nrjs}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn gitlab_runner_registration_token_is_masked() {
    // A GitLab runner registration token is `GR1348941` plus 20
    // characters. The value is not stored. A shorter body stays
    // as written.
    let body = "a".repeat(20);
    let token = format!("GR1348941{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "GR1348941"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let dashed = format!("GR1348941{}-", "b".repeat(19));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, "GR1348941"), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next");
    assert!(hidden(&out, "GR1348941"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("GR1348941{}", "a".repeat(19)),
        format!("GR1348941{}", "a".repeat(21)),
        format!("gr1348941{body}"),
        format!("xGR1348941{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn planetscale_oauth_and_password_are_masked() {
    // `pscale_oauth_` and `pscale_pw_` are not the service token.
    // The value is not stored. A shorter body stays as written.
    let body = "a".repeat(32);
    let oauth = format!("pscale_oauth_{body}");
    let password = format!("pscale_pw_{body}");
    let password_upper = format!("PSCALE_PW_{body}");
    for token in [&oauth, &password, &password_upper] {
        let (vault, out, audit) = shield(token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, "pscale"), "{token} -> {out}");
        assert!(hidden(&out, &body), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let wide = "b".repeat(64);
    let token64 = format!("pscale_oauth_{wide}");
    let (vault, out, audit) = shield(&token64);
    assert_eq!(audit.secret, 1, "{token64} -> {out}");
    assert_eq!(out, "h1_secret", "{token64} -> {out}");
    assert!(hidden(&out, &wide), "{token64} -> {out}");
    assert!(!vault.holds_surface(token64.as_bytes()), "{token64}");

    let padded = format!("pscale_pw_{body}=");
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, &body), "{out}");
    assert!(hidden(&out, "="), "{padded} -> {out}");
    assert!(!vault.holds_surface(padded.as_bytes()));

    for bare in [
        format!("pscale_oauth_{}", "a".repeat(31)),
        format!("pscale_pw_{}", "a".repeat(31)),
        format!("wordpscale_oauth_{body}"),
        format!("PSCALE_OAUTH_{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn pypi_upload_token_is_masked() {
    // `pypi-AgEIcHlwaS5vcmc` plus 50 characters is shorter than the
    // 85-character PyPI rule. The value is not stored.
    let body = "a".repeat(50);
    let token = format!("pypi-AgEIcHlwaS5vcmc{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pypi-"), "{token} -> {out}");
    assert!(hidden(&out, "AgEIcHlwaS5vcmc"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let dashed = format!("pypi-AgEIcHlwaS5vcmc{}-", "b".repeat(49));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, "AgEIcHlwaS5vcmc"), "{dashed} -> {out}");
    assert!(hidden(&out, "-"), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    for bare in [
        format!("pypi-AgEIcHlwaS5vcmc{}", "a".repeat(49)),
        format!("pypi-ageichlwas5vcmc{body}"),
        format!("xpypi-AgEIcHlwaS5vcmc{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn defined_networking_token_is_masked() {
    // A Defined Networking token is `dnkey-`, 26 characters, a hyphen,
    // and 52 more. The value is not stored. A shorter group stays
    // as written.
    let token = format!("dnkey-{}-{}", "a".repeat(26), "b".repeat(52));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "dnkey"), "{token} -> {out}");
    assert!(hidden(&out, &"a".repeat(26)), "{token} -> {out}");
    assert!(hidden(&out, &"b".repeat(52)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let upper = format!("DNKEY-{}-{}", "c".repeat(26), "d".repeat(52));
    let (vault, out, audit) = shield(&upper);
    assert_eq!(audit.secret, 1, "{upper} -> {out}");
    assert_eq!(out, "h1_secret", "{upper} -> {out}");
    assert!(!vault.holds_surface(upper.as_bytes()), "{upper}");

    let dashed = format!("dnkey-{}-{}-", "e".repeat(26), "f".repeat(51));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, &"f".repeat(51)), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    for bare in [
        format!("dnkey-{}-{}", "a".repeat(25), "b".repeat(52)),
        format!("dnkey-{}-{}", "a".repeat(26), "b".repeat(51)),
        format!("xdnkey-{}-{}", "a".repeat(26), "b".repeat(52)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn atlassian_api_token_is_masked() {
    // An Atlassian API token is `ATATT3` plus 186 characters. The
    // value is not stored. A shorter body stays as written.
    let body = "a".repeat(186);
    let token = format!("ATATT3{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "ATATT3"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let dashed = format!("ATATT3{}=", "b".repeat(185));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, "ATATT3"), "{dashed} -> {out}");
    assert!(hidden(&out, &"b".repeat(185)), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next");
    assert!(hidden(&out, "ATATT3"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("ATATT3{}", "a".repeat(185)),
        format!("ATATT3{}", "a".repeat(187)),
        format!("atatt3{body}"),
        format!("x{token}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn azure_ad_client_secret_is_masked() {
    // An Azure AD client secret contains `Q~`. The value is not stored.
    // A shorter tail stays as written.
    let token = format!("abc8Q~{}", "a".repeat(31));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "Q~"), "{token} -> {out}");
    assert!(hidden(&out, &"a".repeat(31)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let wide = format!("abc8Q~{}", "b".repeat(34));
    let (vault, out, audit) = shield(&wide);
    assert_eq!(audit.secret, 1, "{wide} -> {out}");
    assert_eq!(out, "h1_secret", "{wide} -> {out}");
    assert!(hidden(&out, &"b".repeat(34)), "{wide} -> {out}");
    assert!(!vault.holds_surface(wide.as_bytes()), "{wide}");

    let dashed = format!("abc8Q~{}-", "c".repeat(30));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, "Q~"), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "Q~"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("abc8Q~{}", "a".repeat(30)),
        format!("abc8Q~{}", "a".repeat(35)),
        format!("xabc8Q~{}", "a".repeat(31)),
        format!("abc8q~{}", "a".repeat(31)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn slack_webhook_url_is_masked() {
    // A Slack webhook is hooks.slack.com, then services, workflows,
    // or triggers, then 43 to 56 token characters. The value is not
    // stored. A shorter path stays as written.
    let body = "A".repeat(43);
    let token = format!("https://hooks.slack.com/services/{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "hooks.slack.com"), "{token} -> {out}");
    assert!(hidden(&out, &body), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let wide = "B".repeat(56);
    let workflow = format!("hooks.slack.com/workflows/{wide}");
    let (vault, out, audit) = shield(&workflow);
    assert_eq!(audit.secret, 1, "{workflow} -> {out}");
    assert_eq!(out, "h1_secret", "{workflow} -> {out}");
    assert!(hidden(&out, &wide), "{workflow} -> {out}");
    assert!(!vault.holds_surface(workflow.as_bytes()), "{workflow}");

    let trigger = format!("hooks.slack.com/triggers/{}", "C".repeat(43));
    let (vault, out, audit) = shield(&trigger);
    assert_eq!(audit.secret, 1, "{trigger} -> {out}");
    assert_eq!(out, "h1_secret", "{trigger} -> {out}");
    assert!(!vault.holds_surface(trigger.as_bytes()), "{trigger}");

    let plus = format!("hooks.slack.com/services/{}+", "D".repeat(42));
    let (vault, out, audit) = shield(&plus);
    assert_eq!(audit.secret, 1, "{plus} -> {out}");
    assert_eq!(out, "h1_secret", "{plus} -> {out}");
    assert!(hidden(&out, "+"), "{plus} -> {out}");
    assert!(!vault.holds_surface(plus.as_bytes()), "{plus}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "hooks.slack.com"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("https://hooks.slack.com/services/{}", "A".repeat(42)),
        format!("https://hooks.slack.com/services/{}", "A".repeat(57)),
        format!("https://hooks.slack.com/files/{body}"),
        format!("https://example.com/services/{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn teams_webhook_url_is_masked() {
    // A Teams incoming webhook posts to webhook.office.com. The value
    // is not stored. A shorter URL stays as written.
    let url = "https://contoso.webhook.office.com/webhookb2/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@11111111-2222-3333-4444-555555555555/IncomingWebhook/abcdefghijklmnopqrstuvwxyz012345/66666666-7777-8888-9999-000000000000";
    let (vault, out, audit) = shield(url);
    assert_eq!(audit.secret, 1, "{url} -> {out}");
    assert_eq!(out, "h1_secret", "{url} -> {out}");
    assert!(hidden(&out, "webhook.office.com"), "{url} -> {out}");
    assert!(hidden(&out, "IncomingWebhook"), "{url} -> {out}");
    assert!(!vault.holds_surface(url.as_bytes()), "{url}");
    assert!(vault.restore_write(&out).is_err(), "{url}");

    let sentence = format!("see {url}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "webhook.office.com"), "{out}");
    assert!(!vault.holds_surface(url.as_bytes()));

    let short = "https://contoso.webhook.office.com/webhookb2/not-a-webhook";
    let (_vault, out, audit) = shield(short);
    assert_eq!(audit.secret, 0, "{short} -> {out}");
    assert_eq!(out, short, "{short} -> {out}");
}

#[test]
fn sonar_api_token_is_masked() {
    // `squ_`, `sqp_`, and `sqa_` are Sonar tokens. The value is not
    // stored. A shorter body stays as written.
    for prefix in ["squ_", "sqp_", "sqa_", "SQU_"] {
        let token = format!("{prefix}{}", "a".repeat(40));
        let (vault, out, audit) = shield(&token);
        assert_eq!(audit.secret, 1, "{token} -> {out}");
        assert_eq!(out, "h1_secret", "{token} -> {out}");
        assert!(hidden(&out, prefix), "{token} -> {out}");
        assert!(hidden(&out, &"a".repeat(40)), "{token} -> {out}");
        assert!(!vault.holds_surface(token.as_bytes()), "{token}");
        assert!(vault.restore_write(&out).is_err(), "{token}");
    }

    let dashed = format!("sqp_{}=", "b".repeat(39));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, &"b".repeat(39)), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see squ_{}.next", "c".repeat(40));
    let (_vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "squ_"), "{out}");

    for bare in [
        format!("squ_{}", "a".repeat(39)),
        format!("squ_{}", "a".repeat(41)),
        format!("xsqu_{}", "a".repeat(40)),
        "a".repeat(40),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn yandex_iam_token_is_masked() {
    // A Yandex IAM token starts with `t1.`. The value is not stored.
    // A shorter second segment stays as written.
    let token = format!("t1.{}.{}", "a".repeat(8), "b".repeat(86));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "t1."), "{token} -> {out}");
    assert!(hidden(&out, &"b".repeat(86)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let upper = format!("T1.{}.{}", "c".repeat(8), "d".repeat(86));
    let (vault, out, audit) = shield(&upper);
    assert_eq!(audit.secret, 1, "{upper} -> {out}");
    assert_eq!(out, "h1_secret", "{upper} -> {out}");
    assert!(!vault.holds_surface(upper.as_bytes()), "{upper}");

    let padded = format!("t1.{}=.{}==", "e".repeat(8), "f".repeat(86));
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, "="), "{padded} -> {out}");
    assert!(!vault.holds_surface(padded.as_bytes()), "{padded}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "t1."), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("t1.{}.{}", "a".repeat(8), "b".repeat(85)),
        format!("xt1.{}.{}", "a".repeat(8), "b".repeat(86)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn yandex_iam_cookie_is_masked() {
    // A Yandex IAM cookie starts with `c1.`. The `t1.` rule does
    // not see this prefix. The value is not stored. A shorter
    // second segment stays as written.
    let token = format!("c1.{}.{}", "a".repeat(8), "b".repeat(86));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "c1."), "{token} -> {out}");
    assert!(hidden(&out, &"b".repeat(86)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let upper = format!("C1.{}.{}", "c".repeat(8), "d".repeat(86));
    let (vault, out, audit) = shield(&upper);
    assert_eq!(audit.secret, 1, "{upper} -> {out}");
    assert_eq!(out, "h1_secret", "{upper} -> {out}");
    assert!(!vault.holds_surface(upper.as_bytes()), "{upper}");

    let padded = format!("c1.{}=.{}==", "e".repeat(8), "f".repeat(86));
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, "="), "{padded} -> {out}");
    assert!(!vault.holds_surface(padded.as_bytes()), "{padded}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "c1."), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("c1.{}.{}", "a".repeat(8), "b".repeat(85)),
        format!("xc1.{}.{}", "a".repeat(8), "b".repeat(86)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn airtable_access_token_is_masked() {
    // An Airtable token is `pat`, 14 characters, a dot, and 64 hex
    // characters. The value is not stored. A shorter group stays
    // as written.
    let token = format!("pat{}.{}", "a".repeat(14), "b".repeat(64));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pat"), "{token} -> {out}");
    assert!(hidden(&out, &"b".repeat(64)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, &"b".repeat(64)), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("pat{}.{}", "a".repeat(13), "b".repeat(64)),
        format!("pat{}.{}", "a".repeat(14), "b".repeat(63)),
        format!("pat{}.{}", "a".repeat(14), "B".repeat(64)),
        format!("xpat{}.{}", "a".repeat(14), "b".repeat(64)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn mapbox_api_token_is_masked() {
    // A Mapbox token is `pk.`, 60 characters, a dot, and 22 more.
    // The value is not stored. A shorter segment stays as written.
    let token = format!("pk.{}.{}", "a".repeat(60), "b".repeat(22));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pk."), "{token} -> {out}");
    assert!(hidden(&out, &"b".repeat(22)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let upper = format!("PK.{}.{}", "c".repeat(60), "d".repeat(22));
    let (vault, out, audit) = shield(&upper);
    assert_eq!(audit.secret, 1, "{upper} -> {out}");
    assert_eq!(out, "h1_secret", "{upper} -> {out}");
    assert!(!vault.holds_surface(upper.as_bytes()), "{upper}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "pk."), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("pk.{}.{}", "a".repeat(59), "b".repeat(22)),
        format!("pk.{}.{}", "a".repeat(60), "b".repeat(21)),
        format!("xpk.{}.{}", "a".repeat(60), "b".repeat(22)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn cloudflare_origin_ca_key_is_masked() {
    // A Cloudflare Origin CA key is `v1.0-`, 24 hex characters, a
    // hyphen, and 146 more hex characters. The value is not stored.
    // A shorter group stays as written.
    let token = format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "v1.0-"), "{token} -> {out}");
    assert!(hidden(&out, &"b".repeat(146)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "v1.0-"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("v1.0-{}-{}", "a".repeat(23), "b".repeat(146)),
        format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(145)),
        format!("v1.0-{}-{}", "A".repeat(24), "B".repeat(146)),
        format!("xv1.0-{}-{}", "a".repeat(24), "b".repeat(146)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn authress_service_key_is_masked() {
    // An Authress service client key contains `.acc_`. The value is
    // not stored. A shorter segment stays as written.
    let token = format!("sc_abcde.abcd.acc_{}.{}", "c".repeat(10), "d".repeat(30));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, ".acc_"), "{token} -> {out}");
    assert!(hidden(&out, &"d".repeat(30)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let long_prefix = format!(
        "scauth_ABCDE.ABCD.acc-{}.{}",
        "e".repeat(32),
        "f".repeat(120)
    );
    let (vault, out, audit) = shield(&long_prefix);
    assert_eq!(audit.secret, 1, "{long_prefix} -> {out}");
    assert_eq!(out, "h1_secret", "{long_prefix} -> {out}");
    assert!(
        !vault.holds_surface(long_prefix.as_bytes()),
        "{long_prefix}"
    );

    let padded = format!(
        "authress_abcde.abcd.acc_{}.{}=",
        "g".repeat(10),
        "h".repeat(29)
    );
    let (vault, out, audit) = shield(&padded);
    assert_eq!(audit.secret, 1, "{padded} -> {out}");
    assert_eq!(out, "h1_secret", "{padded} -> {out}");
    assert!(hidden(&out, "="), "{padded} -> {out}");
    assert!(!vault.holds_surface(padded.as_bytes()), "{padded}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, ".acc_"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("sc_abcd.abcd.acc_{}.{}", "c".repeat(10), "d".repeat(30)),
        format!("sc_abcde.abcd.ACC_{}.{}", "c".repeat(10), "d".repeat(30)),
        format!("x{}", token),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn facebook_page_token_is_masked() {
    // A Facebook page token is `EAAC` or `EAAM` plus at least 100
    // letters or digits. The value is not stored. A shorter body
    // stays as written. A lowercase prefix stays as written. The
    // Square `EAAA` rule does not see this prefix.
    let body = format!("{}0123456789", "a".repeat(90));
    let token = format!("EAAC{body}");
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "0123456789"), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let mixed = format!("EAAM{}0123456789", "Ab".repeat(45));
    let (vault, out, audit) = shield(&mixed);
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "h1_secret", "{mixed} -> {out}");
    assert!(hidden(&out, "0123456789"), "{mixed} -> {out}");
    assert!(!vault.holds_surface(mixed.as_bytes()), "{mixed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "0123456789"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    let raw = format!(r#"{{"token":"{token}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.secret, 1, "{raw} -> {out}");
    assert_eq!(out, r#"{"token":"h1_secret"}"#, "{out}");
    assert!(hidden(&out, "0123456789"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("EAAC{}0123456789", "a".repeat(89)),
        format!("eaac{body}"),
        format!("EAAc{body}"),
        format!("EAAB{body}"),
        format!("xEAAC{body}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn harness_api_key_is_masked() {
    // A Harness key is `pat.` or `sat.`, 22 characters, a dot, 24
    // letters or digits, a dot, and 20 more. The value is not stored.
    // A shorter segment stays as written. This is not the Airtable
    // `pat` plus 14 characters.
    let token = format!(
        "pat.{}.{}.{}",
        "a".repeat(22),
        "b".repeat(24),
        "c".repeat(20)
    );
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "pat."), "{token} -> {out}");
    assert!(hidden(&out, &"c".repeat(20)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let sat = format!(
        "sat.{}.{}.{}",
        "d".repeat(22),
        "e".repeat(24),
        "f".repeat(20)
    );
    let (vault, out, audit) = shield(&sat);
    assert_eq!(audit.secret, 1, "{sat} -> {out}");
    assert_eq!(out, "h1_secret", "{sat} -> {out}");
    assert!(!vault.holds_surface(sat.as_bytes()), "{sat}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "pat."), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!(
            "pat.{}.{}.{}",
            "a".repeat(21),
            "b".repeat(24),
            "c".repeat(20)
        ),
        format!(
            "pat.{}.{}.{}",
            "a".repeat(22),
            "b".repeat(24),
            "c".repeat(19)
        ),
        format!(
            "PAT.{}.{}.{}",
            "a".repeat(22),
            "b".repeat(24),
            "c".repeat(20)
        ),
        format!(
            "xpat.{}.{}.{}",
            "a".repeat(22),
            "b".repeat(24),
            "c".repeat(20)
        ),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn sidekiq_sensitive_url_is_masked() {
    // A Sidekiq gem URL embeds 8 hex characters, a colon, and 8 more
    // on contribsys.com. The value is not stored. A shorter group
    // is not this secret. The password and host are still an address.
    let url = "https://0123abcd:fedcba98@gems.contribsys.com";
    let (vault, out, audit) = shield(url);
    assert_eq!(audit.secret, 1, "{url} -> {out}");
    assert_eq!(out, "h1_secret", "{url} -> {out}");
    assert!(hidden(&out, "0123abcd"), "{url} -> {out}");
    assert!(hidden(&out, "fedcba98"), "{url} -> {out}");
    assert!(hidden(&out, "gems.contribsys.com"), "{url} -> {out}");
    assert!(!vault.holds_surface(url.as_bytes()), "{url}");
    assert!(vault.restore_write(&out).is_err(), "{url}");

    let enterprise = "http://aaaaaaaa:bbbbbbbb@enterprise.contribsys.com/path";
    let (vault, out, audit) = shield(enterprise);
    assert_eq!(audit.secret, 1, "{enterprise} -> {out}");
    assert_eq!(out, "h1_secret/path", "{enterprise} -> {out}");
    assert!(hidden(&out, "aaaaaaaa"), "{out}");
    assert!(!vault.holds_surface(enterprise.as_bytes()), "{enterprise}");

    let sentence = format!("see {url}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "gems.contribsys.com"), "{out}");
    assert!(!vault.holds_surface(url.as_bytes()));

    // Eight uppercase hex characters are this secret. The miss is a
    // 7-character group. A wrong host is not this secret either.
    for bare in [
        "https://0123abc:fedcba98@gems.contribsys.com",
        "https://0123abcd:fedcba98@example.com",
        "https://0123ABC:FEDCBA98@gems.contribsys.com",
    ] {
        let (_vault, out, audit) = shield(bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert!(out.contains("h1_email_"), "{bare} -> {out}");
        assert!(!out.contains("h1_secret"), "{bare} -> {out}");
        assert!(hidden(&out, "fedcba98"), "{bare} -> {out}");
        assert!(hidden(&out, "FEDCBA98"), "{bare} -> {out}");
        assert!(!out.contains('@'), "{bare} -> {out}");
    }
}

#[test]
fn typeform_access_token_is_masked() {
    // A Typeform personal access token is `tfp_` plus 40 to 59
    // letters, digits, or underscores. The personal access token
    // page shows a 40-character body. A body of 59 characters is
    // the same token. The value is not stored. A shorter body and
    // a longer body stay as written. A sentence dot stays outside
    // the mark. An uppercase prefix stays as written.
    let documented = "tfp_943af478d3ff3d4d760020c11af102b79c440513";
    let (vault, out, audit) = shield(documented);
    assert_eq!(audit.secret, 1, "{documented} -> {out}");
    assert_eq!(out, "h1_secret", "{documented} -> {out}");
    assert!(
        hidden(&out, "943af478d3ff3d4d760020c11af102b79c440513"),
        "{out}"
    );
    assert!(!vault.holds_surface(documented.as_bytes()), "{documented}");
    assert!(vault.restore_write(&out).is_err(), "{documented}");

    let long = format!("tfp_{}", "a".repeat(59));
    let (vault, out, audit) = shield(&long);
    assert_eq!(audit.secret, 1, "{long} -> {out}");
    assert_eq!(out, "h1_secret", "{long} -> {out}");
    assert!(hidden(&out, "tfp_"), "{long} -> {out}");
    assert!(!vault.holds_surface(long.as_bytes()), "{long}");

    let mixed = format!("tfp_{}", "Ab9_".repeat(10));
    let (vault, out, audit) = shield(&mixed);
    assert_eq!(audit.secret, 1, "{mixed} -> {out}");
    assert_eq!(out, "h1_secret", "{mixed} -> {out}");
    assert!(!vault.holds_surface(mixed.as_bytes()), "{mixed}");

    let sentence = format!("see {documented}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "943af478"), "{out}");
    assert!(!vault.holds_surface(documented.as_bytes()));

    for bare in [
        format!("tfp_{}", "a".repeat(39)),
        format!("tfp_{}", "a".repeat(60)),
        format!("TFP_{}", "a".repeat(40)),
        format!("xtfp_{}", "a".repeat(40)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn gitlab_session_cookie_is_masked() {
    // A GitLab session cookie is `_gitlab_session=` plus 32
    // lowercase letters or digits. The value is not stored. A
    // shorter value stays as written.
    let value = "a".repeat(32);
    let cookie = format!("_gitlab_session={value}");
    let (vault, out, audit) = shield(&cookie);
    assert_eq!(audit.secret, 1, "{cookie} -> {out}");
    assert_eq!(out, "h1_secret", "{cookie} -> {out}");
    assert!(hidden(&out, "_gitlab_session="), "{cookie} -> {out}");
    assert!(hidden(&out, &value), "{cookie} -> {out}");
    assert!(!vault.holds_surface(cookie.as_bytes()), "{cookie}");
    assert!(vault.restore_write(&out).is_err(), "{cookie}");

    let sentence = format!("Cookie: {cookie}; Path=/");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "Cookie: h1_secret; Path=/", "{sentence} -> {out}");
    assert!(hidden(&out, &value), "{out}");
    assert!(!vault.holds_surface(cookie.as_bytes()));

    for bare in [
        format!("_gitlab_session={}", "a".repeat(31)),
        format!("_gitlab_session={}", "A".repeat(32)),
        format!("_gitlab_session={}", "a".repeat(33)),
        format!("x_gitlab_session={value}"),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn yandex_aqvn_api_key_is_masked() {
    // A Yandex API key is `AQVN` plus 35 to 38 characters. The value
    // is not stored. A shorter body stays as written.
    let token = format!("AQVN{}", "a".repeat(35));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "AQVN"), "{token} -> {out}");
    assert!(hidden(&out, &"a".repeat(35)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let wide = format!("AQVN{}", "b".repeat(38));
    let (vault, out, audit) = shield(&wide);
    assert_eq!(audit.secret, 1, "{wide} -> {out}");
    assert_eq!(out, "h1_secret", "{wide} -> {out}");
    assert!(!vault.holds_surface(wide.as_bytes()), "{wide}");

    let dashed = format!("AQVN{}-", "c".repeat(34));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, &"c".repeat(34)), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "AQVN"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("AQVN{}", "a".repeat(34)),
        format!("AQVN{}", "a".repeat(39)),
        format!("aqvn{}", "a".repeat(35)),
        format!("xAQVN{}", "a".repeat(35)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}

#[test]
fn yandex_aqw9_api_key_is_masked() {
    // A current Yandex API key is `AQW9` plus 35 to 38 characters.
    // The `AQVN` rule does not see this prefix. The value is not
    // stored. A shorter body stays as written.
    let token = format!("AQW9{}", "a".repeat(35));
    let (vault, out, audit) = shield(&token);
    assert_eq!(audit.secret, 1, "{token} -> {out}");
    assert_eq!(out, "h1_secret", "{token} -> {out}");
    assert!(hidden(&out, "AQW9"), "{token} -> {out}");
    assert!(hidden(&out, &"a".repeat(35)), "{token} -> {out}");
    assert!(!vault.holds_surface(token.as_bytes()), "{token}");
    assert!(vault.restore_write(&out).is_err(), "{token}");

    let wide = format!("AQW9{}", "b".repeat(38));
    let (vault, out, audit) = shield(&wide);
    assert_eq!(audit.secret, 1, "{wide} -> {out}");
    assert_eq!(out, "h1_secret", "{wide} -> {out}");
    assert!(!vault.holds_surface(wide.as_bytes()), "{wide}");

    let dashed = format!("AQW9{}-", "c".repeat(34));
    let (vault, out, audit) = shield(&dashed);
    assert_eq!(audit.secret, 1, "{dashed} -> {out}");
    assert_eq!(out, "h1_secret", "{dashed} -> {out}");
    assert!(hidden(&out, &"c".repeat(34)), "{dashed} -> {out}");
    assert!(!vault.holds_surface(dashed.as_bytes()), "{dashed}");

    let sentence = format!("see {token}.next");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.secret, 1, "{sentence} -> {out}");
    assert_eq!(out, "see h1_secret.next", "{sentence} -> {out}");
    assert!(hidden(&out, "AQW9"), "{out}");
    assert!(!vault.holds_surface(token.as_bytes()));

    for bare in [
        format!("AQW9{}", "a".repeat(34)),
        format!("AQW9{}", "a".repeat(39)),
        format!("aqw9{}", "a".repeat(35)),
        format!("xAQW9{}", "a".repeat(35)),
    ] {
        let (_vault, out, audit) = shield(&bare);
        assert_eq!(audit.secret, 0, "{bare} -> {out}");
        assert_eq!(out, bare, "{bare} -> {out}");
    }
}
