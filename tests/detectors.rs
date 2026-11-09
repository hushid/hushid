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

fn valid_sin() -> String {
    let body = "13069254";
    let mut sin = body.to_string();
    sin.push(luhn_check_digit(body));
    sin
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
    assert!(!out.contains("jean"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let raw = format!(r#"{{"to":"jean{en}luc@example.com"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &raw).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains('@'), "{out}");
    assert!(!out.contains("jean"), "{out}");
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
    assert!(!out.contains("7946"), "{out}");
    assert!(!out.contains('('), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);

    let pair = "call +44 (20) 7946 0958 or +33 (0)1 23 45 67 89 today";
    let (vault, out, audit) = shield(pair);
    assert_eq!(audit.phone, 2, "{pair} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(out.contains(" or "), "{out}");
    assert!(!out.contains('('), "{out}");
    assert!(!out.contains("7946"), "{out}");
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
    assert!(!out.contains("7946"), "{raw} -> {out}");
    assert!(!out.contains('('), "{raw} -> {out}");
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
    assert!(!out.contains("416"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sentence);
    let slashed = "call 416/555-0123 today";
    let (vault, out, audit) = shield(slashed);
    assert_eq!(audit.phone, 1, "{slashed} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains("416"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), slashed);
    let unbroken = "call 416\u{2011}555\u{2011}0123 today";
    let (vault, out, audit) = shield(unbroken);
    assert_eq!(audit.phone, 1, "{unbroken} -> {out}");
    assert!(out.starts_with("call h1_phone_"), "{out}");
    assert!(out.ends_with(" today"), "{out}");
    assert!(!out.contains("416"), "{out}");
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
    assert!(!out.contains("3782"), "{out}");
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
    assert!(!out.contains("3056"), "{out}");
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
    assert!(!out.contains("4111"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued_dotted);
    let dotted_sentence = "pay visa 4111.1111.1111.1111 today.";
    let (vault, out, audit) = shield(dotted_sentence);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("pay visa h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(!out.contains("4111"), "{out}");
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
    assert!(!out.contains("4111"), "{raw} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), raw);
    let bare_dotted = r#"{"n":"4111.1111.1111.1111"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), bare_dotted).unwrap();
    assert_eq!(audit.card, 1, "{bare_dotted} -> {out}");
    assert!(!out.contains("4111"), "{bare_dotted} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), bare_dotted);
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
    assert!(!out.contains("1100006"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let sentence = format!("pay {cued} today.");
    let (vault, out, audit) = shield(&sentence);
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.starts_with("pay visa h1_card_"), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert!(!out.contains("1100006"), "{out}");
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
    assert!(!out.contains("416"), "{out}");
    assert!(!out.contains("0123"), "{out}");
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
    assert!(!out.contains("4111"), "{raw} -> {out}");
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
    assert!(!out.contains("416"), "{out}");
    assert!(!out.contains("0123"), "{out}");
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
    assert!(!out.contains("4111"), "{out}");
    assert!(!out.contains(en), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), cued);

    let sin = valid_sin();
    let dashed = format!("{}{figure}{}{figure}{}", &sin[..3], &sin[3..6], &sin[6..]);
    let cued_sin = format!("SIN {dashed}");
    let (vault, out, audit) = shield(&cued_sin);
    assert_eq!(audit.sin, 1, "{cued_sin} -> {out}");
    assert_eq!(audit.phone, 0, "{cued_sin} -> {out}");
    assert!(out.starts_with("SIN h1_sin_"), "{out}");
    assert!(!out.contains(&sin), "{out}");
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
    assert!(!out.contains("416"), "{raw} -> {out}");
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
