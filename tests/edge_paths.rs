use hushid::{
    accept_non_text, parse_identifiers_config, restore_json_write, shield_json_strings,
    shield_text_with, ArgumentBuffer, ConfigError, Glossary, HeldStream, JsonError, Kind, Mode,
    NonTextRefused, Operator, RestoreError, SealError, Session, TokenError, Vault, VaultError,
};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("hushid-{name}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write(dir: &Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn config_errors_name_the_line_and_quotes_keep_a_hash() {
    let config = parse_identifiers_config(
        "[identifiers]\nmode = off # local\nglossary = \"a#b\"\nner = ''\n",
    )
    .unwrap();
    assert_eq!(config.mode, Mode::Off);
    assert_eq!(config.glossary.unwrap().to_string_lossy(), "a#b");
    assert!(config.ner.is_none());
    let quoted = parse_identifiers_config("[identifiers]\nglossary = 'names.txt'\n").unwrap();
    assert_eq!(quoted.glossary.unwrap().to_string_lossy(), "names.txt");
    assert!(!hushid::shielding_active(Mode::Off, false));
    assert!(hushid::shielding_active(Mode::Cloud, false));
    assert!(!hushid::shielding_active(Mode::Cloud, true));
    assert!(hushid::non_text_allowed(Mode::Off));
    assert!(!hushid::non_text_allowed(Mode::Cloud));
    assert_eq!(
        accept_non_text(Mode::Cloud).unwrap_err().to_string(),
        "non-text input is refused while mode is cloud"
    );
    assert!(accept_non_text(Mode::Off).is_ok());
    assert_eq!(
        NonTextRefused.to_string(),
        "non-text input is refused while mode is cloud"
    );

    let syntax = parse_identifiers_config("mode = cloud").unwrap_err();
    assert_eq!(syntax.to_string(), "invalid identifiers config on line 1");
    assert!(matches!(syntax, ConfigError::Syntax { line: 1 }));
    let open = parse_identifiers_config("[identifiers").unwrap_err();
    assert!(matches!(open, ConfigError::Syntax { .. }));
    let table = parse_identifiers_config("[other]\n").unwrap_err();
    assert_eq!(table.to_string(), "unknown table on line 1");
    let mode = parse_identifiers_config("[identifiers]\nmode = sideways\n").unwrap_err();
    assert_eq!(mode.to_string(), "mode on line 2 must be off or cloud");
    let key = parse_identifiers_config("[identifiers]\nnope = 1\n").unwrap_err();
    assert_eq!(key.to_string(), "unknown key on line 2");
    assert!(parse_identifiers_config("[identifiers]\nmode = has space\n").is_err());
    assert!(parse_identifiers_config("[identifiers]\n= cloud\n").is_err());
    assert!(parse_identifiers_config("[identifiers]\nmode =\n").is_err());
}

#[test]
fn json_escapes_round_trip_and_a_long_prefix_stays_a_prefix() {
    let mut vault = Vault::new();
    let input = r#"{"note":"line\n\r\t\b\f\/\"\\end"}"#;
    let (out, _) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains("\\n"), "{restored}");
    assert!(restored.contains("\\u0008"), "{restored}");
    assert!(restored.contains("\\u000c"), "{restored}");
    assert!(restored.contains('/'), "{restored}");
    let controls = r#"{"note":"\u0001"}"#;
    let (out, _) = shield_json_strings(&mut vault, &Glossary::empty(), controls).unwrap();
    assert!(out.contains("\\u0001"), "{out}");
    let pair = r#"{"note":"\uD83D\uDE00"}"#;
    let (out, _) = shield_json_strings(&mut vault, &Glossary::empty(), pair).unwrap();
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains('😀'), "{restored}");
    assert!(shield_json_strings(&mut vault, &Glossary::empty(), r#"{"note":"\uD800"}"#).is_err());
    assert!(
        shield_json_strings(&mut vault, &Glossary::empty(), r#"{"note":"\uD800\uD800"}"#).is_err()
    );
    assert!(shield_json_strings(&mut vault, &Glossary::empty(), r#"{"note":"\q"}"#).is_err());
    assert!(shield_json_strings(&mut vault, &Glossary::empty(), r#"{"note":"\u12"}"#).is_err());
    assert!(
        shield_json_strings(&mut vault, &Glossary::empty(), "{\"note\":\"\\\u{0001}\"}").is_err()
    );

    let pad = " ".repeat(200);
    let wide = format!("{pad}\"ada@example.com\"");
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &wide).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    let exact = format!("{}\"a\"", " ".repeat(95));
    assert!(shield_json_strings(&mut vault, &Glossary::empty(), &exact).is_ok());

    assert_eq!(
        JsonError::Syntax { at: 4 }.to_string(),
        "json string syntax at byte 4"
    );
    assert_eq!(
        JsonError::Token(TokenError::Payload).to_string(),
        "token payload must be 8 Crockford base32 symbols"
    );
    let restore = JsonError::Restore(RestoreError::Unresolved { at: 1 });
    assert!(restore.to_string().contains("unresolved"));
}

#[test]
fn masks_cover_each_kind_and_a_glossary_word_that_is_already_stars() {
    let cases = [
        ("ada@example.com", "***@***", Kind::Email),
        ("415-555-0134", "***-***-****", Kind::Phone),
        ("4111 1111 1111 1111", "**** **** **** ****", Kind::Card),
        ("SIN 130 692 544", "*** *** ***", Kind::Sin),
        ("BOUF 9451 1419", "**** **** ****", Kind::Ramq),
        ("postal code H2X 1Y4", "*** ***", Kind::Postal),
        ("88 Main Street", "***", Kind::Address),
        ("DOB Jan 2, 1990", "*** *** ***", Kind::Birth),
    ];
    for (text, mask, kind) in cases {
        let mut vault = Vault::new();
        let (out, _) =
            shield_text_with(&mut vault, &Glossary::empty(), text, Operator::Mask).unwrap();
        assert!(out.contains(mask), "{kind:?} {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), out, "{text}");
    }
    let mut vault = Vault::new();
    let glossary = Glossary::from_terms(["Nadine"]);
    let (out, audit) =
        shield_text_with(&mut vault, &glossary, "See Nadine.", Operator::Mask).unwrap();
    assert_eq!(audit.glossary, 1, "{out}");
    assert!(out.contains("***"), "{out}");
    assert!(!out.contains("Nadine"), "{out}");
}

#[test]
fn vault_files_report_a_missing_a_torn_and_a_bad_record() {
    let dir = scratch("vault");
    assert_eq!(
        Vault::load(dir.join("missing").as_path())
            .unwrap_err()
            .to_string(),
        "vault file is missing"
    );
    let io_err = Vault::load(&dir).unwrap_err();
    assert!(
        io_err.to_string().starts_with("vault file error:"),
        "{io_err}"
    );
    assert!(matches!(io_err, VaultError::Io(_)));
    assert_eq!(
        Vault::load(&write(&dir, "empty", ""))
            .unwrap_err()
            .to_string(),
        "vault file is corrupt"
    );
    assert!(Vault::load(&write(&dir, "nonewline", "hushid-vault 1")).is_err());
    assert!(Vault::load(&write(&dir, "header", "nope\n")).is_err());

    let mut vault = Vault::new();
    let token = vault.issue(Kind::Email, b"a@b.co").unwrap();
    let path = dir.join("good");
    vault.save(&path).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert!(Vault::load(&path).unwrap().restore_write(&token).unwrap() == "a@b.co");
    let blank = text.replace("hushid-vault 1\n", "hushid-vault 1\n\n");
    let loaded_blank = Vault::load(&write(&dir, "blank2", &blank)).unwrap();
    assert_eq!(loaded_blank.restore_write(&token).unwrap(), "a@b.co");

    let mut upper_lines = text.lines().map(str::to_string).collect::<Vec<_>>();
    let mut upper_parts = upper_lines[1].splitn(3, ' ');
    let upper_token = upper_parts.next().unwrap().to_string();
    let upper_hex = upper_parts.next().unwrap().to_ascii_uppercase();
    let upper_rest = upper_parts.next().unwrap_or("");
    upper_lines[1] = if upper_rest.is_empty() {
        format!("{upper_token} {upper_hex}")
    } else {
        format!("{upper_token} {upper_hex} {upper_rest}")
    };
    let upper = format!("{}\n", upper_lines.join("\n"));
    assert_eq!(
        Vault::load(&write(&dir, "upper", &upper))
            .unwrap()
            .restore_write(&token)
            .unwrap(),
        "a@b.co"
    );
    let mut lines = text.lines().map(str::to_string).collect::<Vec<_>>();
    let record = lines[1].clone();
    let mut parts = record.split(' ');
    let token_text = parts.next().unwrap();
    let hex = parts.next().unwrap().to_string();
    lines[1] = format!("{token_text} zz");
    assert!(Vault::load(&write(&dir, "hex", &format!("{}\n", lines.join("\n")))).is_err());
    lines[1] = format!("{token_text} {hex} z");
    assert!(Vault::load(&write(&dir, "flag", &format!("{}\n", lines.join("\n")))).is_err());

    let phone = "415-555-0134";
    let mut digits = Vault::new();
    shield_text_with(&mut digits, &Glossary::empty(), phone, Operator::Digits).unwrap();
    let digit_path = dir.join("digits");
    digits.save(&digit_path).unwrap();
    let digit_text = fs::read_to_string(&digit_path).unwrap();
    assert!(digit_text.contains(" d "), "{digit_text}");
    let doubled = digit_text.replacen(" d ", " d 61 d 61", 1);
    assert!(Vault::load(&write(&dir, "doubled", &doubled)).is_err());
    let empty_stand_in = digit_text.replacen(" d ", " d  ", 1);
    assert!(Vault::load(&write(&dir, "empty-stand-in", &empty_stand_in)).is_err());

    let sin = (0..10)
        .map(|digit| format!("13069254{digit}"))
        .find(|sin| {
            let input = format!(r#"{{"sin":{sin}}}"#);
            let mut vault = Vault::new();
            shield_json_strings(&mut vault, &Glossary::empty(), &input)
                .unwrap()
                .1
                .sin
                == 1
        })
        .unwrap();
    let mut numbers = Vault::new();
    shield_json_strings(
        &mut numbers,
        &Glossary::empty(),
        &format!(r#"{{"sin":{sin}}}"#),
    )
    .unwrap();
    let number_path = dir.join("number");
    numbers.save(&number_path).unwrap();
    assert!(fs::read_to_string(&number_path).unwrap().contains(" n"));

    let empty = Vault::default();
    assert!(empty.is_empty());
    assert!(format!("{empty:?}").contains("entries"));
    assert_eq!(
        RestoreError::SecretMark { at: 0 }.to_string(),
        "secret mark remains at byte 0"
    );
    assert_eq!(empty.restore_display("h1_nope"), "h1_nope");
    assert!(empty.restore_write("h1_secret").is_err());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn session_debug_names_the_thinking_length_and_a_missing_index() {
    let mut session = Session::new(Glossary::empty());
    let err = session.store_thinking(0, b"x").unwrap_err();
    assert_eq!(err.to_string(), "message index is out of range");
    let index = session.shield_message("hello").unwrap();
    session.store_thinking(index, b"abc").unwrap();
    let message = format!("{:?}", session.replay()[index]);
    assert!(message.contains("thinking_len"), "{message}");
    assert!(message.contains('3'), "{message}");
    let rendered = format!("{session:?}");
    assert!(rendered.contains("messages"), "{rendered}");
    for kind in [
        Kind::Email,
        Kind::Phone,
        Kind::Card,
        Kind::Sin,
        Kind::Ramq,
        Kind::Postal,
        Kind::Address,
        Kind::Birth,
        Kind::Glossary,
    ] {
        assert!(!kind.to_string().is_empty());
    }
    assert_eq!(
        TokenError::Entropy.to_string(),
        "operating system random source failed"
    );
    assert_eq!(TokenError::Digits.to_string(), "digit stand-in collided");
    assert_eq!(
        TokenError::Surrogate.to_string(),
        "surrogate stand-in collided"
    );
    assert_eq!(
        SealError::Transcript.to_string(),
        "sealed transcript is corrupt"
    );
    let mut held = HeldStream::new();
    assert!(held.push("hello").contains("hello"));
    let mut args = ArgumentBuffer::new();
    args.push("ada@example.com");
    assert_eq!(args.as_str(), "ada@example.com");
}

#[test]
fn json_numbers_literals_and_a_reloaded_number_round_trip() {
    let config = parse_identifiers_config("[identifiers]\n\nglossary = \"\"\n").unwrap();
    assert!(config.glossary.is_none());
    let nested = r#"{"note":"{\"ok\":true,\"no\":false,\"z\":null,\"n\":1.5,\"e\":1e2}"}"#;
    let mut vault = Vault::new();
    let (out, _) = shield_json_strings(&mut vault, &Glossary::empty(), nested).unwrap();
    assert_eq!(restore_json_write(&vault, &out).unwrap(), nested);
    assert!(
        shield_json_strings(&mut vault, &Glossary::empty(), r#"{"note":"{\"bad\":1.}"}"#).is_ok()
    );
    assert!(
        shield_json_strings(&mut vault, &Glossary::empty(), r#"{"note":"{\"bad\":1e}"}"#).is_ok()
    );
    assert!(restore_json_write(&Vault::new(), r#"{"a":"h1_secret"}"#).is_err());

    let sin = (0..10)
        .map(|digit| format!("13069254{digit}"))
        .find(|sin| {
            let input = format!(r#"{{"sin":{sin}}}"#);
            let mut vault = Vault::new();
            shield_json_strings(&mut vault, &Glossary::empty(), &input)
                .unwrap()
                .1
                .sin
                == 1
        })
        .unwrap();
    let input = format!(r#"{{"sin":{sin}}}"#);
    let mut numbers = Vault::new();
    let (shielded, _) = shield_json_strings(&mut numbers, &Glossary::empty(), &input).unwrap();
    let dir = scratch("reload");
    let path = dir.join("number");
    numbers.save(&path).unwrap();
    let loaded = Vault::load(&path).unwrap();
    assert_eq!(restore_json_write(&loaded, &shielded).unwrap(), input);

    let mut vault = Vault::new();
    let token = vault.issue(Kind::Email, b"a@b.co").unwrap();
    let good = dir.join("good");
    vault.save(&good).unwrap();
    let text = fs::read_to_string(&good).unwrap();
    let record = text.lines().nth(1).unwrap().to_string();
    let (token_text, hex) = record.split_once(' ').unwrap();
    let mut lines = text.lines().map(str::to_string).collect::<Vec<_>>();
    lines[1] = format!("{token_text} a");
    assert!(Vault::load(&write(&dir, "odd", &format!("{}\n", lines.join("\n")))).is_err());
    let mut broken = token.clone();
    let last = broken.pop().unwrap();
    let replacement = if last == '2' { '3' } else { '2' };
    broken.push(replacement);
    lines[1] = format!("{broken} {hex}");
    assert!(Vault::load(&write(&dir, "check", &format!("{}\n", lines.join("\n")))).is_err());

    let dest = dir.join("not-a-file");
    fs::create_dir(&dest).unwrap();
    assert!(vault.save(&dest).is_err());
    let _ = fs::remove_dir_all(&dir);
    let _ = token;
}
