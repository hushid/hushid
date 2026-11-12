use hushid::{
    accept_non_text, format_token, parse_identifiers_config, restore_json_write,
    shield_json_strings, shield_text, shielding_active, ArgumentBuffer, Glossary, HeldStream,
    Judgment, Kind, Mode, Session, Sink, Vault,
};
use std::fs;
use std::path::Path;

#[test]
fn abbreviated_birth_month_is_shielded_and_a_bare_date_stays() {
    for text in [
        "DOB Jan 2, 1990",
        "born 2 Jan 1990",
        "DOB Sep 4, 1990",
        "né le 2 févr. 1990",
        "DOB 02-Jan-1990",
        "DOB 02/Jan/1990",
        "DOB Jan-02-1990",
        "DOB 1990-Jan-02",
        "born 2nd of January 1990",
    ] {
        let mut vault = Vault::new();
        let (out, audit) = shield_text(&mut vault, &Glossary::empty(), text).unwrap();
        assert_eq!(audit.birth, 1, "{text} -> {out}");
        assert!(!out.contains("1990"), "{text} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), text);
    }
    let mut vault = Vault::new();
    let bare = "Jan 2, 1990";
    let (out, audit) = shield_text(&mut vault, &Glossary::empty(), bare).unwrap();
    assert_eq!(audit.birth, 0);
    assert_eq!(out, bare);
}

#[test]
fn replay_returns_the_stored_projection_and_thinking_is_untouched() {
    let mut session = Session::new(Glossary::empty());
    let index = session.shield_message("a@b.co").unwrap();
    let stored = session.replay()[index].projection.clone();
    assert!(!stored.contains("a@b.co"));
    let _ = session.shield_message("other@b.co").unwrap();
    assert_eq!(session.replay()[0].projection, stored);

    let thinking = b"signed a@b.co h1_email_AAAAAAAAR";
    let vault_len = session.vault().len();
    session.store_thinking(0, thinking).unwrap();
    assert_eq!(
        session.replay()[0].thinking.as_deref(),
        Some(thinking.as_slice())
    );
    assert_eq!(session.replay()[0].projection, stored);
    assert_eq!(session.vault().len(), vault_len);
    assert!(session.store_thinking(9, b"nope").is_err());
}

#[test]
fn shield_message_keeps_an_audit_the_host_can_read() {
    let mut session = Session::new(Glossary::empty());
    session.shield_message("a@b.co").unwrap();
    assert_eq!(session.audits().len(), 1);
    assert_eq!(session.audits()[0].email, 1);
    assert_eq!(session.audits()[0].phone, 0);
    assert_eq!(session.audits()[0].secret, 0);
    session.shield_message("415-555-0134").unwrap();
    assert_eq!(session.audits().len(), 2);
    assert_eq!(session.audits()[0].email, 1);
    assert_eq!(session.audits()[0].phone, 0);
    assert_eq!(session.audits()[1].phone, 1);
    assert_eq!(session.audits()[1].email, 0);
}

#[test]
fn session_save_vault_writes_the_session_vault() {
    let dir = std::env::temp_dir().join(format!("hushid-session-vault-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    let path = dir.join("vault");
    let mut session = Session::new(Glossary::empty());
    session.shield_message("a@b.co").unwrap();
    let projection = session.replay()[0].projection.clone();
    session.save_vault(&path).unwrap();
    let loaded = Vault::load(&path).unwrap();
    assert_eq!(loaded.restore_write(&projection).unwrap(), "a@b.co");
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn json_strings_are_shielded_and_numbers_stay() {
    let input = r#"{"email":"a@b.co","n":4111111111111111,"note":"call 415-555-0134"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    assert!(out.contains("\"email\""), "{out}");
    assert!(out.contains("4111111111111111"), "{out}");
    assert!(!out.contains("a@b.co"), "{out}");
    assert_eq!(audit.email, 1);
    assert_eq!(audit.phone, 1);
    assert_eq!(audit.card, 0);
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains("a@b.co"), "{restored}");
    assert!(restored.contains("415-555-0134"), "{restored}");
    assert!(restored.contains("4111111111111111"), "{restored}");
}

#[test]
fn json_key_token_restores_and_a_mangled_key_fails() {
    let mut vault = Vault::new();
    let token = vault
        .issue_payload(Kind::Email, "AAAAAAAA", b"a@b.co")
        .unwrap();
    let input = format!(r#"{{"{token}":"ok"}}"#);
    let restored = restore_json_write(&vault, &input).unwrap();
    assert!(restored.contains("a@b.co"), "{restored}");
    assert!(restore_json_write(&vault, r#"{"h1_nope":"ok"}"#).is_err());
}

#[test]
fn json_number_sin_and_nested_document_round_trip() {
    let sin = luhn_sin("13069254");
    let input = format!(r#"{{"sin":{sin}}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &input).unwrap();
    assert_eq!(audit.sin, 1, "{out}");
    assert!(out.contains("h1_sin_"), "{out}");
    assert!(!out.contains(&sin), "{out}");
    let restored = restore_json_write(&vault, &out).unwrap();
    assert_eq!(restored, input);

    let bare = format!(r#"{{"n":{sin}}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &bare).unwrap();
    assert_eq!(audit.sin, 0, "{out}");
    assert_eq!(out, bare);

    let nested = r#"{"note":"{\"email\":\"a@b.co\"}"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), nested).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains("a@b.co"), "{out}");
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains("a@b.co"), "{restored}");
    assert!(!restored.contains("h1_"), "{restored}");
}

#[test]
fn deeply_nested_json_string_stays_plain_text() {
    // Far past the nest cap of 8. The probe must stop and the email
    // inside the string is still shielded as plain text.
    let mut inner = "\"a@b.co\"".to_string();
    for _ in 0..64 {
        inner = format!("[{inner}]");
    }
    let escaped = inner.replace('"', "\\\"");
    let input = format!(r#"{{"doc":"{escaped}"}}"#);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &input).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains("a@b.co"), "{out}");
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains("a@b.co"), "{restored}");
}

#[test]
fn json_nest_cap_keeps_a_unicode_email_plain_past_the_cap() {
    // The probe accepts containers at depth 0 through 7. A unicode
    // escape is an address only after that nested parse, so one more
    // array stays plain text instead of matching on the raw backslash.
    fn document(arrays: usize) -> String {
        let mut inner = "\"a\\u0040b.co\"".to_string();
        for _ in 0..arrays {
            inner = format!("[{inner}]");
        }
        let mut escaped = String::new();
        for ch in inner.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                _ => escaped.push(ch),
            }
        }
        format!(r#"{{"doc":"{escaped}"}}"#)
    }

    let within = document(8);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &within).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains("a@b.co"), "{out}");
    assert!(!out.contains("\\u0040"), "{out}");
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains("a@b.co"), "{restored}");

    let past = document(9);
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), &past).unwrap();
    assert_eq!(audit.email, 0, "{out}");
    assert_eq!(out, past);
    assert!(out.contains("\\u0040"), "{out}");
}

#[cfg(unix)]
#[test]
fn failed_vault_save_leaves_the_first_file() {
    use std::os::unix::fs::PermissionsExt;

    struct ResetMode(std::path::PathBuf);
    impl Drop for ResetMode {
        fn drop(&mut self) {
            let Ok(meta) = fs::metadata(&self.0) else {
                return;
            };
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&self.0, perms);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).unwrap();
    }

    let dir = std::env::temp_dir().join(format!("hushid-vault-ro-{}", std::process::id()));
    if dir.exists() {
        set_mode(&dir, 0o755);
        fs::remove_dir_all(&dir).unwrap();
    }
    fs::create_dir(&dir).unwrap();
    set_mode(&dir, 0o755);
    let _guard = ResetMode(dir.clone());

    let path = dir.join("vault");
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    vault.save(&path).unwrap();

    set_mode(&dir, 0o555);
    let mut second = Vault::new();
    shield_text(&mut second, &Glossary::empty(), "b@b.co").unwrap();
    assert!(second.save(&path).is_err());

    let loaded = Vault::load(&path).unwrap();
    assert_eq!(loaded.restore_write(&projection).unwrap(), "a@b.co");
    let name = path.file_name().unwrap().to_str().unwrap();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    assert!(!tmp.exists(), "{}", tmp.display());

    set_mode(&dir, 0o755);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn json_restore_keeps_an_email_that_starts_with_h1() {
    let input = r#"{"to":"h1_ops@example.com"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains("h1_ops@example.com"), "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), input);
    assert!(restore_json_write(&Vault::new(), r#"{"n":"h1_email_AAAAAAAAR"}"#).is_err());
    assert!(restore_json_write(&Vault::new(), r#"{"n":"h1_secret"}"#).is_err());
}

#[test]
fn json_string_beside_a_cue_is_shielded() {
    let sin = luhn_sin("13069254");
    let spaced = format!("{} {} {}", &sin[..3], &sin[3..6], &sin[6..9]);
    let shielded = [
        (format!(r#"{{"sin":"{sin}"}}"#), sin.clone(), "sin"),
        (format!(r#"{{"nas":"{spaced}"}}"#), spaced, "sin"),
        (format!(r#"{{"{sin}":"NAS"}}"#), sin.clone(), "sin"),
        (
            format!(r#"{{"label":"SIN","id":"{sin}"}}"#),
            sin.clone(),
            "sin",
        ),
        (format!(r#"{{"sin" : "{sin}"}}"#), sin.clone(), "sin"),
        (format!("{{\n  \"sin\": \"{sin}\"\n}}"), sin.clone(), "sin"),
        (
            format!(r#"{{"note":"{{\"sin\":\"{sin}\"}}"}}"#),
            sin.clone(),
            "sin",
        ),
        (
            format!(r#"{{"numéro d'assurance sociale":"{sin}"}}"#),
            sin.clone(),
            "sin",
        ),
        (
            format!(
                r#"{{"numéro d'assurance sociale":"{}","n":"{sin}"}}"#,
                ".".repeat(30)
            ),
            sin.clone(),
            "sin",
        ),
        (
            r#"{"card":"4111111111111111"}"#.to_string(),
            "4111111111111111".to_string(),
            "card",
        ),
        (
            r#"{"visa":"4111111111111111"}"#.to_string(),
            "4111111111111111".to_string(),
            "card",
        ),
    ];
    for (input, surface, kind) in shielded {
        assert_json_surface_shielded(&input, &surface, kind);
    }

    // Three characters (`":"`) sit between the key and the digits.
    // 37 more keep the cue inside the 40-character window. 38 push it out.
    let near = format!(r#"{{"sin":"{}{sin}"}}"#, ".".repeat(37));
    assert_json_surface_shielded(&near, &sin, "sin");
    let far = format!(r#"{{"sin":"{}{sin}"}}"#, ".".repeat(38));
    assert_json_left_as_written(&far);
    let french_far = format!(
        r#"{{"numéro d'assurance sociale":"{}","n":"{sin}"}}"#,
        ".".repeat(31)
    );
    assert_json_left_as_written(&french_far);

    for bare in [
        format!(r#"{{"n":"{sin}"}}"#),
        r#"{"n":"4111111111111111"}"#.to_string(),
        r#"{"phone":"4155550134"}"#.to_string(),
    ] {
        assert_json_left_as_written(&bare);
    }
}

#[test]
fn json_cue_beside_a_nested_document_reaches_the_value() {
    let sin = luhn_sin("13069254");
    // Ten characters (`":"{"id":"`) sit between the cue and the digits.
    // 30 more stay inside the 40-character window. 31 push the cue out.
    let shielded = [
        (
            format!(r#"{{"sin":"{{\"id\":{sin}}}"}}"#),
            sin.clone(),
            "sin",
        ),
        (
            format!(r#"{{"sin":"{{\"id\":\"{sin}\"}}"}}"#),
            sin.clone(),
            "sin",
        ),
        (format!(r#"{{"sin":"[{sin}]"}}"#), sin.clone(), "sin"),
        (
            format!(r#"{{"n":"{{\"id\":\"{sin}\"}}","k":"SIN"}}"#),
            sin.clone(),
            "sin",
        ),
        (
            format!(r#"{{"n":"{{\"id\":{sin}}}","k":"SIN"}}"#),
            sin.clone(),
            "sin",
        ),
        (
            format!(r#"{{"sin":"{{\"id\":\"{}{sin}\"}}"}}"#, ".".repeat(30)),
            sin.clone(),
            "sin",
        ),
        (
            r#"{"visa":"{\"pan\":\"4111111111111111\"}"}"#.to_string(),
            "4111111111111111".to_string(),
            "card",
        ),
        (
            r#"{"card":"{\"pan\":4111111111111111}"}"#.to_string(),
            "4111111111111111".to_string(),
            "card",
        ),
    ];
    for (input, surface, kind) in shielded {
        assert_json_surface_shielded(&input, &surface, kind);
    }

    let far = format!(r#"{{"sin":"{{\"id\":\"{}{sin}\"}}"}}"#, ".".repeat(31));
    assert_json_left_as_written(&far);
    let bare = format!(r#"{{"note":"{{\"id\":{sin}}}"}}"#);
    assert_json_left_as_written(&bare);
    let bare_card = r#"{"note":"{\"pan\":\"4111111111111111\"}"}"#;
    assert_json_left_as_written(bare_card);
}

fn assert_json_left_as_written(input: &str) {
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    assert_eq!(audit.sin, 0, "{input} -> {out}");
    assert_eq!(audit.card, 0, "{input} -> {out}");
    assert_eq!(audit.phone, 0, "{input} -> {out}");
    assert_eq!(out, input);
}

fn assert_json_surface_shielded(input: &str, surface: &str, kind: &str) {
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    let count = match kind {
        "sin" => audit.sin,
        "card" => audit.card,
        other => panic!("unexpected kind {other}"),
    };
    assert_eq!(count, 1, "{input} -> {out}");
    assert!(!out.contains(surface), "{input} -> {out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), input);
}

fn luhn_sin(body: &str) -> String {
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
    format!("{body}{}", char::from_digit(digit, 10).unwrap())
}

#[test]
fn stream_emits_a_long_chunk_and_holds_only_the_tail() {
    let mut text = "a".repeat(20_000);
    text.push('h');
    let mut stream = HeldStream::new();
    let started = std::time::Instant::now();
    let out = stream.push(&text);
    assert!(
        started.elapsed().as_millis() < 500,
        "long chunk took {:?}",
        started.elapsed()
    );
    assert_eq!(out, "a".repeat(20_000));
    assert_eq!(stream.finish(), "h");
}

#[test]
fn stream_holds_a_split_token_until_it_is_complete() {
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    let token = projection.clone();
    let mut stream = HeldStream::new();
    let split = token.len() / 2;
    let first = stream.push_restore(&token[..split], &vault);
    assert!(!first.contains("a@b.co"), "{first}");
    let second = stream.push_restore(&token[split..], &vault);
    let done = stream.finish_restore(&vault);
    assert_eq!(format!("{first}{second}{done}"), "a@b.co");
}

#[test]
fn stream_restores_a_token_whose_tail_looks_like_h1() {
    for suffix in ["H", "H1"] {
        let mut vault = Vault::new();
        let token = email_token_ending_with(&mut vault, suffix);
        let mut stream = HeldStream::new();
        let whole = stream.push_restore(&token, &vault);
        let done = stream.finish_restore(&vault);
        assert_eq!(
            format!("{whole}{done}"),
            "a@b.co",
            "{token} -> {whole}{done}"
        );

        let mut stream = HeldStream::new();
        let cut = token.len() - suffix.len();
        let first = stream.push_restore(&token[..cut], &vault);
        assert!(!first.contains('@'), "{token} -> {first}");
        let second = stream.push_restore(&token[cut..], &vault);
        let done = stream.finish_restore(&vault);
        assert_eq!(
            format!("{first}{second}{done}"),
            "a@b.co",
            "{token} -> {first}{second}{done}"
        );
    }
}

fn email_token_ending_with(vault: &mut Vault, suffix: &str) -> String {
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for &left in alphabet {
        for &right in alphabet {
            let payload = format!("AAAAAA{}{}", left as char, right as char);
            let token = format_token(Kind::Email, &payload).unwrap();
            if token.ends_with(suffix) {
                let issued = vault
                    .issue_payload(Kind::Email, &payload, b"a@b.co")
                    .unwrap();
                assert_eq!(issued, token);
                return issued;
            }
        }
    }
    panic!("no email token ends with {suffix}");
}

#[test]
fn argument_deltas_are_judged_only_when_complete() {
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    let mut args = ArgumentBuffer::new();
    args.push("echo ");
    assert!(matches!(
        args.judge("run_command", false, &vault),
        Judgment::Run { sink: Sink::Shell }
    ));
    args.push(&projection);
    assert!(matches!(
        args.judge("run_command", false, &vault),
        Judgment::Refuse { sink: Sink::Shell }
    ));
}

#[test]
fn config_accepts_off_and_cloud_only() {
    let config = parse_identifiers_config(
        "[identifiers]\nmode = \"cloud\"\nglossary = \"identifiers.txt\"\n",
    )
    .unwrap();
    assert_eq!(config.mode, Mode::Cloud);
    assert_eq!(config.glossary.unwrap().as_os_str(), "identifiers.txt");
    assert!(config.ner.is_none());
    let with_model =
        parse_identifiers_config("[identifiers]\nmode = \"cloud\"\nner = \"models/person.onnx\"\n")
            .unwrap();
    assert_eq!(with_model.ner.unwrap().as_os_str(), "models/person.onnx");
    assert!(shielding_active(Mode::Cloud, false));
    assert!(!shielding_active(Mode::Cloud, true));
    assert!(!shielding_active(Mode::Off, false));
    assert!(parse_identifiers_config("[identifiers]\nmode = \"private\"\n").is_err());
    assert!(parse_identifiers_config("[identifiers]\nmode = \"law25\"\n").is_err());
    assert!(accept_non_text(Mode::Cloud).is_err());
    accept_non_text(Mode::Off).expect("off mode accepts non-text");
}

#[test]
fn glossary_file_round_trip() {
    let path = std::env::temp_dir().join(format!("hushid-glossary-{}", std::process::id()));
    fs::write(&path, "# local\nMarie\n\nJean Pierre\n").unwrap();
    let glossary = Glossary::load(&path).unwrap();
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, "Marie and Jean Pierre").unwrap();
    assert_eq!(audit.glossary, 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), "Marie and Jean Pierre");
    let _ = fs::remove_file(&path);
}

#[test]
fn published_name_glossary_shields_listed_names() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("glossary/popular-names.txt");
    let glossary = Glossary::load(&path).expect("published glossary");
    let sample = "Olivia met Noah Smith and Florence";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, sample).unwrap();
    assert_eq!(audit.glossary, 4, "{out}");
    assert!(!out.contains("Olivia"), "{out}");
    assert!(!out.contains("Smith"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sample);

    let ordinary = "The clinic is open";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, ordinary).unwrap();
    assert_eq!(audit.glossary, 0, "{out}");
    assert_eq!(out, ordinary);
}

#[test]
fn canada_top_100_names_are_shielded() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("glossary/popular-names.txt");
    let glossary = Glossary::load(&path).expect("published glossary");
    let sample = "Muhammad met Violet and Isla";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, sample).unwrap();
    assert_eq!(audit.glossary, 3, "{out}");
    assert!(!out.contains("Muhammad"), "{out}");
    assert!(!out.contains("Violet"), "{out}");
    assert!(!out.contains("Isla"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sample);
}

#[test]
fn glossary_matches_a_name_with_every_accent_left_off() {
    let glossary = Glossary::from_terms(["Élodie", "Éloi", "Côté", "Jean-Léon"]);
    let typed = "Elodie met Eloi, Cote et Jean-Leon";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, typed).unwrap();
    assert_eq!(audit.glossary, 4, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), typed);

    let exact = "Élodie";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, exact).unwrap();
    assert_eq!(audit.glossary, 1, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), exact);

    let decomposed = "E\u{0301}lodie";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, decomposed).unwrap();
    assert_eq!(audit.glossary, 1, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), decomposed);

    for unchanged in ["Èlodie", "elodie", "Éloï", "Côte", "Océane"] {
        let mut vault = Vault::new();
        let (out, audit) = shield_text(&mut vault, &glossary, unchanged).unwrap();
        assert_eq!(audit.glossary, 0, "{unchanged} -> {out}");
        assert_eq!(out, unchanged);
    }
}

#[test]
fn published_name_glossary_shields_accented_quebec_names() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("glossary/popular-names.txt");
    let glossary = Glossary::load(&path).expect("published glossary");
    let sample = "Léo Édouard Théo Béatrice Théodore Émile Raphaël Félix Léa Zoé Éloïse Clémence Léonie Chloé Ophélie Adèle Éléonore Raphaëlle Éloi Léonard Léon Clément";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, sample).unwrap();
    assert_eq!(audit.glossary, 22, "{out}");
    assert!(!out.contains("Édouard"), "{out}");
    assert!(!out.contains("Béatrice"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sample);

    let bank = "Edouard a vu Theo et Beatrice";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, bank).unwrap();
    assert_eq!(audit.glossary, 3, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), bank);

    let other_accent = "Maël, Éloï, Mathéo et Océane restent";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, other_accent).unwrap();
    assert_eq!(audit.glossary, 0, "{out}");
    assert_eq!(out, other_accent);
}

#[test]
fn vault_file_is_mode_0600_and_round_trips() {
    let path = std::env::temp_dir().join(format!("hushid-vault-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    vault.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let loaded = Vault::load(&path).unwrap();
    assert_eq!(loaded.restore_write(&projection).unwrap(), "a@b.co");
    let name = path.file_name().unwrap().to_str().unwrap();
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    assert!(!tmp.exists(), "{}", tmp.display());
    let _ = fs::remove_file(&path);

    fs::write(&path, "hushid-vault 1").unwrap();
    assert!(matches!(
        Vault::load(&path),
        Err(hushid::VaultError::Corrupt)
    ));
    let _ = fs::remove_file(&path);
}

#[test]
fn quebec_surnames_are_shielded() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("glossary/popular-names.txt");
    let glossary = Glossary::load(&path).expect("published glossary");
    let sample = "Tremblay a vu Côté, Gagnon et St-Pierre";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, sample).unwrap();
    assert_eq!(audit.glossary, 4, "{out}");
    assert!(!out.contains("Tremblay"), "{out}");
    assert!(!out.contains("Côté"), "{out}");
    assert!(!out.contains("St-Pierre"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sample);

    let plain = "Cote a vu Belanger";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, plain).unwrap();
    assert_eq!(audit.glossary, 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), plain);
}

#[test]
fn popular_names_are_opt_in() {
    let glossary = Glossary::popular_names();
    let sample = "Olivia met Léo";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, sample).unwrap();
    assert_eq!(audit.glossary, 2, "{out}");
    assert!(!out.contains("Olivia"), "{out}");
    assert!(!out.contains("Léo"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sample);

    let ordinary = "The clinic is open";
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, ordinary).unwrap();
    assert_eq!(audit.glossary, 0, "{out}");
    assert_eq!(out, ordinary);

    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &Glossary::empty(), "Olivia met Léo").unwrap();
    assert_eq!(audit.glossary, 0, "{out}");
    assert_eq!(out, "Olivia met Léo");
}

#[test]
fn quiet_surfaces_stay_out_of_the_tree() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("README.md").exists());
    assert!(!root.join(".github/FUNDING.yml").exists());
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("publish = false"));
    let lower = manifest.to_ascii_lowercase();
    assert!(!lower.contains("keywords"));
    for entry in fs::read_dir(root.join("src")).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap().to_ascii_lowercase();
        assert!(!text.contains("anonym"), "{}", path.display());
        assert!(!text.contains("law 25"), "{}", path.display());
        assert!(!text.contains("law25"), "{}", path.display());
        assert!(!text.contains("private mode"), "{}", path.display());
        assert!(!text.contains("gaze"), "{}", path.display());
    }
}
