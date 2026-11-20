use hushid::{
    judge, restore_json_reply, restore_json_write, shield_json_strings, shield_json_strings_with,
    shield_text, shield_text_with, Glossary, JsonError, Judgment, Operator, RestoreError, Session,
    Vault,
};

fn email_tokens(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("h1_email_") {
        let token = &rest[start..];
        let end = token
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(token.len());
        found.push(&token[..end]);
        rest = &token[end..];
    }
    found
}

#[test]
fn forget_shares_one_email_token_and_stores_nothing() {
    let text = "Write to ada@example.com and ada@example.com today.";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), text, Operator::Forget).unwrap();
    assert_eq!(audit.email, 2, "{out}");
    let tokens = email_tokens(&out);
    assert_eq!(tokens.len(), 2, "{out}");
    assert_eq!(tokens[0], tokens[1], "{out}");
    assert!(tokens[0].starts_with("h1_email_"), "{out}");
    assert!(!out.contains("ada@example.com"), "{out}");
    assert!(vault.is_empty());
    assert!(matches!(
        vault.restore_write(&out),
        Err(RestoreError::Unresolved { .. })
    ));

    let mut kept = Vault::new();
    let (tokened, _) = shield_text(&mut kept, &Glossary::empty(), "ada@example.com").unwrap();
    assert_eq!(kept.restore_write(&tokened).unwrap(), "ada@example.com");
}

#[test]
fn forget_mints_a_new_token_on_the_next_call() {
    let address = "ada@example.com";
    let mut vault = Vault::new();
    let (first, _) =
        shield_text_with(&mut vault, &Glossary::empty(), address, Operator::Forget).unwrap();
    let (second, _) =
        shield_text_with(&mut vault, &Glossary::empty(), address, Operator::Forget).unwrap();
    assert_ne!(first, second);
    assert!(first.starts_with("h1_email_"), "{first}");
    assert!(second.starts_with("h1_email_"), "{second}");
    assert!(vault.is_empty());
}

#[test]
fn forget_does_not_reuse_a_token_already_in_the_vault() {
    let address = "ada@example.com";
    let mut vault = Vault::new();
    let (stored, _) = shield_text(&mut vault, &Glossary::empty(), address).unwrap();
    let (forgotten, _) =
        shield_text_with(&mut vault, &Glossary::empty(), address, Operator::Forget).unwrap();
    assert_ne!(stored, forgotten, "{forgotten}");
    assert!(vault.holds_surface(address.as_bytes()));
    assert_eq!(vault.restore_write(&stored).unwrap(), address);
    assert!(matches!(
        vault.restore_write(&forgotten),
        Err(RestoreError::Unresolved { .. })
    ));
}

#[test]
fn forget_marks_a_secret_and_leaves_a_city() {
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let text = format!("Meet in Springfield. {secret} ada@example.com");
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), &text, Operator::Forget).unwrap();
    assert_eq!(audit.secret, 1, "{out}");
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.contains("Springfield"), "{out}");
    assert!(out.contains("h1_secret"), "{out}");
    assert!(out.contains("h1_email_"), "{out}");
    assert!(!out.contains(secret), "{out}");
    assert!(!out.contains("ada@example.com"), "{out}");
    assert!(vault.is_empty());
}

#[test]
fn json_forget_drops_the_address_and_restore_fails() {
    let input = r#"{"content":"mail marie@example.com"}"#;
    let mut vault = Vault::new();
    let (out, audit) =
        shield_json_strings_with(&mut vault, &Glossary::empty(), input, Operator::Forget).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.contains("h1_email_"), "{out}");
    assert!(!out.contains("marie@example.com"), "{out}");
    assert!(vault.is_empty());
    assert!(matches!(
        restore_json_write(&vault, &out),
        Err(JsonError::Restore(RestoreError::Unresolved { .. }))
    ));
}

#[test]
fn json_forget_shares_one_token_inside_the_call() {
    let input = r#"{"a":"marie@example.com","b":"see marie@example.com and marie@example.com"}"#;
    let mut vault = Vault::new();
    let (out, audit) =
        shield_json_strings_with(&mut vault, &Glossary::empty(), input, Operator::Forget).unwrap();
    assert_eq!(audit.email, 3, "{out}");
    let tokens = email_tokens(&out);
    assert_eq!(tokens.len(), 3, "{out}");
    assert_eq!(tokens[0], tokens[1], "{out}");
    assert_eq!(tokens[1], tokens[2], "{out}");
    assert!(vault.is_empty());

    let nested = r#"{"note":"{\"a\":\"marie@example.com\"}","b":"marie@example.com"}"#;
    let (out, audit) =
        shield_json_strings_with(&mut vault, &Glossary::empty(), nested, Operator::Forget).unwrap();
    assert_eq!(audit.email, 2, "{out}");
    let tokens = email_tokens(&out);
    assert_eq!(tokens.len(), 2, "{out}");
    assert_eq!(tokens[0], tokens[1], "{out}");
    assert!(vault.is_empty());
}

#[test]
fn json_forget_mints_again_and_skips_a_stored_token() {
    let input = r#"{"content":"marie@example.com"}"#;
    let mut vault = Vault::new();
    let (stored, _) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    assert_eq!(vault.len(), 1);
    let (forgotten, _) =
        shield_json_strings_with(&mut vault, &Glossary::empty(), input, Operator::Forget).unwrap();
    assert_ne!(stored, forgotten, "{forgotten}");
    assert_eq!(vault.len(), 1);
    assert_eq!(restore_json_write(&vault, &stored).unwrap(), input);
    assert!(matches!(
        restore_json_write(&vault, &forgotten),
        Err(JsonError::Restore(RestoreError::Unresolved { .. }))
    ));

    let mut fresh = Vault::new();
    let (first, _) =
        shield_json_strings_with(&mut fresh, &Glossary::empty(), input, Operator::Forget).unwrap();
    let (second, _) =
        shield_json_strings_with(&mut fresh, &Glossary::empty(), input, Operator::Forget).unwrap();
    assert_ne!(first, second);
    assert!(fresh.is_empty());
}

#[test]
fn json_token_still_stores_and_reuses_the_address() {
    let input = r#"{"a":"marie@example.com","b":"marie@example.com"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    assert_eq!(audit.email, 2, "{out}");
    assert_eq!(vault.len(), 1, "{out}");
    let tokens = email_tokens(&out);
    assert_eq!(tokens.len(), 2, "{out}");
    assert_eq!(tokens[0], tokens[1], "{out}");
    assert_eq!(restore_json_write(&vault, &out).unwrap(), input);

    let later = r#"{"content":"see marie@example.com"}"#;
    let (again, audit) = shield_json_strings(&mut vault, &Glossary::empty(), later).unwrap();
    assert_eq!(audit.email, 1, "{again}");
    assert!(again.contains(tokens[0]), "{again}");
    assert_eq!(vault.len(), 1);
}

#[test]
fn json_forget_drops_a_card_number_and_a_secret_tail() {
    let card = "4111111111111111";
    let input = format!(r#"{{"visa":{card},"card":{card}}}"#);
    let mut vault = Vault::new();
    let (out, audit) =
        shield_json_strings_with(&mut vault, &Glossary::empty(), &input, Operator::Forget).unwrap();
    assert_eq!(audit.card, 2, "{out}");
    assert!(!out.contains(card), "{out}");
    let tokens = card_tokens(&out);
    assert_eq!(tokens.len(), 2, "{out}");
    assert_eq!(tokens[0], tokens[1], "{out}");
    assert!(tokens[0].starts_with("h1_card_"), "{out}");
    assert!(vault.is_empty());
    assert!(vault.get(tokens[0]).is_none());
    assert!(matches!(
        restore_json_write(&vault, &out),
        Err(JsonError::Restore(RestoreError::Unresolved { .. }))
    ));

    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let assigned = format!(r#"{{"MY_API_KEY":"{secret} ada@example.com"}}"#);
    let (out, audit) =
        shield_json_strings_with(&mut vault, &Glossary::empty(), &assigned, Operator::Forget)
            .unwrap();
    assert_eq!(audit.secret, 1, "{out}");
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.contains("h1_secret"), "{out}");
    assert!(out.contains("h1_email_"), "{out}");
    assert!(!out.contains(secret), "{out}");
    assert!(!out.contains("ada@example.com"), "{out}");
    assert!(vault.is_empty());
    assert!(restore_json_write(&vault, &out).is_err());
}

#[test]
fn json_mask_stores_nothing_for_an_email_or_a_card_number() {
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings_with(
        &mut vault,
        &Glossary::empty(),
        r#"{"content":"ada@example.com"}"#,
        Operator::Mask,
    )
    .unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.contains("***@***"), "{out}");
    assert!(!out.contains("ada@example.com"), "{out}");
    assert!(vault.is_empty());

    let (out, audit) = shield_json_strings_with(
        &mut vault,
        &Glossary::empty(),
        r#"{"visa":4111111111111111}"#,
        Operator::Mask,
    )
    .unwrap();
    assert_eq!(audit.card, 1, "{out}");
    assert!(out.contains("**** **** **** ****"), "{out}");
    assert!(!out.contains("4111111111111111"), "{out}");
    assert!(vault.is_empty());
}

#[test]
fn session_forget_keeps_the_projection_and_stores_nothing() {
    let mut session = Session::new(Glossary::empty());
    let index = session
        .shield_message_with("ada@example.com and ada@example.com", Operator::Forget)
        .unwrap();
    let projection = session.replay()[index].projection.clone();
    let tokens = email_tokens(&projection);
    assert_eq!(tokens.len(), 2, "{projection}");
    assert_eq!(tokens[0], tokens[1], "{projection}");
    assert!(session.vault().is_empty());
    assert!(matches!(
        session.vault().restore_write(&projection),
        Err(RestoreError::Unresolved { .. })
    ));

    let second = session
        .shield_message_with("ada@example.com", Operator::Forget)
        .unwrap();
    assert_ne!(
        session.replay()[index].projection,
        session.replay()[second].projection
    );
    assert!(session.vault().is_empty());
}

#[test]
fn a_reply_keeps_a_forgotten_token_and_restores_the_stored_one() {
    let mut vault = Vault::new();
    let (stored, _) =
        shield_json_strings(&mut vault, &Glossary::empty(), r#"{"a":"ada@example.com"}"#).unwrap();
    let stored_token = email_tokens(&stored)[0].to_string();
    let (forgotten, _) = shield_json_strings_with(
        &mut vault,
        &Glossary::empty(),
        r#"{"a":"marie@example.com"}"#,
        Operator::Forget,
    )
    .unwrap();
    let forgotten_token = email_tokens(&forgotten)[0].to_string();
    assert_ne!(stored_token, forgotten_token);
    assert_eq!(vault.len(), 1);
    assert!(vault.get(&forgotten_token).is_none());
    assert!(!vault.holds_surface(b"marie@example.com"));

    let reply = format!(r#"{{"text":"see {stored_token} and {forgotten_token}"}}"#);
    let restored = restore_json_reply(&vault, &reply).unwrap();
    assert!(restored.contains("ada@example.com"), "{restored}");
    assert!(restored.contains(&forgotten_token), "{restored}");
    assert!(!restored.contains("marie@example.com"), "{restored}");
    assert!(matches!(
        restore_json_write(&vault, &reply),
        Err(JsonError::Restore(RestoreError::Unresolved { .. }))
    ));
    assert!(matches!(
        vault.restore_write(&forgotten_token),
        Err(RestoreError::Unresolved { .. })
    ));
    assert!(matches!(
        judge(&vault, "write_file", &forgotten_token, false),
        Judgment::WriteRejected { .. }
    ));

    let plain = format!("see {stored_token} and {forgotten_token} h1_secret");
    let restored = vault.restore_reply(&plain).unwrap();
    assert!(restored.contains("ada@example.com"), "{restored}");
    assert!(restored.contains(&forgotten_token), "{restored}");
    assert!(restored.contains("h1_secret"), "{restored}");
    assert!(vault.restore_reply("h1_email_AAAAAAAAR").is_err());
    assert!(restore_json_reply(&vault, r#"{"text":"h1_email_AAAAAAAAR"}"#).is_err());

    let path = std::env::temp_dir().join(format!(
        "hushid-forgotten-reply-{}.vault",
        std::process::id()
    ));
    vault.save(&path).unwrap();
    let loaded = Vault::load(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.len(), 1);
    let restored = loaded.restore_reply(&plain).unwrap();
    assert!(restored.contains("ada@example.com"), "{restored}");
    assert!(restored.contains(&forgotten_token), "{restored}");
    let (again, _) = shield_json_strings_with(
        &mut vault,
        &Glossary::empty(),
        r#"{"a":"marie@example.com"}"#,
        Operator::Forget,
    )
    .unwrap();
    assert_ne!(forgotten, again);
    assert_eq!(vault.len(), 1);
}

fn card_tokens(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("h1_card_") {
        let token = &rest[start..];
        let end = token
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(token.len());
        found.push(&token[..end]);
        rest = &token[end..];
    }
    found
}

#[test]
fn mask_still_stars_an_email_and_stores_nothing() {
    let mut vault = Vault::new();
    let (out, audit) = shield_text_with(
        &mut vault,
        &Glossary::empty(),
        "ada@example.com",
        Operator::Mask,
    )
    .unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert_eq!(out, "***@***");
    assert!(vault.is_empty());
}
