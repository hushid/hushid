use hushid::{shield_text, shield_text_with, Glossary, Operator, RestoreError, Vault};

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
