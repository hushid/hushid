use hushid::{shield_text, shield_text_with, Glossary, Operator, Vault};

#[test]
fn mask_hides_an_email_and_does_not_restore_it() {
    let text = "Write to ada@example.com today.";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), text, Operator::Mask).unwrap();
    assert_eq!(audit.email, 1, "{out}");
    assert_eq!(out, "Write to ***@*** today.");
    assert!(!vault.holds_surface(b"ada@example.com"));
    assert_eq!(vault.restore_write(&out).unwrap(), out);

    let (tokened, _) = shield_text(&mut Vault::new(), &Glossary::empty(), text).unwrap();
    assert!(tokened.contains("h1_email_"), "{tokened}");
}

#[test]
fn mask_leaves_a_secret_unrestored() {
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), secret, Operator::Mask).unwrap();
    assert_eq!(audit.secret, 1, "{out}");
    assert_eq!(out, "h1_secret");
    assert!(vault.restore_write(&out).is_err());
}
