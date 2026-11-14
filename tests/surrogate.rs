use hushid::{shield_text, shield_text_with, Glossary, Operator, RestoreError, Vault};

fn shield(text: &str) -> (Vault, String, hushid::AuditRecord) {
    let mut vault = Vault::new();
    let (out, audit) = shield_text_with(&mut vault, &Glossary::empty(), text, Operator::Surrogate)
        .expect("surrogate");
    (vault, out, audit)
}

#[test]
fn surrogate_ramq_reads_as_a_health_number() {
    let text = "see BOUF 9451 1419 next";
    let (vault, out, audit) = shield(text);
    assert_eq!(audit.ramq, 1, "{out}");
    assert!(!out.contains("BOUF"), "{out}");
    assert!(!out.contains("9451"), "{out}");
    assert!(out.starts_with("see "), "{out}");
    assert!(out.ends_with(" next"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);
    let stand_in = out
        .strip_prefix("see ")
        .unwrap()
        .strip_suffix(" next")
        .unwrap();
    let (again, audit) = shield_text(&mut Vault::new(), &Glossary::empty(), stand_in).unwrap();
    assert_eq!(audit.ramq, 1, "{stand_in} -> {again}");
    assert!(again.starts_with("h1_ramq_"), "{again}");
}

#[test]
fn surrogate_email_reads_as_an_email_and_restores() {
    let text = "Write to ada@example.com today.";
    let (vault, out, audit) = shield(text);
    assert_eq!(audit.email, 1, "{out}");
    assert!(!out.contains("h1_email_"), "{out}");
    assert!(!out.contains("ada@example.com"), "{out}");
    assert!(out.contains("@example.org"), "{out}");
    assert!(out.starts_with("Write to "), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);

    let (tokened, audit) = shield_text(&mut Vault::new(), &Glossary::empty(), text).unwrap();
    assert_eq!(audit.email, 1, "{tokened}");
    assert!(tokened.contains("h1_email_"), "{tokened}");
}

#[test]
fn surrogate_kinds_hide_the_original_bytes() {
    let glossary = Glossary::from_terms(["Elodie"]);
    let samples = [
        ("416-555-0123", "-"),
        ("4111 1111 1111 1111", " "),
        ("SIN 130 692 544", "SIN "),
        ("born Jan 2, 1990", "born "),
        ("88 Main Street", "Example Lane"),
        ("postal code H2X 1Y4", " "),
    ];
    for (text, marker) in samples {
        let mut vault = Vault::new();
        let (out, audit) =
            shield_text_with(&mut vault, &Glossary::empty(), text, Operator::Surrogate)
                .expect("surrogate");
        assert!(!out.contains("h1_"), "{text} -> {out}");
        assert_ne!(out, text, "{text}");
        assert!(out.contains(marker), "{text} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), text, "{out}");
        let _ = audit;
    }

    let mut vault = Vault::new();
    let (out, audit) = shield_text_with(
        &mut vault,
        &glossary,
        "Ask Elodie today.",
        Operator::Surrogate,
    )
    .expect("name");
    assert_eq!(audit.glossary, 1, "{out}");
    assert!(!out.contains("Elodie"), "{out}");
    assert!(!out.contains("h1_glossary_"), "{out}");
    assert!(out.starts_with("Ask "), "{out}");
    assert!(out.ends_with(" today."), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), "Ask Elodie today.");
}

#[test]
fn surrogate_digits_keep_the_detected_shape() {
    for surface in [
        "4111.1111.1111.1111",
        "3782 822463 10005",
        "SIN 130.692.544",
        "+44 20 7946 0958",
    ] {
        let mut vault = Vault::new();
        let (out, _) =
            shield_text_with(&mut vault, &Glossary::empty(), surface, Operator::Surrogate).unwrap();
        let marks = |text: &str| {
            text.chars()
                .filter(|ch| !ch.is_ascii_digit())
                .collect::<String>()
        };
        let digits = |text: &str| {
            text.chars()
                .filter(|ch| ch.is_ascii_digit())
                .collect::<String>()
        };
        assert_eq!(marks(&out), marks(surface), "{surface} -> {out}");
        assert_eq!(
            digits(&out).len(),
            digits(surface).len(),
            "{surface} -> {out}"
        );
        assert_ne!(digits(&out), digits(surface), "{surface} -> {out}");
        assert!(!out.contains("555-555-"), "{surface} -> {out}");
        assert_eq!(vault.restore_write(&out).unwrap(), surface);
    }
}

#[test]
fn surrogate_leaves_a_secret_unrestored() {
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), secret, Operator::Surrogate)
            .expect("secret");
    assert_eq!(audit.secret, 1, "{out}");
    assert_eq!(out, "h1_secret");
    assert!(matches!(
        vault.restore_write(&out),
        Err(RestoreError::SecretMark { .. })
    ));
}

#[test]
fn two_surrogate_emails_differ() {
    let text = "ada@example.com and bea@example.com";
    let (vault, out, audit) = shield(text);
    assert_eq!(audit.email, 2, "{out}");
    assert!(!out.contains("ada@example.com"), "{out}");
    assert!(!out.contains("bea@example.com"), "{out}");
    let parts: Vec<_> = out.split(" and ").collect();
    assert_eq!(parts.len(), 2, "{out}");
    assert_ne!(parts[0], parts[1], "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);
}

#[test]
fn a_glued_letter_does_not_restore_the_surrogate() {
    let original = "ada@example.com";
    let mut vault = Vault::new();
    let (out, _) = shield_text_with(
        &mut vault,
        &Glossary::empty(),
        original,
        Operator::Surrogate,
    )
    .unwrap();
    let glued = format!("x{out}");
    assert_eq!(vault.restore_write(&glued).unwrap(), glued);
    assert_eq!(vault.restore_write(&out).unwrap(), original);
}

#[test]
fn surrogate_round_trips_through_the_vault_file() {
    let text = "Write to ada@example.com today.";
    let path = std::env::temp_dir().join(format!("hushid-surrogate-{}.vault", std::process::id()));
    let mut vault = Vault::new();
    let (out, _) =
        shield_text_with(&mut vault, &Glossary::empty(), text, Operator::Surrogate).unwrap();
    vault.save(&path).expect("save");
    let loaded = Vault::load(&path).expect("load");
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.restore_write(&out).unwrap(), text);
}
