use hushid::{shield_text, shield_text_with, Glossary, Operator, Vault};

fn luhn_ok(digits: &[u8]) -> bool {
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

fn digit_bytes(text: &str) -> Vec<u8> {
    text.bytes().filter(|byte| byte.is_ascii_digit()).collect()
}

#[test]
fn digits_keep_the_card_shape_and_restore() {
    let card = "4111 1111 1111 1111";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), card, Operator::Digits).expect("digits");
    assert_eq!(audit.card, 1, "{out}");
    assert!(!out.contains("h1_card"), "{out}");
    assert_eq!(out.len(), card.len(), "{out}");
    assert_ne!(out, card);
    assert!(luhn_ok(&digit_bytes(&out)), "{out}");
    for (before, after) in card.chars().zip(out.chars()) {
        assert_eq!(before.is_ascii_digit(), after.is_ascii_digit(), "{out}");
        if !before.is_ascii_digit() {
            assert_eq!(before, after, "{out}");
        }
    }
    assert_eq!(vault.restore_write(&out).unwrap(), card);
    let (tokened, audit) = shield_text(&mut Vault::new(), &Glossary::empty(), card).expect("token");
    assert_eq!(audit.card, 1, "{tokened}");
    assert!(tokened.starts_with("h1_card_"), "{tokened}");
}

#[test]
fn digits_keep_a_sin_and_a_phone_and_leave_email() {
    let sin = "SIN 130 692 544";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), sin, Operator::Digits).expect("sin");
    assert_eq!(audit.sin, 1, "{out}");
    assert!(out.starts_with("SIN "), "{out}");
    assert!(!out.contains("130 692 544"), "{out}");
    assert!(luhn_ok(&digit_bytes(&out)), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), sin);

    let phone = "416-555-0123";
    let mut vault = Vault::new();
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), phone, Operator::Digits).expect("phone");
    assert_eq!(audit.phone, 1, "{out}");
    assert_eq!(out.len(), phone.len(), "{out}");
    assert!(out.as_bytes().contains(&b'-'), "{out}");
    assert_ne!(digit_bytes(&out), digit_bytes(phone));
    assert_eq!(vault.restore_write(&out).unwrap(), phone);

    let mail = "ada@example.com";
    let (out, audit) =
        shield_text_with(&mut vault, &Glossary::empty(), mail, Operator::Digits).expect("mail");
    assert_eq!(audit.email, 1, "{out}");
    assert!(out.starts_with("h1_email_"), "{out}");
}

#[test]
fn digit_stand_in_round_trips_through_the_vault_file() {
    let card = "4111 1111 1111 1111";
    let path = std::env::temp_dir().join(format!("hushid-digits-{}.vault", std::process::id()));
    let mut vault = Vault::new();
    let (out, _) =
        shield_text_with(&mut vault, &Glossary::empty(), card, Operator::Digits).expect("digits");
    vault.save(&path).expect("save");
    let loaded = Vault::load(&path).expect("load");
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.restore_write(&out).unwrap(), card);
}
