use hushid::{seal_transcript, shield_text, Glossary, Vault};

#[test]
fn seal_round_trips_the_vault_and_the_clear_transcript() {
    let mut vault = Vault::new();
    let (projection, _) =
        shield_text(&mut vault, &Glossary::empty(), "Write to ada@example.com.").unwrap();
    let clear = vec!["Write to ada@example.com.".to_string(), projection.clone()];
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).unwrap();
    let sealed = seal_transcript(&vault, &clear, &key).unwrap();
    assert!(!sealed
        .windows(email_bytes().len())
        .any(|window| window == email_bytes()));
    let (opened, messages) = hushid::open_sealed(&sealed, &key).unwrap();
    assert_eq!(messages, clear);
    assert_eq!(opened.restore_write(&projection).unwrap(), clear[0]);
    let mut wrong = key;
    wrong[0] ^= 1;
    assert!(hushid::open_sealed(&sealed, &wrong).is_err());
    let mut torn = sealed.clone();
    let last = torn.len() - 1;
    torn[last] ^= 1;
    assert!(hushid::open_sealed(&torn, &key).is_err());
}

fn email_bytes() -> &'static [u8] {
    b"ada@example.com"
}
