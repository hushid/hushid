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
    let wrong_open = hushid::open_sealed(&sealed, &wrong).unwrap_err();
    assert_eq!(wrong_open.to_string(), "sealed transcript cannot be opened");
    let mut torn = sealed.clone();
    let last = torn.len() - 1;
    torn[last] ^= 1;
    let torn_open = hushid::open_sealed(&torn, &key).unwrap_err();
    assert_eq!(torn_open.to_string(), "sealed transcript cannot be opened");
    let short = hushid::open_sealed(&[], &key).unwrap_err();
    assert_eq!(short.to_string(), "sealed transcript cannot be opened");
    let bare = hushid::open_sealed(b"not-a-seal", &key).unwrap_err();
    assert_eq!(bare.to_string(), "sealed transcript cannot be opened");
}

fn email_bytes() -> &'static [u8] {
    b"ada@example.com"
}
