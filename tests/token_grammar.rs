use hushid::{format_token, Kind, RestoreError, Vault};

#[test]
fn token_is_kind_plus_eight_symbols_and_a_check() {
    let token = format_token(Kind::Email, "AAAAAAAA").unwrap();
    assert_eq!(token, "h1_email_AAAAAAAAR");
    assert_eq!(token.len(), "h1_email_".len() + 9);
    assert!(token.starts_with("h1_email_"));
}

#[test]
fn payload_must_be_eight_symbols() {
    assert!(format_token(Kind::Email, "AAAAAAA").is_err());
    assert!(format_token(Kind::Email, "AAAAAAAAA").is_err());
    assert!(format_token(Kind::Email, "AAAAAAAU").is_err());
}

#[test]
fn issued_token_restores_exact_bytes() {
    let mut vault = Vault::new();
    let token = vault.issue(Kind::Phone, b"+1 415 555 0134").unwrap();
    assert_eq!(vault.get(&token), Some(b"+1 415 555 0134".as_slice()));
    let wrapped = format!("call {token} now");
    assert_eq!(
        vault.restore_write(&wrapped).unwrap(),
        "call +1 415 555 0134 now"
    );
}

#[test]
fn check_failure_is_unresolved() {
    let mut vault = Vault::new();
    let token = vault
        .issue_payload(Kind::Email, "AAAAAAAA", b"a@b.co")
        .unwrap();
    let mut bytes = token.into_bytes();
    let index = bytes.len() - 2;
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    assert_eq!(vault.get(&tampered), None);
    assert!(vault.restore_write(&tampered).is_err());
    assert_eq!(vault.restore_display(&tampered), tampered);
}

#[test]
fn valid_check_from_another_vault_is_not_restored() {
    let forged = format_token(Kind::Card, "BBBBBBBB").unwrap();
    let vault = Vault::new();
    assert_eq!(vault.get(&forged), None);
    assert!(vault.restore_write(&forged).is_err());
    assert_eq!(vault.restore_display(&forged), forged);
}

#[test]
fn uppercase_spelling_still_restores() {
    let mut vault = Vault::new();
    let token = vault
        .issue_payload(Kind::Email, "AAAAAAAA", b"a@b.co")
        .unwrap();
    assert_eq!(
        vault.restore_write(&token.to_ascii_uppercase()).unwrap(),
        "a@b.co"
    );
}

#[test]
fn a_non_utf8_surface_names_the_token_not_the_stored_bytes() {
    let mut vault = Vault::new();
    let token = vault.issue(Kind::Email, &[0xff, 0xfe]).unwrap();
    let err = vault.restore_write(&token).unwrap_err();
    assert_eq!(err, RestoreError::NotUtf8 { at: 0 });
    assert_eq!(
        err.to_string(),
        "stored surface for the token at byte 0 is not utf-8"
    );
}

#[test]
fn lowercase_and_crockford_aliases_resolve() {
    let mut vault = Vault::new();
    let token = vault
        .issue_payload(Kind::Sin, "OOOOOOOO", b"130692544")
        .unwrap();
    assert!(token.contains("00000000"));
    let aliased = token.replace('0', "O");
    assert_eq!(vault.restore_write(&aliased).unwrap(), "130692544");
    assert_eq!(
        vault.restore_write(&token.to_ascii_lowercase()).unwrap(),
        "130692544"
    );
}

#[test]
fn short_suffix_and_unknown_prefix_do_not_restore() {
    let mut vault = Vault::new();
    let _ = vault
        .issue_payload(Kind::Email, "AAAAAAAA", b"a@b.co")
        .unwrap();
    assert!(vault.restore_write("h1_email_AAAAAAAA").is_err());
    assert!(vault.restore_write("see h1_nope").is_err());
    assert!(vault.restore_write("h1_secret_AAAAAAAAR").is_err());
}

#[test]
fn same_surface_gets_distinct_tokens() {
    let mut vault = Vault::new();
    let first = vault.issue(Kind::Email, b"a@b.co").unwrap();
    let second = vault.issue(Kind::Email, b"a@b.co").unwrap();
    assert_ne!(first, second);
    assert_eq!(vault.restore_write(&first).unwrap(), "a@b.co");
    assert_eq!(vault.restore_write(&second).unwrap(), "a@b.co");
}
