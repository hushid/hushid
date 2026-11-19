//! Windows host paths and a second save of the same vault file.
//! These run on every OS. The second save is the case that fails when
//! rename cannot replace an existing file.

use hushid::{shield_text, Glossary, Vault};
use std::fs;

#[test]
fn second_save_replaces_a_vault_whose_name_has_a_space() {
    let dir = std::env::temp_dir().join(format!("hushid-win-vault-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("session vault.bin");

    let mut first = Vault::new();
    let (kept, _) = shield_text(&mut first, &Glossary::empty(), "ada@example.com").unwrap();
    first.save(&path).expect("first save");

    let mut second = Vault::new();
    let (replaced, _) = shield_text(&mut second, &Glossary::empty(), "bea@example.com").unwrap();
    second.save(&path).expect("second save");

    let loaded = Vault::load(&path).expect("load");
    assert_eq!(loaded.restore_write(&replaced).unwrap(), "bea@example.com");
    assert!(loaded.restore_write(&kept).is_err(), "{kept}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn notepad_utf8_bom_and_crlf_still_match_the_first_name() {
    let dir = std::env::temp_dir().join(format!("hushid-win-glossary-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("names.txt");
    let body = "\u{feff}Tremblay\r\nMarie\r\n";
    fs::write(&path, body).unwrap();
    let glossary = Glossary::load(&path).unwrap();
    let mut vault = Vault::new();
    let (out, _) = shield_text(&mut vault, &glossary, "Call Tremblay and Marie.").unwrap();
    assert!(!out.contains("Tremblay"), "{out}");
    assert!(!out.contains("Marie"), "{out}");
    assert!(out.contains("h1_glossary_"), "{out}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn notepad_unicode_glossary_is_refused() {
    let dir = std::env::temp_dir().join(format!("hushid-win-utf16-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("names.txt");
    let mut bytes = vec![0xff, 0xfe];
    for unit in "Tremblay\r\n".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    fs::write(&path, bytes).unwrap();
    let err = Glossary::load(&path).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("UTF-8") || message.contains("utf-8") || message.contains("stream"),
        "{message}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vault_save_creates_a_parent_whose_name_is_not_ascii() {
    let dir = std::env::temp_dir().join(format!("hushid-win-café-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let path = dir.join("nested").join("vault.bin");
    let mut vault = Vault::new();
    let (out, _) = shield_text(&mut vault, &Glossary::empty(), "ada@example.com").unwrap();
    vault.save(&path).expect("save");
    let loaded = Vault::load(&path).unwrap();
    assert_eq!(loaded.restore_write(&out).unwrap(), "ada@example.com");
    let _ = fs::remove_dir_all(&dir);
}
