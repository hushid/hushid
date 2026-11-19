#![cfg(windows)]
//! Session files on a case-insensitive volume.

use hushid::{shield_text, Glossary, Vault};
use hushid_proxy::{load_session, save_session};

#[cfg(windows)]
#[test]
fn a_different_case_does_not_open_the_other_session() {
    let dir = std::env::temp_dir().join(format!("hushid-proxy-case-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut first = Vault::new();
    let (token, _) = shield_text(&mut first, &Glossary::empty(), "ada@example.com").unwrap();
    save_session(&dir, "WinCase", &first).unwrap();

    let err = load_session(&dir, "wincase").unwrap_err();
    assert_eq!(err.to_string(), "session");
    let mut second = Vault::new();
    shield_text(&mut second, &Glossary::empty(), "bea@example.com").unwrap();
    let save_err = save_session(&dir, "wincase", &second).unwrap_err();
    assert_eq!(save_err.to_string(), "session");

    let loaded = load_session(&dir, "WinCase").unwrap();
    assert_eq!(loaded.restore_write(&token).unwrap(), "ada@example.com");
    let text = std::fs::read_to_string(dir.join("WinCase.vault")).unwrap();
    assert!(!text.contains("626561406578616d706c652e636f6d"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}
