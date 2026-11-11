#![no_main]

use hushid::{find_h1, parse_token_at, secret_mark_at, shield_text, Glossary, Vault};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut index = 0;
    while index < text.len() {
        if text.is_char_boundary(index) {
            if let Some(parsed) = parse_token_at(text, index) {
                assert!(parsed.end > index && parsed.end <= text.len());
                assert!(text.is_char_boundary(parsed.end));
                let again = parse_token_at(&parsed.canonical, 0).expect("canonical parses");
                assert_eq!(again.kind, parsed.kind);
                assert_eq!(again.check_ok, parsed.check_ok);
                assert_eq!(again.end, parsed.canonical.len());
            }
            if let Some(end) = secret_mark_at(text, index) {
                assert!(end > index && end <= text.len());
                assert!(text.is_char_boundary(end));
            }
        }
        index += 1;
    }
    if let Some(at) = find_h1(text, 0) {
        assert!(text.is_char_boundary(at));
        assert!(at + 3 <= text.len());
    }
    if find_h1(text, 0).is_some() {
        let _ = Vault::new().restore_write(text);
        return;
    }
    let mut vault = Vault::new();
    let Ok((out, audit)) = shield_text(&mut vault, &Glossary::empty(), text) else {
        return;
    };
    if audit.secret == 0 {
        let restored = vault
            .restore_write(&out)
            .expect("reversible shield restores");
        assert_eq!(restored, text);
    } else {
        assert!(vault.restore_write(&out).is_err());
    }
});
