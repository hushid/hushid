#![no_main]

use hushid::{find_h1, restore_json_write, shield_json_strings, Glossary, Vault};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = restore_json_write(&Vault::new(), text);
    if find_h1(text, 0).is_some() {
        return;
    }
    let mut vault = Vault::new();
    let Ok((out, audit)) = shield_json_strings(&mut vault, &Glossary::empty(), text) else {
        return;
    };
    if audit.secret == 0 {
        // Escapes may be rewritten (`\b` becomes `\u0008`). Restore must
        // succeed. The bytes do not have to match.
        restore_json_write(&vault, &out).expect("shielded json restores");
    } else {
        assert!(restore_json_write(&vault, &out).is_err());
    }
});
