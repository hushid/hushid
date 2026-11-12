use hushid::{shield_text, Glossary, Vault};

fn standard_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let chunk = (u32::from(data[index]) << 16)
            | (u32::from(data[index + 1]) << 8)
            | u32::from(data[index + 2]);
        out.push(ALPHABET[((chunk >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 6) & 63) as usize] as char);
        out.push(ALPHABET[(chunk & 63) as usize] as char);
        index += 3;
    }
    out
}

#[test]
fn base64_of_a_detected_email_is_shielded() {
    let email = "ada@example.com";
    let encoded = standard_base64(email.as_bytes());
    let text = format!("{email} {encoded}");
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &Glossary::empty(), &text).unwrap();
    assert_eq!(audit.email, 2, "{out}");
    assert!(!out.contains(email), "{out}");
    assert!(!out.contains(&encoded), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), text);
}

#[test]
fn echo_of_a_known_name_is_shielded_without_the_glossary() {
    let mut vault = Vault::new();
    let glossary = Glossary::from_terms(["Elodie"]);
    shield_text(&mut vault, &glossary, "Ask Elodie today.").unwrap();
    let (out, audit) = shield_text(&mut vault, &Glossary::empty(), "echo Elodie").unwrap();
    assert_eq!(audit.glossary, 1, "{out}");
    assert!(!out.contains("Elodie"), "{out}");
    assert!(out.starts_with("echo h1_glossary_"), "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), "echo Elodie");
}
