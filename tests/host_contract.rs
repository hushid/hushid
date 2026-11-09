use hushid::{
    accept_non_text, parse_identifiers_config, restore_json_write, shield_json_strings,
    shield_text, shielding_active, ArgumentBuffer, Glossary, HeldStream, Judgment, Kind, Mode,
    Session, Sink, Vault,
};
use std::fs;
use std::path::Path;

#[test]
fn replay_returns_the_stored_projection_and_thinking_is_untouched() {
    let mut session = Session::new(Glossary::empty());
    let index = session.shield_message("a@b.co").unwrap();
    let stored = session.replay()[index].projection.clone();
    assert!(!stored.contains("a@b.co"));
    let _ = session.shield_message("other@b.co").unwrap();
    assert_eq!(session.replay()[0].projection, stored);

    let thinking = b"signed a@b.co h1_email_AAAAAAAAR";
    let vault_len = session.vault().len();
    session.store_thinking(0, thinking).unwrap();
    assert_eq!(
        session.replay()[0].thinking.as_deref(),
        Some(thinking.as_slice())
    );
    assert_eq!(session.replay()[0].projection, stored);
    assert_eq!(session.vault().len(), vault_len);
    assert!(session.store_thinking(9, b"nope").is_err());
}

#[test]
fn json_strings_are_shielded_and_numbers_stay() {
    let input = r#"{"email":"a@b.co","n":4111111111111111,"note":"call 415-555-0134"}"#;
    let mut vault = Vault::new();
    let (out, audit) = shield_json_strings(&mut vault, &Glossary::empty(), input).unwrap();
    assert!(out.contains("\"email\""), "{out}");
    assert!(out.contains("4111111111111111"), "{out}");
    assert!(!out.contains("a@b.co"), "{out}");
    assert_eq!(audit.email, 1);
    assert_eq!(audit.phone, 1);
    assert_eq!(audit.card, 0);
    let restored = restore_json_write(&vault, &out).unwrap();
    assert!(restored.contains("a@b.co"), "{restored}");
    assert!(restored.contains("415-555-0134"), "{restored}");
    assert!(restored.contains("4111111111111111"), "{restored}");
}

#[test]
fn json_key_token_fails_a_write() {
    let mut vault = Vault::new();
    let token = vault
        .issue_payload(Kind::Email, "AAAAAAAA", b"a@b.co")
        .unwrap();
    let input = format!(r#"{{"{token}":"ok"}}"#);
    assert!(restore_json_write(&vault, &input).is_err());
}

#[test]
fn stream_holds_a_split_token_until_it_is_complete() {
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    let token = projection.clone();
    let mut stream = HeldStream::new();
    let split = token.len() / 2;
    let first = stream.push_restore(&token[..split], &vault);
    assert!(!first.contains("a@b.co"), "{first}");
    let second = stream.push_restore(&token[split..], &vault);
    let done = stream.finish_restore(&vault);
    assert_eq!(format!("{first}{second}{done}"), "a@b.co");
}

#[test]
fn argument_deltas_are_judged_only_when_complete() {
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    let mut args = ArgumentBuffer::new();
    args.push("echo ");
    assert!(matches!(
        args.judge("run_command", false, &vault),
        Judgment::Run { sink: Sink::Shell }
    ));
    args.push(&projection);
    assert!(matches!(
        args.judge("run_command", false, &vault),
        Judgment::Refuse { sink: Sink::Shell }
    ));
}

#[test]
fn config_accepts_off_and_cloud_only() {
    let config = parse_identifiers_config(
        "[identifiers]\nmode = \"cloud\"\nglossary = \"identifiers.txt\"\n",
    )
    .unwrap();
    assert_eq!(config.mode, Mode::Cloud);
    assert_eq!(config.glossary.unwrap().as_os_str(), "identifiers.txt");
    assert!(shielding_active(Mode::Cloud, false));
    assert!(!shielding_active(Mode::Cloud, true));
    assert!(!shielding_active(Mode::Off, false));
    assert!(parse_identifiers_config("[identifiers]\nmode = \"private\"\n").is_err());
    assert!(parse_identifiers_config("[identifiers]\nmode = \"law25\"\n").is_err());
    assert!(accept_non_text(Mode::Cloud).is_err());
    assert!(accept_non_text(Mode::Off).is_ok());
}

#[test]
fn glossary_file_round_trip() {
    let path = std::env::temp_dir().join(format!("hushid-glossary-{}", std::process::id()));
    fs::write(&path, "# local\nMarie\n\nJean Pierre\n").unwrap();
    let glossary = Glossary::load(&path).unwrap();
    let mut vault = Vault::new();
    let (out, audit) = shield_text(&mut vault, &glossary, "Marie and Jean Pierre").unwrap();
    assert_eq!(audit.glossary, 2, "{out}");
    assert_eq!(vault.restore_write(&out).unwrap(), "Marie and Jean Pierre");
    let _ = fs::remove_file(&path);
}

#[test]
fn vault_file_is_mode_0600_and_round_trips() {
    let path = std::env::temp_dir().join(format!("hushid-vault-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    vault.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let loaded = Vault::load(&path).unwrap();
    assert_eq!(loaded.restore_write(&projection).unwrap(), "a@b.co");
    let _ = fs::remove_file(&path);
}

#[test]
fn quiet_surfaces_stay_out_of_the_tree() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("README.md").exists());
    assert!(!root.join(".github/FUNDING.yml").exists());
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("publish = false"));
    let lower = manifest.to_ascii_lowercase();
    assert!(!lower.contains("keywords"));
    for entry in fs::read_dir(root.join("src")).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap().to_ascii_lowercase();
        assert!(!text.contains("anonym"), "{}", path.display());
        assert!(!text.contains("law 25"), "{}", path.display());
        assert!(!text.contains("law25"), "{}", path.display());
        assert!(!text.contains("private mode"), "{}", path.display());
        assert!(!text.contains("gaze"), "{}", path.display());
    }
}
