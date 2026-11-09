use hushid::{
    classify, judge, permissions_view, shield_text, Glossary, Judgment, Sink, Vault, VaultError,
};

fn shielded_email() -> (Vault, String) {
    let mut vault = Vault::new();
    let (out, _) = shield_text(&mut vault, &Glossary::empty(), "marie+tag@example.com").unwrap();
    (vault, out)
}

#[test]
fn write_restores_exact_bytes() {
    let (vault, token) = shielded_email();
    let body = format!("addr={token};");
    match judge(&vault, "edit_file", &body, false) {
        Judgment::RestoreAndRun {
            sink: Sink::LocalWrite,
            restored,
        } => assert_eq!(restored, "addr=marie+tag@example.com;"),
        other => panic!("expected restore, got {other:?}"),
    }
}

#[test]
fn write_fails_on_unresolved_token_and_on_secret_mark() {
    let (vault, token) = shielded_email();
    let mangled = format!("{token} h1_nope");
    match judge(&vault, "edit_file", &mangled, false) {
        Judgment::WriteRejected {
            sink: Sink::LocalWrite,
            error,
        } => {
            let rendered = format!("{error:?}");
            assert!(!rendered.contains("marie"));
            assert!(!rendered.contains('@'));
        }
        other => panic!("expected write rejection, got {other:?}"),
    }

    let marked = format!("{token} h1_secret");
    assert!(matches!(
        judge(&vault, "notebook_edit", &marked, false),
        Judgment::WriteRejected { .. }
    ));
    assert!(vault.restore_write("keep h1_secret").is_err());
}

#[test]
fn shell_refuses_tokens_and_does_not_interpolate() {
    let (vault, token) = shielded_email();
    let command = format!("echo {token}");
    match judge(&vault, "run_command", &command, false) {
        Judgment::Refuse { sink: Sink::Shell } => {}
        other => panic!("expected refuse, got {other:?}"),
    }
    let rendered = format!("{:?}", judge(&vault, "run_background", &command, false));
    assert!(!rendered.contains("marie"));
    assert!(!rendered.contains("RestoreAndRun"));

    assert!(matches!(
        judge(&vault, "code_mode", "echo h1_secret", false),
        Judgment::Refuse { sink: Sink::Shell }
    ));
    assert!(matches!(
        judge(&vault, "run_command", "echo h1_nope", false),
        Judgment::Refuse { sink: Sink::Shell }
    ));
    assert!(matches!(
        judge(&vault, "run_command", "echo hello", false),
        Judgment::Run { sink: Sink::Shell }
    ));
}

#[test]
fn network_github_image_video_and_mcp_refuse_when_a_token_is_present() {
    let (vault, token) = shielded_email();
    for name in [
        "web_search",
        "web_fetch",
        "create_issue",
        "git_commit",
        "image_gen",
        "image_edit",
        "image_to_video",
        "reference_to_video",
        "image_upscale",
        "send_somewhere",
    ] {
        assert!(
            matches!(judge(&vault, name, &token, false), Judgment::Refuse { .. }),
            "{name}"
        );
        assert!(
            matches!(judge(&vault, name, "clean", false), Judgment::Run { .. }),
            "{name} clean"
        );
    }
    assert!(matches!(
        judge(&vault, "read_file", &token, true),
        Judgment::Refuse {
            sink: Sink::LeavesMachine
        }
    ));
}

#[test]
fn local_read_keeps_arguments_and_display_restores() {
    let (vault, token) = shielded_email();
    assert!(matches!(
        judge(&vault, "read_file", &token, false),
        Judgment::Run {
            sink: Sink::LocalRead
        }
    ));
    assert_eq!(classify("git_diff", false), Sink::LocalRead);
    assert_eq!(classify("git_commit", false), Sink::LeavesMachine);
    match judge(&vault, "ask_user", &token, false) {
        Judgment::RestoreAndRun {
            sink: Sink::Display,
            restored,
        } => assert_eq!(restored, "marie+tag@example.com"),
        other => panic!("expected display restore, got {other:?}"),
    }
}

#[test]
fn permissions_view_is_not_the_shell_result() {
    let (vault, token) = shielded_email();
    let view = permissions_view(&vault, &token);
    assert_eq!(view.as_str(), "marie+tag@example.com");
    assert!(!format!("{view:?}").contains("marie"));
    match judge(&vault, "run_command", &token, false) {
        Judgment::Refuse { .. } => {}
        other => panic!("shell must not restore, got {other:?}"),
    }
}

#[test]
fn missing_vault_does_not_rebuild_from_clear_text() {
    let path = std::env::temp_dir().join(format!("hushid-missing-{}-vault", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let err = Vault::load(&path).unwrap_err();
    assert!(matches!(err, VaultError::Missing));

    let (vault, token) = shielded_email();
    let empty = Vault::new();
    assert!(empty.restore_write(&token).is_err());
    assert!(!empty.holds_surface(b"marie+tag@example.com"));
    drop(vault);
}

#[test]
fn rescan_of_a_projection_does_not_issue_new_tokens() {
    let mut vault = Vault::new();
    let (projection, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
    let before = vault.len();
    let (again, audit) = shield_text(&mut vault, &Glossary::empty(), &projection).unwrap();
    assert_eq!(again, projection);
    assert_eq!(audit.email, 0);
    assert_eq!(vault.len(), before);
}
