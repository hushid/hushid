use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use hushid::{
    classify, judge, known_tool_sinks, permissions_view, shield_text, Glossary, Judgment, Sink,
    Vault, VaultError,
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
fn local_file_tools_restore_a_token() {
    let (vault, token) = shielded_email();
    let body = format!(r#"{{"content":"{token}"}}"#);
    for name in [
        "write_file",
        "hashline_edit",
        "apply_patch",
        "apply_patch_file",
        "patchloom_plan",
        "delete_file",
        "rename_file",
        "tidy",
        "undo",
        "manage_skill",
        "manage_memory",
        "plan",
        "todo",
        "update_goal",
        "md_replace_section",
        "md_upsert_bullet",
        "md_table_append",
        "md_insert_after",
        "md_insert_before",
        "md_move_section",
        "doc_set",
        "doc_ensure",
        "doc_delete",
        "doc_merge",
        "doc_append",
        "doc_prepend",
        "doc_update",
        "doc_move",
        "doc_delete_where",
    ] {
        match judge(&vault, name, &body, false) {
            Judgment::RestoreAndRun {
                sink: Sink::LocalWrite,
                restored,
            } => {
                assert_eq!(restored, r#"{"content":"marie+tag@example.com"}"#, "{name}");
            }
            other => panic!("{name} expected a local restore, got {other:?}"),
        }
    }
    assert!(matches!(
        judge(&vault, "write_file", "keep h1_secret", false),
        Judgment::WriteRejected {
            sink: Sink::LocalWrite,
            ..
        }
    ));
}

#[test]
fn think_runs_without_restoring_a_token() {
    let (vault, token) = shielded_email();
    let thought = format!("note {token}");
    assert!(matches!(
        judge(&vault, "think", &thought, false),
        Judgment::Run {
            sink: Sink::LocalRead
        }
    ));
    assert!(matches!(
        judge(&vault, "think", "note h1_secret", false),
        Judgment::Run {
            sink: Sink::LocalRead
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

#[test]
fn every_listed_tool_judges_its_sink() {
    let (vault, token) = shielded_email();
    let body = format!(r#"{{"content":"{token}"}}"#);
    let mut seen = BTreeSet::new();
    for (name, sink) in known_tool_sinks() {
        assert!(seen.insert(*name), "duplicate tool {name}");
        assert_eq!(classify(name, false), *sink, "{name}");
        match sink {
            Sink::LocalWrite => match judge(&vault, name, &body, false) {
                Judgment::RestoreAndRun {
                    sink: Sink::LocalWrite,
                    restored,
                } => assert!(
                    restored.contains("marie+tag@example.com"),
                    "{name} {restored}"
                ),
                other => panic!("{name} expected a local restore, got {other:?}"),
            },
            Sink::LocalRead => assert!(
                matches!(
                    judge(&vault, name, &body, false),
                    Judgment::Run {
                        sink: Sink::LocalRead
                    }
                ),
                "{name}"
            ),
            Sink::Display => match judge(&vault, name, &body, false) {
                Judgment::RestoreAndRun {
                    sink: Sink::Display,
                    restored,
                } => assert!(restored.contains("marie+tag@example.com"), "{name}"),
                other => panic!("{name} expected a display restore, got {other:?}"),
            },
            Sink::Shell | Sink::LeavesMachine => {
                assert!(
                    matches!(judge(&vault, name, &body, false), Judgment::Refuse { .. }),
                    "{name} should refuse a token"
                );
                assert!(
                    matches!(judge(&vault, name, "plain", false), Judgment::Run { .. }),
                    "{name} should run plain text"
                );
            }
        }
    }
    assert_eq!(classify("not_a_tool", false), Sink::LeavesMachine);
}

#[test]
fn bline_builtin_tools_are_in_the_judge_list() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../bline/crates/bline-tools/src/builtin");
    if !dir.is_dir() {
        return;
    }
    let mut found = BTreeSet::new();
    collect_tool_names(&dir, &mut found);
    let known: BTreeSet<&str> = known_tool_sinks().iter().map(|(name, _)| *name).collect();
    let missing: Vec<_> = found
        .iter()
        .filter(|name| !known.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "Bline tools missing from judge: {missing:?}"
    );
}

fn collect_tool_names(dir: &Path, found: &mut BTreeSet<String>) {
    let entries = fs::read_dir(dir).unwrap();
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_tool_names(&path, found);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for line in text.lines() {
            if let Some(name) = tool_name_on_line(line) {
                found.insert(name);
            }
        }
    }
}

fn tool_name_on_line(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("name:")?;
    let rest = rest.trim().strip_prefix('"')?;
    let name = rest.split('"').next()?;
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    {
        return None;
    }
    Some(name.to_string())
}

#[test]
fn secret_mark_that_splits_a_multibyte_character_does_not_panic() {
    let split = "h1_secre\u{3394}";
    assert!(Vault::new().restore_write(split).is_err());
    let crash = [
        107, 101, 0, 104, 48, 95, 115, 101, 227, 142, 148, 116, 10, 116, 10,
    ];
    let text = std::str::from_utf8(&crash).unwrap();
    let _ = Vault::new().restore_write(text);
}
