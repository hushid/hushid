use crate::token::find_h1;
use crate::vault::{RestoreError, Vault};
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sink {
    LocalRead,
    LocalWrite,
    Display,
    Shell,
    LeavesMachine,
}

/// What the host may do with a finished tool call.
///
/// `Run` carries no restored text. The host keeps the original arguments.
/// `Refuse` is the shell, network, GitHub, image, video, and MCP path:
/// an `h1_` prefix refuses the call, including a hex spelling of that
/// prefix, and nothing is interpolated.
#[derive(Debug, PartialEq, Eq)]
pub enum Judgment {
    Run { sink: Sink },
    RestoreAndRun { sink: Sink, restored: String },
    WriteRejected { sink: Sink, error: RestoreError },
    Refuse { sink: Sink },
}

/// Every tool name this crate classifies. A name that is not here leaves
/// the machine. The host's builtin list is checked against this table when
/// that tree is checked out beside this crate.
pub fn known_tool_sinks() -> &'static [(&'static str, Sink)] {
    TOOL_SINKS
}

const TOOL_SINKS: &[(&str, Sink)] = &[
    ("apply_fragment", Sink::LocalWrite),
    ("apply_patch", Sink::LocalWrite),
    ("apply_patch_file", Sink::LocalWrite),
    ("ask_user", Sink::Display),
    ("ast_deps", Sink::LocalRead),
    ("ast_diff", Sink::LocalRead),
    ("ast_impact", Sink::LocalRead),
    ("ast_list", Sink::LocalRead),
    ("ast_map", Sink::LocalRead),
    ("ast_read", Sink::LocalRead),
    ("ast_rename", Sink::LocalWrite),
    ("ast_search", Sink::LocalRead),
    ("ast_validate", Sink::LocalRead),
    ("code_mode", Sink::Shell),
    ("create_issue", Sink::LeavesMachine),
    ("delete_file", Sink::LocalWrite),
    ("doc_append", Sink::LocalWrite),
    ("doc_delete", Sink::LocalWrite),
    ("doc_delete_where", Sink::LocalWrite),
    ("doc_ensure", Sink::LocalWrite),
    ("doc_get", Sink::LocalRead),
    ("doc_has", Sink::LocalRead),
    ("doc_keys", Sink::LocalRead),
    ("doc_len", Sink::LocalRead),
    ("doc_merge", Sink::LocalWrite),
    ("doc_move", Sink::LocalWrite),
    ("doc_prepend", Sink::LocalWrite),
    ("doc_set", Sink::LocalWrite),
    ("doc_update", Sink::LocalWrite),
    ("edit_file", Sink::LocalWrite),
    ("browser_click", Sink::LeavesMachine),
    ("browser_evaluate", Sink::LeavesMachine),
    ("browser_navigate", Sink::LeavesMachine),
    ("browser_screenshot", Sink::LeavesMachine),
    ("browser_type", Sink::LeavesMachine),
    ("find_refs", Sink::LocalRead),
    ("get_agent_status", Sink::LocalRead),
    ("get_monitor_output", Sink::LocalRead),
    ("get_task_output", Sink::LocalRead),
    ("git_branch", Sink::LocalWrite),
    ("git_commit", Sink::LeavesMachine),
    ("git_diff", Sink::LocalRead),
    ("git_log", Sink::LocalRead),
    ("git_status", Sink::LocalRead),
    ("hashline_edit", Sink::LocalWrite),
    ("hashline_grep", Sink::LocalRead),
    ("hashline_read", Sink::LocalRead),
    ("image_edit", Sink::LeavesMachine),
    ("image_gen", Sink::LeavesMachine),
    ("image_resize", Sink::LocalWrite),
    ("image_to_video", Sink::LeavesMachine),
    ("image_upscale", Sink::LeavesMachine),
    ("index_definition", Sink::LocalRead),
    ("index_references", Sink::LocalRead),
    ("kill_task", Sink::LocalRead),
    ("list_dir", Sink::LocalRead),
    ("list_monitors", Sink::LocalRead),
    ("list_tasks", Sink::LocalRead),
    ("lsp_definition", Sink::LocalRead),
    ("lsp_diagnostics", Sink::LocalRead),
    ("lsp_hover", Sink::LocalRead),
    ("lsp_references", Sink::LocalRead),
    ("lsp_symbols", Sink::LocalRead),
    ("manage_memory", Sink::LocalWrite),
    ("mcp_manage", Sink::LeavesMachine),
    ("manage_skill", Sink::LocalWrite),
    ("md_insert_after", Sink::LocalWrite),
    ("md_insert_before", Sink::LocalWrite),
    ("md_lint", Sink::LocalRead),
    ("md_move_section", Sink::LocalWrite),
    ("md_replace_section", Sink::LocalWrite),
    ("md_table_append", Sink::LocalWrite),
    ("md_upsert_bullet", Sink::LocalWrite),
    ("notebook_edit", Sink::LocalWrite),
    ("patchloom_plan", Sink::LocalWrite),
    ("plan", Sink::LocalWrite),
    ("read_file", Sink::LocalRead),
    ("reflect", Sink::LocalRead),
    ("reference_to_video", Sink::LeavesMachine),
    ("rename_file", Sink::LocalWrite),
    ("replace_in_symbol", Sink::LocalWrite),
    ("run_background", Sink::Shell),
    ("run_command", Sink::Shell),
    ("scheduler_create", Sink::LocalWrite),
    ("scheduler_delete", Sink::LocalWrite),
    ("scheduler_list", Sink::LocalRead),
    ("search", Sink::LocalRead),
    ("semantic_search", Sink::LocalRead),
    ("start_monitor", Sink::Shell),
    ("spawn_agent", Sink::LocalWrite),
    ("stop_monitor", Sink::LocalRead),
    ("task_output", Sink::LocalRead),
    ("think", Sink::LocalRead),
    ("tidy", Sink::LocalWrite),
    ("tool_search", Sink::LocalRead),
    ("todo", Sink::LocalWrite),
    ("undo", Sink::LocalWrite),
    ("use_mcp_tool", Sink::LeavesMachine),
    ("update_goal", Sink::LocalWrite),
    ("video_upscale", Sink::LeavesMachine),
    ("web_fetch", Sink::LeavesMachine),
    ("web_llm_chat", Sink::LeavesMachine),
    ("web_search", Sink::LeavesMachine),
    ("write_file", Sink::LocalWrite),
    ("x_search", Sink::LeavesMachine),
];

pub fn classify(name: &str, mcp: bool) -> Sink {
    if mcp {
        return Sink::LeavesMachine;
    }
    TOOL_SINKS
        .iter()
        .find(|(tool, _)| *tool == name)
        .map(|(_, sink)| *sink)
        .unwrap_or(Sink::LeavesMachine)
}

/// Decide whether a finished tool call may run.
///
/// A local write gets the original bytes back. The token in the
/// arguments is not what the tool should write. A local read runs
/// with the arguments unchanged.
///
/// ```
/// use hushid::{judge, shield_text, Glossary, Judgment, Sink, Vault};
///
/// let mut vault = Vault::new();
/// let (token, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
/// let judgment = judge(&vault, "write_file", &token, false);
/// assert!(matches!(
///     judgment,
///     Judgment::RestoreAndRun {
///         sink: Sink::LocalWrite,
///         ref restored,
///     } if restored == "a@b.co"
/// ));
/// ```
pub fn judge(vault: &Vault, name: &str, arguments: &str, mcp: bool) -> Judgment {
    let sink = classify(name, mcp);
    match sink {
        Sink::LocalRead => Judgment::Run { sink },
        Sink::Display => Judgment::RestoreAndRun {
            sink,
            restored: vault.restore_display(arguments),
        },
        Sink::LocalWrite => match vault.restore_write(arguments) {
            Ok(restored) => Judgment::RestoreAndRun { sink, restored },
            Err(error) => Judgment::WriteRejected { sink, error },
        },
        Sink::Shell | Sink::LeavesMachine => {
            if arguments_carry_a_token(arguments) {
                Judgment::Refuse { sink }
            } else {
                Judgment::Run { sink }
            }
        }
    }
}

fn arguments_carry_a_token(arguments: &str) -> bool {
    if find_h1(arguments, 0).is_some() {
        return true;
    }
    let bytes = arguments.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_hexdigit() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        let run = &arguments[start..index];
        if run.len() < 8 || !run.len().is_multiple_of(2) {
            continue;
        }
        let Some(decoded) = decode_hex(run) else {
            continue;
        };
        if find_h1(&decoded, 0).is_some() {
            return true;
        }
    }
    false
}

fn decode_hex(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index + 1 < bytes.len() {
        let high = hex_value(bytes[index])?;
        let low = hex_value(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Restored copy for a permission check. Dropping it zeroes the bytes.
/// The copy is not the value that a shell or network tool runs.
pub struct Ephemeral {
    text: String,
}

impl Ephemeral {
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for Ephemeral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ephemeral(len={})", self.text.len())
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

pub fn permissions_view(vault: &Vault, text: &str) -> Ephemeral {
    Ephemeral {
        text: vault.restore_display(text),
    }
}

#[cfg(test)]
mod tests {
    use super::{judge, Judgment, Sink};
    use crate::glossary::Glossary;
    use crate::shield_text;
    use crate::token::find_h1;
    use crate::vault::Vault;

    #[test]
    fn a_shell_hex_of_a_token_is_refused() {
        let mut vault = Vault::new();
        let (token, _) = shield_text(&mut vault, &Glossary::empty(), "ada@example.com").unwrap();
        let hex: String = token.bytes().map(|byte| format!("{byte:02x}")).collect();
        let command = format!("python3 -c \"print(bytes.fromhex('{hex}').decode())\"");
        assert!(find_h1(&command, 0).is_none(), "{command}");
        assert!(
            matches!(
                judge(&vault, "run_command", &command, false),
                Judgment::Refuse { sink: Sink::Shell }
            ),
            "{command}"
        );
        let upper = command.replace(&hex, &hex.to_ascii_uppercase());
        assert!(matches!(
            judge(&vault, "run_command", &upper, false),
            Judgment::Refuse { sink: Sink::Shell }
        ));
    }

    #[test]
    fn a_shell_hex_of_the_clear_address_still_runs() {
        let vault = Vault::new();
        let email = "ada@example.com";
        let hex: String = email.bytes().map(|byte| format!("{byte:02x}")).collect();
        let command = format!("python3 -c \"print(bytes.fromhex('{hex}').decode())\"");
        assert!(matches!(
            judge(&vault, "run_command", &command, false),
            Judgment::Run { sink: Sink::Shell }
        ));
    }
}
