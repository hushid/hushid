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
/// any `h1_` prefix refuses the call, and nothing is interpolated.
#[derive(Debug, PartialEq, Eq)]
pub enum Judgment {
    Run { sink: Sink },
    RestoreAndRun { sink: Sink, restored: String },
    WriteRejected { sink: Sink, error: RestoreError },
    Refuse { sink: Sink },
}

pub fn classify(name: &str, mcp: bool) -> Sink {
    if mcp {
        return Sink::LeavesMachine;
    }
    match name {
        "read_file" | "list_dir" | "search" | "semantic_search" | "task_output"
        | "get_task_output" | "git_status" | "git_diff" | "git_log" | "git_show" | "git_blame"
        | "git_ls_files" => Sink::LocalRead,
        "edit_file" | "notebook_edit" | "apply_fragment" | "replace_in_symbol" | "ast_rename"
        | "write_file" | "hashline_edit" | "apply_patch" | "apply_patch_file" | "delete_file"
        | "rename_file" | "tidy" | "undo" | "manage_skill" | "manage_memory" | "plan" | "todo"
        | "update_goal" | "md_replace_section" | "md_upsert_bullet" | "md_table_append"
        | "md_insert_after" | "md_insert_before" | "md_move_section" | "doc_set" | "doc_ensure"
        | "doc_delete" | "doc_merge" | "doc_append" | "doc_prepend" | "doc_update" | "doc_move"
        | "doc_delete_where" => Sink::LocalWrite,
        "ask_user" => Sink::Display,
        "run_command" | "run_background" | "code_mode" => Sink::Shell,
        "web_search" | "web_fetch" | "create_issue" | "git_commit" | "image_gen" | "image_edit"
        | "image_to_video" | "reference_to_video" | "image_upscale" => Sink::LeavesMachine,
        _ => Sink::LeavesMachine,
    }
}

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
            if find_h1(arguments, 0).is_some() {
                Judgment::Refuse { sink }
            } else {
                Judgment::Run { sink }
            }
        }
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
