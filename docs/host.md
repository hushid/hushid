# Host

`shield_text` returns the rewritten text and an `AuditRecord`. The record counts each kind. It does not contain the original values, so a log can say how many emails were replaced without writing the addresses.

`shield_json_strings` walks string values in a JSON document, including a string that is itself JSON. It uses `Operator::Token` and stores a reversible value. `shield_json_strings_with` accepts an operator. `Operator::Forget` writes `h1_<kind>_` and leaves the vault empty, including a recognized phone, card, or SIN written as a JSON number. A second call mints another token. Two copies in one call share one token. `restore_json_write` of that token fails. The chat proxy stays on `shield_json_strings`. A key that names an API-key assignment is replaced with `h1_secret` and is not stored. A number or a key that no detector recognizes stays as it is. `restore_json_write` fails when an `h1_` token is still unresolved. `restore_json_reply` is what the chat proxy uses for a model reply: issued tokens come back, and `h1_secret` stays the mark. The MCP `restore` tool uses `restore_reply` the same way.

`judge` decides what a finished tool call may do with those tokens.

| Call | Result |
|---|---|
| A local read | Runs. The arguments stay as they are. |
| A display | Runs after `restore_display`. |
| A local write, such as `write_file` | Runs with the original bytes. The token is not what the tool should write. |
| A local write that still contains `h1_secret` or an unknown `h1_` token | Rejected. |
| A shell, or a call that leaves the machine | Refused when the arguments contain `h1_`, including a hex spelling of that prefix. |
| A tool name this crate does not list | Treated as leaving the machine. |
| An MCP call | Treated as leaving the machine. |

```rust
use hushid::{judge, shield_text, Glossary, Judgment, Sink, Vault};

let mut vault = Vault::new();
let (token, _) = shield_text(&mut vault, &Glossary::empty(), "a@b.co").unwrap();
let judgment = judge(&vault, "write_file", &token, false);
assert!(matches!(
    judgment,
    Judgment::RestoreAndRun {
        sink: Sink::LocalWrite,
        ref restored,
    } if restored == "a@b.co"
));
```
