# Host

`shield_text` returns the rewritten text and an `AuditRecord`. The record counts each kind. It does not contain the original values, so a log can say how many emails were replaced without writing the addresses.

`shield_json_strings` walks string values in a JSON document, including a string that is itself JSON. It uses `Operator::Token` and stores a reversible value. A JSON number becomes a quoted token, and a later shield of that number reuses it. A JSON number of 13 to 19 digits that passes the card check is that number, including when another number is present and when the number sits in an array. The same digits in a JSON string still need a cue or separators. `Operator::Digits` and `Operator::Surrogate` keep that one number token too. A token stored for the same digits as a string is not reused. `shield_text` and `Session::shield_message` use that JSON shield when the whole message is a JSON object or array. Prose stays on the text shield. `shield_json_strings_with` accepts an operator. `Operator::Forget` writes `h1_<kind>_` and does not store the original, including a recognized phone, card, or SIN written as a JSON number. A second call mints another token. Two copies in one call share one token. `restore_json_write` of that token fails. A reply keeps it. The chat proxy stays on `shield_json_strings`. A key that names an API-key assignment is replaced with `h1_secret` and is not stored. A number or a key that no detector recognizes stays as it is. `restore_json_write` fails when an `h1_` token is still unresolved. `restore_json_reply` is what the chat proxy uses for a model reply: issued tokens come back, `h1_secret` stays the mark, and a forgotten token stays in the text. The chat proxy joins event-stream `delta` content values before that call, so a token split across those values is restored. A token this vault did not mint still fails. The MCP `restore` tool uses that JSON reply when the text is a JSON object or array, so a number token becomes digits again. Other text uses `restore_reply`. The MCP `shield` tool uses `shield_text`.

`judge` decides what a finished tool call may do with those tokens.

| Call | Result |
|---|---|
| A local read | Runs. The arguments stay as they are. |
| A display | Runs after `restore_display`. |
| A local write, such as `write_file` | Runs with the original bytes. The token is not what the tool should write. |
| A local write that still contains `h1_secret`, a forgotten token, or an `h1_` token this vault did not mint | Rejected. |
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
