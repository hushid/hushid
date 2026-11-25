# Replace and restore

```rust
use hushid::{shield_text, Glossary, Vault};

let mut vault = Vault::new();
let (shielded, _) =
    shield_text(&mut vault, &Glossary::empty(), "Write ada@example.com").unwrap();
let restored = vault.restore_write(&shielded).unwrap();
assert_eq!(restored, "Write ada@example.com");
```

`Glossary::empty()` matches no names. A host that wants the optional name list passes the path `glossary/popular-names.txt` to `Glossary::load`. That file is not loaded on its own. A UTF-8 BOM at the start of a line is ignored.

`shield_text` writes tokens. When the whole text is a JSON object or array, it uses the JSON shield, so a recognized number becomes a quoted token and a later shield of that number reuses it. A JSON number of 13 to 19 digits that passes the card check is recognized without a nearby word, including in an array and beside another number. The same digits in prose, or in a JSON string, still need that word or separators. Prose stays on the text shield. `shield_text_with` can write digit stand-ins or a same-kind stand-in instead. Those stand-ins restore to the original bytes as well. `Operator::Forget` writes a token and does not store the original. A local write of that token fails. A reply keeps the token and still restores a stored token. A mask is for a display or a log and is not restored. `shield_json_strings` stores tokens. `shield_json_strings_with` takes the same operators, including `Operator::Forget`.
