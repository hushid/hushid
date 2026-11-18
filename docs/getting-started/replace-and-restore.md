# Replace and restore

```rust
use hushid::{shield_text, Glossary, Vault};

let mut vault = Vault::new();
let (shielded, _) =
    shield_text(&mut vault, &Glossary::empty(), "Write ada@example.com").unwrap();
let restored = vault.restore_write(&shielded).unwrap();
assert_eq!(restored, "Write ada@example.com");
```

`Glossary::empty()` matches no names. A host that wants the optional name list passes the path `glossary/popular-names.txt` to `Glossary::load`. That file is not loaded on its own.

`shield_text` writes tokens. `shield_text_with` can write digit stand-ins or a same-kind stand-in instead. Those stand-ins restore to the original bytes as well. A mask is for a display or a log and is not restored.
