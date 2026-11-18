# Vault

The vault is the map from a token back to the original bytes. `Vault::new` starts empty. `Vault::save` writes that map to a file as mode `0600` on Unix. `Vault::load` reads it back.

```rust
use hushid::Vault;
use std::path::Path;

let mut vault = Vault::new();
vault.save(Path::new("session.vault")).unwrap();
let loaded = Vault::load(Path::new("session.vault")).unwrap();
```

Keep that file with the session that issued the tokens. Leave it out of a support bundle and out of a share export. Anyone who can read the file can read the identifiers.

Restore copies the original back only for a token this vault issued. As long as the file exists, those bytes can be copied back. Deleting the file drops them. A restorable token means the identifier is still in the vault.
