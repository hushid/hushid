<p align="center">
  <img src="brand/ember.svg" alt="Hushid" width="420">
</p>

# Hushid

[![CI](https://github.com/hushid/hushid/actions/workflows/ci.yml/badge.svg?event=pull_request)](https://github.com/hushid/hushid/actions/workflows/ci.yml)
[![Security](https://github.com/hushid/hushid/actions/workflows/security.yml/badge.svg?event=pull_request)](https://github.com/hushid/hushid/actions/workflows/security.yml)
[![Coverage](https://github.com/hushid/hushid/actions/workflows/coverage.yml/badge.svg?event=pull_request)](https://github.com/hushid/hushid/actions/workflows/coverage.yml)
[![Release](https://img.shields.io/github/v/release/hushid/hushid?logo=github&sort=semver)](https://github.com/hushid/hushid/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hushid/hushid/badge)](https://securityscorecards.dev/viewer/?uri=github.com/hushid/hushid)
[![FOSSA Status](https://github.com/hushid/hushid/actions/workflows/fossa.yml/badge.svg?event=push)](https://github.com/hushid/hushid/actions/workflows/fossa.yml)

Hushid replaces a direct identifier it recognizes with a typed token. The original bytes stay in a session vault and are copied back only when that vault is asked to restore a token it issued. A value no detector recognizes is left unchanged.

The token looks like `h1_<kind>_<8 characters><check>`. A secret-shaped value becomes `h1_secret` and is not stored, so it cannot be restored.

## Add it to a crate

The crate is not published to crates.io. Depend on a tag:

```toml
[dependencies]
hushid = { git = "https://github.com/hushid/hushid", tag = "hushid-v0.1.3" }
```

Rust 1.87 or newer.

## Replace and restore

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

## What a detector recognizes

Email, a phone number with separators, a payment card, a SIN next to a cue, a RAMQ number, a postal code next to a cue, a civic address, and a birth date next to a cue. Names match only when the host loads a glossary.

## What stays as written

A city, a diagnosis, an account number with no recognized shape, a person who is not in the loaded glossary, and text inside an image or a PDF. The optional `ner` feature is off unless the host turns it on, and `shield_text` does not use it.

## Chat proxy

From a clone of this repository, `hushid-proxy` listens on `127.0.0.1:8078` unless `--listen` is set. It shields a chat request, forwards it to `--upstream`, and restores tokens in the response. The session header is `X-Hushid-Session`.

```text
cargo run -p hushid-proxy -- --upstream URL --vault-dir DIR
```

`--glossary FILE` is optional. `HUSHID_VAULT_DIR` and `HUSHID_GLOSSARY` are the same settings as environment variables.

## MCP

From a clone of this repository, `hushid-mcp` reads MCP frames on stdin and writes frames on stdout. `HUSHID_VAULT_DIR` is required. `HUSHID_GLOSSARY` is optional.

```text
HUSHID_VAULT_DIR=DIR cargo run -p hushid-proxy --bin hushid-mcp
```

## Security

Report a vulnerability through [GitHub security advisories](https://github.com/hushid/hushid/security/advisories/new). See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
