# Chat proxy

From a clone of this repository, `hushid-proxy` listens on `127.0.0.1:8078` unless `--listen` is set. It shields a chat request, forwards it to `--upstream`, and restores tokens in the response. The session header is `X-Hushid-Session`.

```text
cargo run -p hushid-proxy -- --upstream URL --vault-dir DIR
```

`--glossary FILE` is optional. `HUSHID_VAULT_DIR` and `HUSHID_GLOSSARY` are the same settings as environment variables.
