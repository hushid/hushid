# MCP

From a clone of this repository, `hushid-mcp` reads MCP frames on stdin and writes frames on stdout. `HUSHID_VAULT_DIR` is required. `HUSHID_GLOSSARY` is optional.

```text
HUSHID_VAULT_DIR=DIR cargo run -p hushid-proxy --bin hushid-mcp
```

Each request is one frame. The header carries `Content-Length`. The name is accepted in any case, and space around the colon is ignored. The body is capped at 1 MiB before it is allocated. A clean end of stdin before any byte exits 0.

The tools are `shield` and `restore`. `restore` copies back tokens this vault issued. `h1_secret` stays the mark, and the secret is not copied back. An unknown `h1_` token is an error.

| What happened | Process |
|---|---|
| `HUSHID_VAULT_DIR` is missing | Exits 2 and prints `missing HUSHID_VAULT_DIR` |
| The glossary file cannot be read | Exits 2 and prints `glossary` and the path |
| The frame is too long, is not UTF-8, has a bad or oversized length, or the body is short | Exits 1 and prints `frame` |
| The response cannot be written | Exits 1 and prints `client` |
