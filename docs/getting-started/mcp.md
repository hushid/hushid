# MCP

From a clone of this repository, `hushid-mcp` reads MCP frames on stdin and writes frames on stdout. `HUSHID_VAULT_DIR` is required. `HUSHID_GLOSSARY` is optional.

```text
HUSHID_VAULT_DIR=DIR cargo run -p hushid-proxy --bin hushid-mcp
```

Each request is one frame. The header carries `Content-Length`. The name is accepted in any case, and space around the colon is ignored. The body is capped at 1 MiB before it is allocated. A clean end of stdin before any byte exits 0.

The tools are `shield` and `restore`. `shield` uses `shield_text`. A JSON object or array passed to it is shielded as JSON, so a recognized number becomes a quoted token. That includes a 13 to 19 digit JSON number that passes the card check, with no nearby word. `restore` copies back tokens this vault issued. When that text is a JSON object or array, a number token becomes digits again. `h1_secret` stays the mark, and the secret is not copied back. A token minted with `Forget` stays in the text. An `h1_` token this vault did not mint is an error.

| What happened | Process |
|---|---|
| `HUSHID_VAULT_DIR` is missing | Exits 2 and prints `missing HUSHID_VAULT_DIR` |
| The glossary file cannot be read | Exits 2 and prints `glossary` and the path |
| The frame is too long, is not UTF-8, has a bad or oversized length, or the body is short | Exits 1 and prints `frame` |
| The response cannot be written | Exits 1 and prints `client` |
