# Chat proxy

From a clone of this repository, `hushid-proxy` listens on `127.0.0.1:8078` unless `--listen` is set. On Windows, `localhost` listens on `127.0.0.1` and `::1`. It shields a chat request, forwards it to `--upstream`, and restores tokens in the response. The session header is `X-Hushid-Session`.

```text
cargo run -p hushid-proxy -- --upstream URL --vault-dir DIR
```

`--glossary FILE` is optional. `HUSHID_VAULT_DIR` and `HUSHID_GLOSSARY` are the same settings as environment variables.

The only path is `POST /v1/chat/completions`. The body is read up to 1 MiB. A redirect is not followed. The proxy does not forward the body until the request has been read.

| What happened | Response |
|---|---|
| No `X-Hushid-Session` | HTTP 400 `{"error":"missing session"}` |
| A session name the vault rejects, including one that would open another session's file on a case-insensitive volume | HTTP 400 `{"error":"bad session"}` |
| A bad header, a bad `Content-Length`, or a carriage return in `Authorization` | HTTP 400 `{"error":"headers"}` or `{"error":"length"}`. The process stays up. A line break in the upstream URL is HTTP 502 `{"error":"upstream"}` before the proxy opens a socket. The process stays up. |
| A bad chunk, or a body that is not UTF-8 | HTTP 400 `{"error":"body"}`. The process stays up. |
| The vault file cannot be read or written | HTTP 500 `{"error":"vault"}` |
| The upstream dial or write fails | HTTP 502 `{"error":"upstream"}` |
| The reply quotes `h1_secret` | HTTP 200. That mark stays, other tokens are restored, and the secret is not copied back. |
| The reply quotes a token minted with `Forget` | HTTP 200. That token stays, and a stored token in the same reply is restored. |
| The upstream names a content type | That type is kept. An event stream stays `text/event-stream`. A missing or unsafe type is `application/json`. |
| The upstream status is `429 Too Many Requests` | The same status line is returned. A token in that body is restored. |
| The reply contains an `h1_` token this vault did not mint | HTTP 502 `{"error":"restore"}`. The unrestored body is not forwarded. |
