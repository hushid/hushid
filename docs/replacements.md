# Replacements

`shield_text` uses `Operator::Token`. The other operators are `shield_text_with`.

| Operator | What you see | Restore |
|---|---|---|
| `Token` | `h1_<kind>_<8 characters><check>`, for example a token that starts with `h1_email_` | The original bytes, when this vault issued the token |
| `Digits` | Another number of the same shape, for a phone, a card, or a SIN. Other kinds still use a token. | The original bytes |
| `Surrogate` | A stand-in of the same kind, so the sentence still reads | The original bytes |
| `Mask` | A fixed pattern: `***@***`, `***-***-****`, `**** **** **** ****`, `*** *** ***`, `**** **** ****`, `*** ***`, or `***` | Nothing. The original is not stored. Two emails in one sentence become the same stars. |
| `Forget` | The same `h1_<kind>_<8 characters><check>` shape as `Token` | Nothing. The original is not stored. The same bytes share one token inside the call. A later call mints another, and a token already in the vault is not reused. |

A secret is not one of those operators. Every recognized secret becomes the same mark, `h1_secret`. Nothing is stored, so restore cannot recover it.

A repeat of the same address inside one `shield_text` call gets its own token. A later call that sees an address already in the vault reuses the token that was stored first.

`restore_write` fails when the text contains `h1_secret` or an `h1_` token this vault did not issue. The check character has to match. A token from another vault is not restored.
