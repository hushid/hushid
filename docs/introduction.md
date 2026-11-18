# Hushid

Hushid replaces a direct identifier it recognizes with a typed token. The original bytes stay in a session vault and are copied back only when that vault is asked to restore a token it issued. A value no detector recognizes is left unchanged.

The token looks like `h1_<kind>_<8 characters><check>`. A secret-shaped value becomes `h1_secret` and is not stored, so it cannot be restored.

## What a detector recognizes

Email, a phone number with separators, a payment card, a SIN next to a cue, a RAMQ number, a postal code next to a cue, a civic address, and a birth date next to a cue. Names match only when the host loads a glossary.

## What stays as written

A city, a diagnosis, an account number with no recognized shape, a person who is not in the loaded glossary, and text inside an image or a PDF. The optional `ner` feature is off unless the host turns it on, and `shield_text` does not use it.

## Security and license

Report a vulnerability through [GitHub security advisories](https://github.com/hushid/hushid/security/advisories/new). The license is [Apache-2.0](https://github.com/hushid/hushid/blob/main/LICENSE).
