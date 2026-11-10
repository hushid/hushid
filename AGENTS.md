# hushid

Library crate. It replaces direct identifiers it recognizes with typed tokens. A value no detector recognizes is left unchanged.

## Constraints

- No README, GitHub description, topics, homepage, badges, or FUNDING.yml.
- The mark is `brand/ember.svg`. The org picture and the repository social preview are generated from that file. Do not replace them with a different image.
- `publish = false`. Do not publish the crate.
- Do not describe this crate as anonymization, private mode, or Law 25 compliant.
- No Bline types. No `gaze-recognizers` dependency.
- Sign every commit with `git commit -s`. The sign-off email is `git config user.email`.

## Checks

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```
