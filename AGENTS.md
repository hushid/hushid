# hushid

Library crate. It replaces direct identifiers it recognizes with typed tokens. A value no detector recognizes is left unchanged.

## Constraints

- No README, GitHub description, topics, homepage, social preview, badges, or FUNDING.yml.
- `publish = false`. Do not publish the crate.
- Do not describe this crate as anonymization, private mode, or Law 25 compliant.
- No Bline types. No `gaze-recognizers` dependency.
- Sign every commit with `git commit -s`. The sign-off email is `git config user.email`.

## Checks

```
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo deny check
```
