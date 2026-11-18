# Contributing

Hushid replaces a recognized identifier with a typed token. The original stays in a vault. An unrecognized value is left unchanged.

## Changes

Open a pull request against `main`. The pull request form asks for the change and the checks. Sign every commit with `git commit -s`. The sign-off email is `git config user.email`.

Do not publish the crate. `publish` stays `false`. Do not add a homepage or `FUNDING.yml`. Do not add a README badge that does not resolve. The passing badges are CI, Security, Coverage, the GitHub release, the Apache-2.0 license, Scorecard, FOSSA, and OpenSSF Best Practices.

Do not describe the crate as anonymization, private mode, or Law 25 compliant. Do not add a Bline type or a `gaze-recognizers` dependency.

The mark is `brand/ember.svg`. The org picture is `brand/ember-avatar.svg`. Do not replace either with a different image.

## Checks

Rust 1.87 or newer.

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --locked --features ner
cargo +1.87.0 test --workspace --locked
cargo +1.87.0 test --workspace --locked --features ner
cargo deny check
```

A vulnerability report goes through [GitHub security advisories](https://github.com/hushid/hushid/security/advisories/new), not a public issue. See [SECURITY.md](SECURITY.md).
