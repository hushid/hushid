# Contributing

Hushid replaces a recognized identifier with a typed token. The original stays in a vault. An unrecognized value is left unchanged.

## Changes

Open a pull request against `main`. The pull request form asks for the change and the checks. Sign every commit with `git commit -s`. The sign-off email is `git config user.email`.

Do not run `cargo publish` yourself. A release publishes the `hushid` crate. Leave `hushid-proxy` unpublished. The homepage is the mdBook in `docs/`. Do not add a second site or `FUNDING.yml`. Do not add a README badge that does not resolve. The passing badges are CI, Security, Coverage, the GitHub release, crates.io, the Apache-2.0 license, Scorecard, FOSSA, OpenSSF Best Practices, the docs site, and docs.rs.

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
