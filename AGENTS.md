# hushid

Library crate. It replaces direct identifiers it recognizes with typed tokens. A value no detector recognizes is left unchanged.

## Constraints

- `README.md` is the public page. The GitHub description is set, and the topics are `rust` and `identifiers`. The README shows the ember mark and the CI, Security, Coverage, release, crates.io, license, Scorecard, FOSSA, OpenSSF Best Practices, docs, and docs.rs badges. The Best Practices project id is 16867. Scorecard uses the public API shield. FOSSA uses the workflow badge for a push run. The GitHub homepage is `https://hushid.github.io/hushid/`, the mdBook in `docs/`. FUNDING.yml stays unset. Do not `cargo publish` from a laptop. A release tag publishes the `hushid` crate from `.github/workflows/publish-crates.yml`. `hushid-proxy` stays `publish = false`. Do not merge a release pull unless this chat names it and says yes.
- The mark is `brand/ember.svg`. The repository social preview is generated from that file. The org picture is `brand/ember-avatar.svg`, that mark filling a square. Do not replace either with a different image.
- The `hushid` crate is published to crates.io when a release tag is pushed. `hushid-proxy` stays unpublished.
- Do not describe this crate as anonymization, private mode, or Law 25 compliant.
- No Bline types. No `gaze-recognizers` dependency.
- Sign every commit with `git commit -s`. The sign-off email is `git config user.email`.
- The optional name list is `glossary/popular-names.txt`. It is not loaded unless the host sets `glossary` to that path.

## Checks

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --locked --features ner
cargo +1.87.0 test --workspace --locked
cargo +1.87.0 test --workspace --locked --features ner
cargo deny check

CI also runs the `token` and `json_restore` fuzz targets on nightly for 10 seconds each. Locally, put nightly first on `PATH`, then `cargo fuzz run token -- -max_total_time=10` and the same for `json_restore`.

Pull requests also run CodeQL for Rust and Actions, and `cargo llvm-cov`. Those checks do not run again when the pull request is merged. Scorecard and release-please still run on the default branch. FOSSA runs on a pull request that changes the lockfile, the sources, or its workflow, and again on Monday. A release pull keeps the required check names and skips the test suite, the fuzzer, coverage, and CodeQL. The README already links CI, Security, and Coverage. Do not add a second badge for the same check.

release-please opens the version pull. Do not merge that pull unless this chat names it and says yes. A merged release publishes `hushid` to crates.io. `hushid-proxy` stays unpublished.
```
