# hushid

Library crate. It replaces direct identifiers it recognizes with typed tokens. A value no detector recognizes is left unchanged.

## Constraints

- No README, GitHub description, topics, homepage, badges, or FUNDING.yml.
- The mark is `brand/ember.svg`. The repository social preview is generated from that file. The org picture is `brand/ember-avatar.svg`, that mark filling a square. Do not replace either with a different image.
- `publish = false`. Do not publish the crate.
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
cargo +1.85.0 test --workspace --locked
cargo +1.85.0 test --workspace --locked --features ner
cargo deny check

CI also runs the `token` and `json_restore` fuzz targets on nightly for 10 seconds each. Locally, put nightly first on `PATH`, then `cargo fuzz run token -- -max_total_time=10` and the same for `json_restore`.

Pull requests also run CodeQL for Rust and Actions, and `cargo llvm-cov`. Those checks do not run again when the pull request is merged. Scorecard and release-please still run on the default branch. FOSSA runs on a pull request that changes the lockfile, the sources, or its workflow, and again on Monday. A release pull keeps the required check names and skips the test suite, the fuzzer, coverage, and CodeQL. Do not add a badge for any of these.

release-please opens the version pull. Do not merge that pull unless this chat names it and says yes. The crate stays unpublished.
```
