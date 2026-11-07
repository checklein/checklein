# Contributing to Checklein

Thanks for helping. A few ground rules keep the verifier trustworthy.

## Developer Certificate of Origin

Checklein uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/) instead of a CLA. Sign off every commit:

```bash
git commit -s
```

This adds a `Signed-off-by:` line certifying that you wrote the change, or otherwise have the right to submit it under Apache-2.0.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo run -q -p checklein-cli -- conformance vectors/web-bot-auth
```

## Rules for verifier code

- **No new credential formats.** Checklein implements public specs; it does not invent identity tokens.
- **Implement from public specs only.** Do not copy code published under proprietary terms (for example Visa's Trusted Agent Protocol repository).
- **Fail closed.** Unsupported components or parameters are rejected, never silently ignored.
- **Every behavior change ships with a conformance vector**, valid and invalid cases both.
- **No raw identifiers in receipts.** Digests, thumbprints and keyed hashes only.
