## Summary

<!-- What does this change and why? Link the issue it addresses (Fixes #123). -->

## Verification

<!-- Check what you ran, and say on which kernel (uname -r) and architecture. -->

- [ ] `cargo build`
- [ ] `cargo test --workspace`
- [ ] `cargo xtask test-e2e` (required for changes to tracing, attribution or reporting)
- [ ] Added or updated tests (unit tests, or an e2e scenario documented in AGENTS.md)
- [ ] Updated AGENTS.md, README.md and CHANGELOG.md (`[Unreleased]`) where behavior changed

Kernel and architecture tested:

## Report schema impact

<!-- whytime.report/1 accepts additive changes only (new optional fields, new class values). -->

- [ ] No change to the `--json` report
- [ ] Additive change to `whytime.report/1` (field reference in AGENTS.md updated)
- [ ] Breaking change (requires `whytime.report/2`; discussed in an issue first)

Trace file format or record ABI changed (old trace files will no longer replay): yes / no
