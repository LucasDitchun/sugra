## Summary

Describe the change and why it is needed.

## Safety and compatibility

- Target scope or active-capability impact:
- Report schema or CLI impact:
- Platform or dependency impact:

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] Relevant manual checks or fixtures are described below

## Checklist

- [ ] Tests use synthetic data and do not contact live targets by default
- [ ] No credentials, private target data, or generated run artifacts are included
- [ ] User-facing changes are documented
- [ ] A changelog entry is included when appropriate
