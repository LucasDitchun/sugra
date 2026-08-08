# Contributing

Thank you for improving Sugra.

1. Open an issue describing the behavior and safety impact.
2. Keep domain logic independent from network, filesystem, terminal, and clock implementations.
3. Add deterministic tests with synthetic fixtures. Live network tests must be opt-in.
4. Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features`.
5. Use a conventional commit subject such as `feat: add DNS CAA inspection`.

New scanners need a stable descriptor, declared targets and capabilities, typed options, a success fixture, an edge case, an adapter failure test, and a safety-policy test.
