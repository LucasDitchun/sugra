# Contributing to Sugra

Thank you for helping improve Sugra. Contributions that preserve explicit scope, bounded execution,
deterministic evidence, and cross-platform behavior are welcome.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). For vulnerabilities
or unsafe behavior that could expose users or targets, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

## Before you start

- Search existing issues and pull requests before proposing a change.
- Open an issue for significant behavior, architecture, scanner, or safety changes.
- Keep live targets, credentials, and sensitive output out of issues, fixtures, and commits.
- Use only systems you own or are explicitly authorized to assess while developing.

Small documentation, test, and focused bug fixes can go directly to a pull request.

## Development setup

Install Rust through rustup, clone the repository, and let `rust-toolchain.toml` select the supported
toolchain. The minimum supported Rust version (MSRV) is 1.94.

```console
git clone https://github.com/LucasDitchun/sugra.git
cd sugra
cargo build --workspace --all-features
cargo test --workspace --all-features
```

Tests must be deterministic and use synthetic fixtures. Live network tests must be opt-in and must
never run in the default test suite.

## Required checks

Run these commands before requesting review:

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features --release
cargo audit
cargo deny check
```

Continuous integration repeats the relevant checks on Linux, macOS, and Windows and checks the MSRV
separately. New or changed business logic should include enough focused tests to keep at least 80%
coverage for that logic where it can be measured meaningfully.

## Scanner requirements

A new scanner must include:

- a stable canonical descriptor and compatibility identity where applicable;
- declared target kinds, capabilities, options, and bounded default budgets;
- a successful synthetic fixture and at least one edge case;
- adapter-failure and cancellation behavior;
- a safety-policy test for every active capability;
- deterministic findings, evidence, and user-safe errors;
- provider attribution when external data contributes to a finding.

Keep domain logic independent from network, filesystem, terminal, process, and clock implementations.
Validate all external input at those boundaries and never include credentials in evidence or logs.

## Commits and pull requests

Use a conventional commit subject such as `feat: add DNS CAA inspection` or
`fix: preserve redirect scope`. Keep commits focused and avoid unrelated formatting changes.

Open feature, fix, documentation, dependency, and CI pull requests against `develop`. The `main`
branch is release-only and changes exclusively through the draft release train from `develop`.
Do not open ordinary pull requests against `main`.

A pull request should explain:

- what changed and why;
- safety or compatibility effects;
- tests and manual checks performed;
- any user-facing, report-schema, or dependency changes.

Maintainers may ask for a changelog entry when a change affects users. Reviews focus on correctness,
safety, deterministic behavior, platform compatibility, and maintainability.

## Releases and versioning

The draft `develop` to `main` pull request accumulates accepted changes without publishing each
feature separately. When a batch is ready, a maintainer runs the **Prepare release** workflow on
`develop`. The workflow calculates the next version, updates `Cargo.toml`, `Cargo.lock`, and
`CHANGELOG.md`, and dispatches fresh CI, security, and cargo-dist dry-run checks. The pull request
remains a draft until a maintainer deliberately marks it ready.

Before 1.0.0, Sugra follows this ZeroVer policy:

- backward-compatible feature and fix batches increment patch once, regardless of commit count;
- breaking API, schema, or architecture batches increment minor;
- maintainers may explicitly select patch, minor, or major for an exceptional release.

Starting at 1.0.0, automatic calculation follows standard semantic versioning: fixes increment
patch, compatible features increment minor, and breaking changes increment major. Merging the
release train is the only supported mutation of `main`; it automatically dispatches the generated
cargo-dist workflow, which creates the tag, GitHub Release, installers, checksums, and archives.
