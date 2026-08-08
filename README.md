# Sugra

[![CI](https://github.com/LucasDitchun/sugra/actions/workflows/ci.yml/badge.svg)](https://github.com/LucasDitchun/sugra/actions/workflows/ci.yml)
[![Security](https://github.com/LucasDitchun/sugra/actions/workflows/security.yml/badge.svg)](https://github.com/LucasDitchun/sugra/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-orange.svg)](rust-toolchain.toml)

Sugra is a typed, cross-platform security reconnaissance toolkit written in Rust. Its CLI and
full-screen terminal interface share the same scanner catalog, scope policy, execution engine,
evidence model, and deterministic reports.

> [!WARNING]
> Use Sugra only on systems you own or are explicitly authorized to assess. Some scanners make
> active network requests or invoke local tools. Active capabilities are denied unless the operator
> supplies `--authorize-active`; that flag records intent but does not grant legal permission.

Sugra is under active development. The report schema and command-line interface may change before
the first stable release.

## Highlights

- 147 bounded scanners address DNS, TLS, HTTP, routing, asset discovery, and threat intelligence.
- Canonical, numeric, and supplemental scanner identifiers keep catalog references stable.
- Exact target scope, operation budgets, timeouts, response limits, and cancellation constrain runs.
- JSON is the canonical persisted report; terminal, CSV, and self-contained HTML are projections.
- Network, provider, filesystem, terminal, process, and clock boundaries are replaceable for tests.
- Linux, macOS, and Windows are exercised in continuous integration.

## Install

Prebuilt archives and SHA-256 checksums are attached to versioned GitHub releases for supported
platforms. Shell and PowerShell installers are also generated for each release. Until a release is
available, build from source:

```console
git clone https://github.com/LucasDitchun/sugra.git
cd sugra
cargo install --locked --path crates/sugra-cli
sugra --help
```

Building requires Rust 1.94 or newer. The checked-in toolchain file installs the supported compiler,
formatter, and linter when the repository is used through rustup.

## Quick start

Browse the catalog and inspect a scanner contract before running it:

```console
sugra catalog
sugra info http-security
sugra scan http-security https://example.com
```

Write a JSON projection to standard output without persisting a run:

```console
sugra scan dns-records example.com --format json --no-persist
```

Run a curated group and explicitly authorize any active capabilities it contains:

```console
sugra preset web https://example.com --authorize-active
```

By default, canonical reports are written once beneath `sugra-runs/<run-id>/report.json`. They can be
listed and rendered later:

```console
sugra history
sugra report sugra-runs/<run-id>/report.json --format html > report.html
```

Running `sugra` in an interactive terminal opens the dashboard. Use `sugra tui` to request it
explicitly. In a pipe or redirected environment, the command prints help and exits rather than
blocking for input.

## Credentials and external services

Scanners backed by third-party services read credentials only from environment variables. A missing
credential produces an unavailable result rather than embedding a secret in configuration.

| Service | Environment variable |
| --- | --- |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| Censys | `CENSYS_API_TOKEN` |
| Cloudflare Radar | `CLOUDFLARE_API_TOKEN` |
| Have I Been Pwned | `HIBP_API_KEY` |
| IPinfo | `IPINFO_API_KEY` |
| OTX | `OTX_API_KEY` |
| Shodan | `SHODAN_API_KEY` |
| URLhaus | `URLHAUS_AUTH_KEY` |
| VirusTotal | `VIRUSTOTAL_API_KEY` |

Not every provider-backed scanner requires a credential. Provider terms, quotas, availability, and
data licenses remain under the provider's control; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Development

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features --release
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for scanner requirements and pull request guidance. Security
issues belong in the private reporting channel described in [SECURITY.md](SECURITY.md).

## Origins and license

Sugra is an independent Rust implementation inspired by the publicly documented capabilities of
[Argus](https://github.com/LucasDitchun/Argus). It does not share source code or version history with
that project.

Sugra is licensed under the [MIT License](LICENSE). Third-party components and services retain their
respective terms; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
