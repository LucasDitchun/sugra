# Sugra

Sugra is a typed, cross-platform security reconnaissance toolkit written in Rust. It offers a scriptable CLI and a full-screen terminal interface over the same catalog, safety policy, execution engine, evidence model, and reports.

The project is a clean Rust reimplementation inspired by the capabilities of [Argus](https://github.com/LucasDitchun/Argus). No source code or version history is shared between the projects.

## Principles

- Every scan has an explicit target and scope.
- Active capabilities require explicit authorization.
- Findings, evidence, failures, and partial results are distinct typed values.
- Network and provider boundaries are replaceable and testable offline.
- The core works on Linux, macOS, and Windows.
- JSON is the canonical report format; terminal, CSV, and HTML are projections.

## Build

```console
cargo build --workspace
cargo test --workspace
cargo run -p sugra-cli -- --help
```

Running `sugra` in a terminal opens the dashboard. In a pipe or redirected environment it prints concise help and exits without blocking.

## Safety

Use Sugra only on systems you own or are explicitly authorized to assess. Active HTTP, fuzzing, protocol probes, and local commands are denied by default. Read [SECURITY.md](SECURITY.md) before enabling them.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
