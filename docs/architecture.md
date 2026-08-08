# Architecture

Sugra uses a six-crate workspace with one-way dependency boundaries:

```text
sugra-domain
  <- sugra-core
      <- sugra-adapters
      <- sugra-scanners
      <- sugra-tui
      <- sugra-cli
```

The domain contains immutable values and state transitions without I/O. Core owns catalog validation, scope policy, execution planning, scheduling, reporting, and storage ports. Adapters implement DNS, HTTP, TLS, registry, provider, and protocol boundaries. Scanner modules compose those ports into typed observations. CLI and TUI are presentation edges over shared application services.

The catalog is compiled and validated. Dynamic code loading is intentionally excluded from the first stable architecture. A compatibility selector translates published Argus IDs at the CLI boundary without affecting canonical identities.

Each run produces a versioned JSON manifest and report. CSV and HTML are deterministic projections. Active operations cannot reach an adapter until scope and authorization policy succeeds.
