# Scanner contract

Every scanner declares:

- a stable canonical ID and optional compatibility ID;
- supported target types;
- required capabilities and optional dependencies;
- typed option definitions and defaults;
- a versioned implementation;
- deterministic behavior under synthetic adapters.

Execution returns a typed result with status, findings, evidence, and safe diagnostics. An unavailable dependency is not a negative finding. Partial results preserve valid evidence from successful boundaries.

The required test set is a positive fixture, a meaningful edge case, an adapter failure, target and option validation, and safety-policy coverage. Network access is disabled in the default test suite.
