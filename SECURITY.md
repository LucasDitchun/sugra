# Security policy

## Supported versions

Security fixes are applied to the latest release line.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting. Do not open a public issue for a vulnerability that could expose users or targets.

Include the affected version, reproduction conditions, impact, and a minimal proof. Never include real credentials or data from systems you do not own.

## Operating model

Sugra denies active capabilities unless the operator supplies an explicit scope and authorization flag. This control is a safety boundary, not proof that an assessment is legally permitted. The operator remains responsible for authorization.

Secrets are read from environment variables, redacted before persistence, and never included in support bundles. TLS verification is enabled by default and cannot be disabled through ordinary scan options.
