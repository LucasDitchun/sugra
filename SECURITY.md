# Security policy

## Supported versions

Security fixes are applied to the latest release line. Pre-release builds and unreleased source may
change without notice. Upgrade to the newest patched release before reporting an issue that might
already have been addressed.

## Report a vulnerability

Use GitHub private vulnerability reporting for the Sugra repository. Do not open a public issue,
discussion, or pull request for a vulnerability that could expose users, credentials, or assessed
targets.

Include, when available:

- the affected version, operating system, and installation method;
- reproduction conditions and the smallest safe proof;
- expected and observed behavior;
- impact, affected boundaries, and suggested mitigations;
- whether the report contains information that needs special handling.

Never include real credentials or data taken from systems you do not own. Maintainers will
acknowledge the report, validate its impact, coordinate a fix, and agree on disclosure timing through
the private report. Please allow a reasonable remediation period before public disclosure.

## Security model

Sugra validates target type and exact scope before execution. Capabilities that can make active HTTP
requests, fuzz, probe protocols, or execute local commands require `--authorize-active`. The flag is
a safety boundary and an audit signal; it is not proof of permission from a target owner.

Runs also apply explicit time, request, response-size, depth, and concurrency budgets. Redirects and
resolved endpoints are checked against scope. TLS certificate verification is enabled by default and
cannot be disabled through ordinary scan options.

Provider credentials are read from environment variables at the adapter boundary. They must be
redacted before persistence and must never appear in reports, logs, fixtures, command lines, or issue
attachments. Canonical reports may still contain sensitive reconnaissance data; store and share them
accordingly.

## Out of scope

The following are not project vulnerabilities by themselves:

- findings about a third-party target produced during an authorized scan;
- provider downtime, quota enforcement, or upstream data inaccuracies;
- use of Sugra without the target owner's authorization;
- attacks that require a user to execute an untrusted binary or deliberately expose a report.

Reports showing a bypass of scope, authorization, redaction, TLS verification, resource budgets, or
safe persistence are in scope and are especially valuable.
