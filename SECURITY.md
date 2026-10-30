# Security Policy

Report suspected vulnerabilities in any part of Threat Model Forge, including its source code,
scripts, dependencies, packages, and integrations.

## Reporting a Vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/Hacks4Snacks/tmforge/security/advisories/new)
to contact the maintainers. Do not post vulnerability details, exploit code, credentials, or
confidential threat models in public issues, discussions, or pull requests.

Include:

- The affected version or commit, platform, and deployment or integration involved.
- Reproduction steps and a minimal, sanitized example or proof of concept.
- The expected and observed behavior, security impact, and any required access or configuration.
- Relevant logs with secrets and confidential architecture removed.

Test only systems you own or are authorized to assess. Prefer a local instance and synthetic model;
do not use other people's data or disrupt shared services to demonstrate an issue.

## Supported Versions

Security fixes target the latest stable release. Older releases and development builds do not have
guaranteed security maintenance. Where possible, reproduce the issue on the latest stable release
and include the versions you tested.

## Response and Disclosure

Maintainers assess reports according to their impact and may request additional evidence. Updates,
remediation, and disclosure timing are coordinated through the private report. There is no guaranteed
response or remediation timeframe. Please keep details private while coordinated disclosure is arranged.

## AI-Assisted Reports

AI-assisted analysis and proofs of concept are welcome, but a human must review and validate the
report before submission. Check the relevant implementation, verify the claimed impact, and reproduce
the behavior where feasible. State any testing limitations or unverified assumptions. Reports that
consist only of unverified generated findings may be closed pending supporting evidence.

## Deployment Security

The engine API has no built-in authentication. See the [documented security posture](docs/deployment.md#security-posture)
for data handling, limits, and operator responsibilities when hosting it.
