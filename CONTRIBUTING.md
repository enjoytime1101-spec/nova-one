# Contributing to NOVA One

Thank you for improving NOVA One. This project repository treats security and
claim accuracy as product features. A change is incomplete if its documentation
overstates what the implementation proves.

## Development setup

Requirements:

- Node.js 20 or newer;
- npm; and
- Git.

From an existing repository checkout, enter the package directory and run:

```bash
cd nova-one
npm ci
npm test
npm run check
```

Runtime dependencies are permitted when they reduce custom security-sensitive
code and have a documented maintenance, advisory, licensing and package-size
review. Pin direct dependencies exactly, commit the lockfile, update the SBOM or
inventory, and run the online advisory audit.

## Working agreement

1. Open or reference an issue for a material change.
2. Keep a pull request focused and add tests for observable behaviour, error
   cases, replay handling, and fail-closed boundaries.
3. Run `npm test`, `npm run check`, `npm run demo`, `npm run pack:check`, and `npm run test:package`.
4. Update API, CLI, Skill, security, or interoperability documentation when the
   contract changes.
5. Explain new data retention, external calls, secrets, permissions, and
   migration requirements in the pull request.

Do not commit generated state, keys, credentials, bearer tokens, personal data,
vendor secrets, or real action receipts. Examples must use synthetic data and
must not contact a live provider by default.

## Compatibility and profiles

Changes to canonicalisation, token claims, credential status, selective
disclosure, proof transcripts, audit entries, checkpoints, or tool contracts are
protocol changes. They require:

- an explicit profile or schema version;
- backward-compatibility or a documented migration;
- positive and negative interoperability fixtures; and
- precise wording about whether the profile is custom, compatible, conformant,
  or merely inspired by a standard.

Never label a custom profile as certified or standards-compliant without an
applicable conformance program and independent evidence. In particular, NOVA's
current credential and status profiles remain custom. Its RFC 9901 SD-JWT
mechanics use a custom NOVA application envelope and have no holder key binding.
The former custom Schnorr surface has been removed; do not reintroduce custom
proof mathematics.

## Controlled-action changes

External side effects are disabled in 0.3.0. Re-enablement requires a durable
transactional outbox, upstream idempotency key, reconciliation worker, crash and
concurrency tests, and an independently authenticated approval provider. Keep
proposal, policy, dry-run, approval, execution and receipt as distinct states.
Prompts and model output are untrusted input, never authorisation.

## Documentation and governance mappings

Link to primary sources where possible and date time-sensitive mappings. A
mapping describes how evidence may support a review; it must not claim legal
advice, certification, regulator approval, or automatic compliance. Mark gaps
and deployment responsibilities plainly.

## Commit and pull-request quality

Use clear, imperative commit subjects. The pull request should describe the
problem, contract changes, tests, security impact, data and privacy impact,
compatibility, and documentation updates. Maintainers may ask for a smaller
change when independent review would be safer.

By submitting a contribution, you agree that it is licensed under the
[Apache License 2.0](LICENSE) and that you have the right to submit it.

For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

## Design and browser contributions

Follow [the design system](docs/design-system.md), preserve the explicit browser-demo trust profile, test keyboard access and narrow viewports, and keep the Playground free of credentials, analytics, external model calls and production claims.
