# NOVA One v0.3.0

An independent local reference prerelease of **NOVA One Digital Trust Infrastructure**: runnable code, automation, Agent tools and a browser Playground.

## Added and corrected

- Versioned JSON automation tasks and local policies, dry-run, explicit execution keys, idempotent record actions and saved report verification.
- Local writer coordination across instances/processes, atomic writes and separately committed workflow failure evidence.
- Standard MCP stdio using the official SDK, read-only tools by default, operator-controlled write allowlists and a local-trust-bound action receipt verifier.
- A usable Skill with CLI fallback, a portable Prompt Block and Agent-host setup instructions.
- An English interactive Playground with actual browser signing, verification and tamper/failure demonstrations, plus grid/color/design documentation.
- Complete locked dependency SBOM, English installation/contribution docs, installed-package verification and GitHub CI/release/Pages workflows.

## Install

Download `nova-one-digital-trust-0.3.0.tgz` and `SHA256SUMS`, verify its checksum, then use `npm install --global ./nova-one-digital-trust-0.3.0.tgz`. Alternatively, unpack the source archive and run `npm ci && npm run demo`.

The Skill ZIP contains `skills/nova-one-trust-workflow`. Follow its linked Agent integration guide in the source repository. Source commit and per-archive SHA-256 hashes are recorded in `RELEASE.json`.

## Verification

The repository CI checks Node.js 20, 22 and 24; the package smoke installs the actual npm archive and exercises initialization, preview, execution, retry, read-only verification, tamper rejection and the installed test suite. Standard MCP tests use a real SDK client handshake and tool calls.

## Boundaries

This is local reference software, not production acceptance. Examples are marked synthetic; browser receipts use a separate demonstration profile. External webhook actions and mathematical business ZKP remain disabled. Real provider/witness integrations, production database/RBAC/KMS, holder-bound disclosure and standard status federation remain open. No npm-registry publication, hosted GPT, independent certification or automatic compliance is claimed.

See [README](https://github.com/enjoytime1101-spec/nova-one), [Playground](https://enjoytime1101-spec.github.io/nova-one/) and the broader requirements matrix.
