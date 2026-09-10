# v0.3.0 capability and acceptance matrix

This release is a **local reference prerelease**. Publication of working open-source code is separate from production acceptance. The following checks are executable in the repository; the release records actual results, source commit and archive checksums.

| Delivery | Implementation | Verification |
| --- | --- | --- |
| Independent engineering package | Own package, lockfile, CLI, SDK and license; no consuming platform dependency | `npm run check`, clean source installation |
| Complete local automation | Versioned task and policy, verified inputs, minimum context, Agent binding, local action and receipt | `test/automation-runner.test.mjs`, installed-package smoke |
| Preview and execution | Dry-run without persisted changes; explicit execute/run key | Dry-run state comparison, idempotent retry and changed-task rejection |
| Verifiable receipts | Task/policy/run-key binding and local admission; MCP action receipt verifier uses the selected local trust store | Valid, tampered, wrong-actor, wrong-request and wrong-home cases |
| Local concurrency and failure evidence | Exclusive writer coordination, atomic files, failure-only audit commit | Multi-instance/process and rollback tests |
| Agent integration | Standard MCP stdio, Skill with CLI fallback, Prompt Block | SDK client initialize/list/call and permission-denial tests |
| Online experience | Static browser proof demonstration with its own receipt profile | Web Crypto tests; desktop/mobile browser review |
| Documentation | English README, installation, automation, API, Agent, design and contribution guides | Link/package review, documented commands exercised |
| Supply chain | Exact direct versions, full lockfile graph/SBOM, license inventory, secrets/independence scan | Static checks and online advisory audit |
| GitHub delivery | Source commit, public repository, prerelease archives, checksums, CI and Pages | Remote URLs and successful workflow runs |

## Capability boundaries

| Capability | v0.3.0 status |
| --- | --- |
| Ed25519 credentials, local lifecycle and audit | Implemented under custom NOVA profiles |
| RFC 9901 disclosure mechanics | Implemented through maintained SD-JWT core, without holder key binding |
| Source freshness, conflicting claims, minimal scope | Implemented; example sources are explicitly synthetic |
| Model output binding | Implemented; stock example uses a deterministic Agent |
| Local record append | Implemented with idempotency and signed result binding |
| External source/model adapters | SDK extension points; no provider credentials or real-provider acceptance included |
| External webhook actions | Technically disabled pending durable outbox, reconciliation and real approval controls |
| Business mathematical ZKP | Disabled; signed attestations are not range proofs |
| Independent witness / organizational identity | Adapter/governance work remains; local signatures do not supply independence |
| Production RBAC, database availability, KMS/HSM, TLS gateway | Open production engineering and deployment work |

The [broader requirements matrix](original-requirements-matrix.md) retains unresolved goals. Passing the local package suite does not close them. Older v0.2.0 records are historical and cannot establish v0.3.0 test results.
