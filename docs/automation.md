# Versioned local automation

The `nova-automation-task-0.1` runner turns a JSON task into a complete local reference workflow: signed fixture inputs, source and claim verification, purpose-bound context, deterministic Agent output, an optional controlled local record, and signed receipts. The command uses no network, external model or external action executor.

## Run the example

From the repository root, initialize a dedicated local home. Initialization reveals its API token once; keep the home and token private. The CLI uses Node.js 20 or newer.

```sh
node bin/nova-one.mjs init --home .nova-local
node bin/nova-one.mjs automation --file workflows/local-record.json --home .nova-local --out preview.json
```

The default is **dry-run**. It verifies the fixture workflow on a detached state snapshot, returns the Agent output and a signed ephemeral report, and performs no action or persistent state write. The report says `mode: "dry-run"`, `actionExecuted: false`, and `verification.persisted: false`. A preview is not admitted execution evidence.

Execute the declared local action with an explicit application-chosen run key:

```sh
node bin/nova-one.mjs automation --file workflows/local-record.json --execute --run-key capacity-review-001 --home .nova-local --out execution.json
```

This records the result and receipts in the local home. Reusing the same task, revision and run key returns the same local action receipt without appending another record. Each retry still runs fresh fixture verification and produces a new workflow audit trace. A changed task or policy under the same task revision and run key is rejected rather than silently returning a receipt for different content. Incrementing the task revision or selecting a new run key identifies a new requested action.

`--out` reserves a private report file before invoking the workflow. Existing targets, missing parent directories and unwritable destinations fail before any action. A failed workflow releases and removes its own empty reservation. It never overwrites an existing file. If a later disk write fails after execution committed, retry with the **same run key** and a new output filename; the local action will not repeat. Commands also print JSON to stdout. Validation, execution or verification failures return a nonzero exit code and a JSON error on stderr.

## Verify without executing

Supply the expected task and run key from your application, rather than taking them from an untrusted report:

```sh
node bin/nova-one.mjs automation verify --file execution.json --task workflows/local-record.json --run-key capacity-review-001 --home .nova-local
node bin/nova-one.mjs automation verify --file preview.json --task workflows/local-record.json --home .nova-local
```

Verification never invokes a workflow, source adapter, Agent or action. It checks:

- The task hash, policy hash, revision, expected run key, actor and execution mode against the signed automation trace.
- The trace hash, Merkle inclusion proof and checkpoint signature under the selected home's pinned key.
- The displayed Agent output against the signed output hash.
- For execution, the signed action receipt, idempotency key, exact declared record and result hash, and the receipt and result admitted in that home's intact ledger/state.

The report binds one specific local execution context. A correctly signed receipt from a different run, changed policy or other home is rejected. Verification checks recorded evidence and expected context; it does not recompute the original workflow against fresh source data. Reports retain `trustLevel: "untrusted-fixture"` and `independentWitness: false`.

## Task file contract

Use `workflows/local-record.json` as the executable example. `automation/runner.mjs` exports the strict `TASK_SCHEMA`, `validateTask`, `runAutomation` and `verifyAutomationReport` interfaces.

| Field | Meaning |
| --- | --- |
| `profile`, `id`, `revision` | Versioned task format and application task identity. |
| `policy.id`, `policy.revision` | Reviewable policy version. |
| `policy.minIndependentSources`, `policy.maxAgeMs` | Evidence-count and freshness constraints enforced by context construction. |
| `policy.allowedActions` | Empty or `record.append`; the requested action must be allowed. |
| `workflow.subject`, `actor`, `audience`, `purpose` | Scope of the local context and authorization. Actor defaults to subject. |
| `workflow.claims`, `fixtures` | Claims to verify and explicit local signed fixture payloads. Fixture IDs must be unique. |
| `workflow.action` | Optional `record.append` with JSON `parameters.record`; no arbitrary executables, URLs or external adapters. |

Execution wraps the declared record as `{ "automation": { taskId, revision, taskHash, policyHash, runKey }, "value": <declared record> }`. Its receipt binds the full wrapper, so task and policy provenance travel with the stored result. Fixture signing keys are ephemeral and source IDs are namespaced per attempt to avoid rebinding an existing source identity. The task hash remains stable over its original declarative fixture IDs.

These are local fixtures with declared independence labels, not authenticated independent external publishers. The Agent is deterministic. The runner demonstrates evidence validation and controlled automation without claiming real-world truth, a live model, production ZKP, an HSM or an independent transparency witness. Local CLI/SDK callers control the home and are its trusted operator; this is not a multi-tenant authorization boundary.

## Failure evidence and storage scope

A workflow failure discards partial sources, context, credentials, actions and results, then commits a signed `security.workflow_failed` summary on the clean pre-operation state. The error carries `failureEvidence` with the input hash, reason and audit receipt. Error messages and raw input payloads are not placed in that summary. Invalid task input rejected before a workflow transaction is not recorded as an executed workflow attempt. Dry-run failures do not write failure evidence.

If the signer or storage is unavailable while recording the failure, `failure_evidence_unavailable` is returned and no business result is committed. A state-file commit error likewise cannot promise a durable failure receipt; it returns an error and preserves the previous state when atomic replacement fails. No external effect is compensated: external action execution stays disabled.

The JSON store coordinates separate instances and processes through an exclusive lock on the local state file. It writes a private unique temporary file, flushes it, and atomically replaces the state. A failed mutation is never committed; concurrent initializers cannot replace an existing state, key bundle or configuration.

This reference backend targets one local filesystem. It is not a distributed database or a guarantee of durability across hardware failure. A crashed writer can leave `state.json.lock` (or initialization can leave `state.json.init.lock`). Locks are never automatically stolen: first stop every process using that home and establish that no writer remains, then an operator can remove the abandoned lock and retry. A paused live process must not lose lock ownership. Do not share this backend across unverified network filesystems or multiple hosts.

## Targeted regression checks

```sh
node --test test/automation-store.test.mjs test/automation-runner.test.mjs test/workflow.test.mjs
```

The checks cover separate instances/processes, abandoned locks, write failures, business rollback with signed failure evidence, unavailable signing keys, dry-run isolation, idempotent retries, expected-context receipt substitution, output tampering, external capability denial and read-only CLI verification.
