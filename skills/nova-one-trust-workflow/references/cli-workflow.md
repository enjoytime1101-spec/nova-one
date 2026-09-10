# Installed CLI workflow

Use this when the user requested a local NOVA reference run. The skill is
self-contained after copying its directory; its fixture lives at
`assets/local-record.json` relative to `SKILL.md`. It requires Node.js 20+ and an
installed `nova-one` CLI. Confirm `nova-one help` succeeds. If the CLI is missing,
report the missing prerequisite instead of inventing a tool result.

Choose absolute paths for the installed skill, a private workspace dedicated to
this run, and the task. The following POSIX example uses illustrative paths;
resolve them before execution. For an existing NOVA home, run `status` and reuse
only the home explicitly selected by the user. Do not run `init` on an unknown
home as a repair operation.

For a **new, authorised local demo**, initialize private state without exposing
the one-time API token in chat or a committed log:

```sh
umask 077
mkdir -p /ABS/private-nova-reference
nova-one init --home /ABS/private-nova-reference/state > /ABS/private-nova-reference/initialization.json
nova-one status --home /ABS/private-nova-reference/state
```

Copy the bundled `assets/local-record.json` into that private workspace as
`task.json`, then review the exact subject, audience, purpose, claims, policy,
and `record.append` content. Both sources are explicitly local fixtures. Even
if they agree and have different independence labels, they are not independently
operated external publishers.

Preview without persisting a workflow action:

```sh
nova-one automation --file /ABS/private-nova-reference/task.json --home /ABS/private-nova-reference/state --out /ABS/private-nova-reference/preview.json
nova-one automation verify --file /ABS/private-nova-reference/preview.json --task /ABS/private-nova-reference/task.json --run-key preview --home /ABS/private-nova-reference/state
```

Keep an execution key chosen for the agreed task, such as `reference-run-001`.
Execute when that local side effect is within the user's authorization:

```sh
nova-one automation --file /ABS/private-nova-reference/task.json --execute --run-key reference-run-001 --home /ABS/private-nova-reference/state --out /ABS/private-nova-reference/report.json
nova-one automation verify --file /ABS/private-nova-reference/report.json --task /ABS/private-nova-reference/task.json --run-key reference-run-001 --home /ABS/private-nova-reference/state
```

Always supply the expected execution key to verification. Do not copy an
untrusted report's key to make it pass. Keep the exact task/policy alongside the
report; a signature does not authorize a different task. If execution is
interrupted or its outcome is unclear, first inspect/verify saved evidence. A
retry must keep the agreed task and key; changing them can create another record.
Choose a fresh `--out` path for each attempt and retain the earlier report; the
CLI does not overwrite an existing report file.
Do not create a fresh key merely to defeat an idempotency or verification error.

Inspect the structured `verified`, `mode`, `actionExecuted`, `persisted`, and
`trustLevel` fields. A dry run is not a persisted action. Successful execution
is a local reference record with `untrusted-fixture` evidence, not an external
provider action or production certification. The reference runner is
fixture-only and has no network/model/provider executor switches.

For an existing MCP action receipt, use `nova_verify_action_receipt` with the
expected context retained from the agreed action. For a complete automation
report, the CLI `automation verify` command checks its task/policy/run binding
and signed audit proof without re-running the workflow. Store selection is a
trust decision made by the operator, not by the incoming report.
