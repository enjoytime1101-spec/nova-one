# Agent integration

NOVA provides a standard local MCP stdio server, an installable Skill, a reusable
Prompt Block, and a CLI automation runner. The server uses the official
`@modelcontextprotocol/sdk` pinned to **1.30.0** and its initialize/stdio protocol.
The low-level SDK server preserves NOVA's existing JSON Schemas without a second
schema translation. See the [official SDK transport documentation](https://ts.sdk.modelcontextprotocol.io/server).

`agent-tools/stdio.mjs` remains the original JSONL compatibility adapter. It is
**not MCP**, has no initialize handshake, and does not gain the new MCP startup
permission controls. Do not use it as a fallback after an MCP permission denial.

## Install or run from a checkout

Node.js 20+ is required. In the independent NOVA repository:

```sh
npm ci --ignore-scripts
npm run test:mcp
node agent-tools/mcp.mjs --help
node agent-tools/mcp.mjs --version
```

For an operator-chosen CLI installation from a reviewed local package:

```sh
npm pack --ignore-scripts
npm install --global ./nova-one-digital-trust-0.3.0.tgz --ignore-scripts
nova-one help
nova-one-mcp --help
```

These are installation instructions, not an automatic global install. The npm
package exports the `nova-one` and `nova-one-mcp` executable commands. `--help`
and `--version` do not require a state home or start a protocol session.

## Select isolated state

MCP requires an explicit absolute `NOVA_HOME` and never initializes one or falls
back to `~/.nova-one`. Keep each project/environment separate. For an authorized
new local reference workspace, replace these illustrative absolute paths:

```sh
umask 077
mkdir -p /ABS/private-nova
nova-one init --home /ABS/private-nova/state > /ABS/private-nova/initialization.json
nova-one status --home /ABS/private-nova/state
```

The initialization file includes a one-time API token. Keep it private, outside
committed artifacts; do not paste it, signing keys, or holder credentials into
Agent prompts. MCP stdio does not require that HTTP bearer token. The OS account
and the operator-selected home determine local key access and trust.

## Register a local MCP host

For Claude Desktop, merge this server entry into its Developer → Edit Config
configuration, preserving other servers. Replace `command` with the absolute
Node executable and `args[0]` with your reviewed checkout path:

```json
{
  "mcpServers": {
    "nova-one": {
      "command": "/ABS/node/bin/node",
      "args": ["/ABS/nova-one-open-source/agent-tools/mcp.mjs"],
      "env": {
        "NOVA_HOME": "/ABS/private-nova/state"
      }
    }
  }
}
```

With an installed package, `command` may instead be the absolute
`nova-one-mcp` executable, with `args: []`. Restart that host after configuration
changes. This follows the [official local-server host configuration guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers).
Other hosts should use their stdio-server registration format with the same
command, arguments, and environment; this JSON is not a universal host format.

No HTTP listener is started. stdout carries only MCP JSON-RPC during a server
session; startup errors use stderr. A real official SDK client integration test
exercises `initialize`, `notifications/initialized`, `tools/list`, and
`tools/call`, including npm-style executable symlink resolution. This is not a
claim that every desktop host has been manually tested.

## Default permissions and explicit local writes

The default `tools/list` contains:

| Tool | Scope |
|---|---|
| `nova_status` | Local status and ledger verification |
| `nova_verify_credential` | Signature, expected scope and local validity |
| `nova_credential_status` | Current local admission/status |
| `nova_predicate_proof_capabilities` | Disabled predicate-proof capability report |
| `nova_verify_action_receipt` | Existing local action/result/audit verification |

All other tools are hidden from discovery and explicitly refused on direct
`tools/call`. This includes signing/presentation creation, challenge consumption,
selective-disclosure audit writes, issuance, revocation, demos, and workflows.
Tool annotations are descriptive; the server enforces permission before calling
the shared executor, then the executor validates the exact input schema.

An operator can allow specific local mutations with a JSON policy file:

```json
{
  "version": 1,
  "home": "/ABS/private-nova/state",
  "allowWriteTools": ["nova_issue_credential"]
}
```

Save it at an absolute operator-controlled path, restrict other-user write access
(for example `chmod 600 /ABS/private-nova/mcp-policy.json`), and add
`NOVA_MCP_POLICY_FILE: "/ABS/private-nova/mcp-policy.json"` to the host's server
environment. The home binding must match. Unknown fields/tool names and malformed
policies fail startup. Policy is read once; changing the file does not broaden a
running session. There is no permission-editing tool or allow-all CLI flag.

The allowlist authorizes a tool for that local home; it is not a per-user, per-claim,
or per-action approval service. Choose narrow tools and preserve the user's
specific task authority. An Agent must not change the policy, choose another
home, or switch to CLI/JSONL to bypass a refusal. This process is not a sandbox
against another program or Agent with direct access to the same OS files.

Network access, model calls and external action adapters remain disabled even
when a workflow tool is allowed. A tool input cannot enable them. A verification
failure is returned as MCP `isError: true` with a stable NOVA error code in JSON
`structuredContent` and the equivalent text content; handle it as a failed check.

## Verify a receipt without repeating an action

Call `nova_verify_action_receipt` with the existing `receipt` and independently
retained `expectedIssuer`, `expectedKeyId`, `expectedActionId`,
`expectedRequestHash`, and `expectedActor`. Do not derive all expectations from
the unverified receipt itself.

The server selects the public verification key from the fixed `NOVA_HOME` key
bundle, not from tool input. It verifies issuer/key identity, signature, context,
local action/receipt admission, stored record hash, and the signed audit chain's
action binding. Supplying a different self-generated key is not accepted. A
successful result establishes a completed local `record.append`; it reports
`externalExecutionVerified: false`. Local trust-store selection remains an
operator trust decision, not a certificate of real-world identity or source truth.

For a complete automation report, retain the original task and execution key:

```sh
nova-one automation verify --file /ABS/private-nova/report.json --task /ABS/private-nova/task.json --run-key reference-run-001 --home /ABS/private-nova/state
```

This verifies the report's task/policy/run context and audit proof without
executing the workflow again. The CLI runner's preview/execute/verify recipe is
also included inside the portable Skill.

## Install the Skill and reuse the Prompt Block

From this checkout, choose a project that should discover the Skill. Use a new
destination, or inspect an existing installation before replacing it:

```sh
mkdir -p /ABS/your-project/.agents/skills
cp -R skills/nova-one-trust-workflow /ABS/your-project/.agents/skills/
```

The complete folder includes `SKILL.md`, `agents/openai.yaml`, a bundled fixture
task, CLI instructions, tool reference, and Prompt Block. It has no hardcoded
checkout or user path and can instead be copied to a user-chosen Skill directory.
It does not install the CLI or register MCP automatically. Invoke it as
`$nova-one-trust-workflow` in a compatible Skill host.

For a host without Skill discovery, use
[`verified-action-block.md`](../skills/nova-one-trust-workflow/prompts/verified-action-block.md)
as the reusable prompt structure. It is guidance, not a permission grant or tool
schema. The [portable CLI recipe](../skills/nova-one-trust-workflow/references/cli-workflow.md)
uses installed commands to preview, execute with an explicit key, and verify.

## Explicitly unavailable

This integration does not publish GPT Actions, host a remote MCP endpoint,
configure OAuth, call live models/providers, enable webhook execution, provide
business predicate ZK proofs, or certify a production deployment. Reference
automation uses locally supplied fixtures and a deterministic Agent adapter;
its signatures and receipts do not upgrade those fixtures into independent
external evidence. See the project's threat model for the broader trust limits.
