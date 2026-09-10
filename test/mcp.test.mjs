import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createNovaService } from '../src/service.mjs';
import { canonical, sha256 } from '../src/canonical.mjs';
import { createKeyBundle, signBytes } from '../src/crypto.mjs';
import { MCP_READ_ONLY_TOOLS } from '../agent-tools/mcp.mjs';
import { NOVA_TOOL_CONTRACTS } from '../agent-tools/tool-contracts.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const entry = path.join(root, 'agent-tools/mcp.mjs');
const scope = { subject: 'did:example:mcp-test', audience: 'mcp-test', purpose: 'local-verification-test' };
function setup(t, initialize = true) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-mcp-'));
  const home = path.join(directory, 'isolated-state');
  const service = createNovaService({ home });
  if (initialize) service.initialize({ issuer: 'https://mcp.test/nova' });
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { directory, home, service };
}
function stateDigest(home) {
  return Object.fromEntries(fs.readdirSync(home).sort().map(file => [file, sha256(fs.readFileSync(path.join(home, file)))]));
}
function policyFile(fixture, allowWriteTools) {
  const file = path.join(fixture.directory, 'operator-policy.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, home: fixture.home, allowWriteTools }), { mode: 0o600 });
  return file;
}
async function connect(t, fixture, { policy = '', executable = entry } = {}) {
  const client = new Client({ name: 'nova-mcp-regression', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [executable], cwd: fixture.directory,
    env: { NOVA_HOME: fixture.home, NOVA_MCP_POLICY_FILE: policy }, stderr: 'pipe',
  });
  const sent = [];
  const send = transport.send.bind(transport);
  transport.send = message => { if (message.method) sent.push(message.method); return send(message); };
  await client.connect(transport);
  t.after(() => client.close());
  return { client, sent };
}
async function call(client, name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent);
  return { ...result, data: result.structuredContent };
}

test('official client initializes the installed-style stdio entry and read tools leave state unchanged', { timeout: 20_000 }, async t => {
  const f = setup(t);
  const credential = await f.service.issueCredential({ type: 'IdentityCredential', ...scope, claims: { role: 'tester' } });
  const before = stateDigest(f.home);
  const link = path.join(f.directory, 'nova-one-mcp');
  fs.symlinkSync(entry, link);
  const { client, sent } = await connect(t, f, { executable: link });
  assert.equal(client.getServerVersion().name, 'nova-one');
  assert.ok(client.getServerCapabilities().tools);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(tool => tool.name).sort(), [...MCP_READ_ONLY_TOOLS].sort());
  assert.ok(tools.every(tool => tool.annotations.readOnlyHint && !tool.annotations.openWorldHint));
  const status = await call(client, 'nova_status');
  assert.equal(status.data.ledger.valid, true);
  assert.deepEqual(status.data.capabilities, { network: false, model: false, executor: false });
  assert.equal((await call(client, 'nova_verify_credential', { ...scope, token: credential.token })).data.verified, true);
  const wrongAudience = await call(client, 'nova_verify_credential', { ...scope, audience: 'other', token: credential.token });
  assert.equal(wrongAudience.isError, true);
  assert.equal(wrongAudience.data.error, 'audience_mismatch');
  assert.equal((await call(client, 'nova_predicate_proof_capabilities')).data.enabled, false);
  assert.ok(sent.includes('initialize') && sent.includes('notifications/initialized') && sent.includes('tools/list') && sent.includes('tools/call'));
  assert.deepEqual(stateDigest(f.home), before);
});

test('default MCP rejects every mutating tool, including challenge-consuming verification and self-granted permissions', { timeout: 20_000 }, async t => {
  const f = setup(t);
  const before = stateDigest(f.home);
  const { client } = await connect(t, f);
  for (const tool of NOVA_TOOL_CONTRACTS.filter(tool => !MCP_READ_ONLY_TOOLS.includes(tool.name))) {
    const response = await call(client, tool.name, { allowWriteTools: [tool.name], home: f.home, approved: true });
    assert.equal(response.isError, true, tool.name);
    assert.equal(response.data.error, 'mcp_write_tool_disabled', tool.name);
  }
  const schemaFailure = await call(client, 'nova_status', { allowNetwork: true });
  assert.equal(schemaFailure.isError, true);
  assert.equal(schemaFailure.data.error, 'tool_input_invalid');
  await assert.rejects(client.callTool({ name: 'nova_enable_permissions', arguments: {} }));
  assert.deepEqual(stateDigest(f.home), before);
});

test('operator startup policy permits exact local mutations, stays immutable in-session, and keeps external actions disabled', { timeout: 20_000 }, async t => {
  const f = setup(t);
  const policy = policyFile(f, ['nova_issue_credential', 'nova_run_workflow']);
  const { client } = await connect(t, f, { policy });
  const names = (await client.listTools()).tools.map(tool => tool.name);
  assert.ok(names.includes('nova_issue_credential'));
  assert.ok(!names.includes('nova_change_credential_status'));
  const issued = await call(client, 'nova_issue_credential', { type: 'IdentityCredential', ...scope, claims: { role: 'test' } });
  assert.ok(issued.data.token);
  assert.equal((await call(client, 'nova_verify_credential', { ...scope, token: issued.data.token })).data.verified, true);
  policyFile(f, ['nova_issue_credential', 'nova_run_workflow', 'nova_change_credential_status']);
  const denied = await call(client, 'nova_change_credential_status', { id: issued.data.id, state: 'revoked', actor: scope.subject });
  assert.equal(denied.data.error, 'mcp_write_tool_disabled');
  const blocked = await call(client, 'nova_run_workflow', { ...scope, action: { type: 'webhook.dispatch', parameters: { url: 'https://example.invalid/must-not-be-called' } } });
  assert.equal(blocked.isError, true);
  assert.equal(blocked.data.error, 'external_actions_disabled');
  assert.equal(f.service.credentialStatus(issued.data.id).state, 'active');
});

test('receipt verification binds local trust, action, actor, request, result and audit without re-execution', { timeout: 20_000 }, async t => {
  const f = setup(t);
  const demo = await f.service.runDemo(scope);
  const receipt = demo.workflow.action.receipt;
  const input = {
    receipt, expectedIssuer: receipt.issuer, expectedKeyId: receipt.signature.keyId,
    expectedActionId: receipt.actionId, expectedRequestHash: receipt.requestHash, expectedActor: receipt.actor,
  };
  const before = stateDigest(f.home);
  const { client } = await connect(t, f);
  const verified = await call(client, 'nova_verify_action_receipt', input);
  assert.equal(verified.data.verified, true);
  assert.equal(verified.data.localRecordVerified, true);
  assert.equal(verified.data.externalExecutionVerified, false);
  for (const change of [{ expectedActionId: 'other-action' }, { expectedActor: 'other-actor' }, { expectedRequestHash: 'f'.repeat(64) }, { expectedIssuer: 'https://attacker.invalid' }]) {
    assert.equal((await call(client, 'nova_verify_action_receipt', { ...input, ...change })).isError, true);
  }
  const tampered = { ...receipt, result: { ...receipt.result, recordHash: '0'.repeat(64) } };
  assert.equal((await call(client, 'nova_verify_action_receipt', { ...input, receipt: tampered })).isError, true);
  const attacker = createKeyBundle({ issuer: receipt.issuer, keyId: receipt.signature.keyId });
  const { signature: _signature, ...unsigned } = receipt;
  const forged = { ...unsigned, signature: { ...receipt.signature, value: signBytes(attacker, canonical(unsigned)) } };
  assert.equal((await call(client, 'nova_verify_action_receipt', { ...input, receipt: forged })).data.error, 'invalid_action_receipt_signature');
  assert.equal((await call(client, 'nova_verify_action_receipt', { ...input, trustedPublicKey: {} })).data.error, 'tool_input_invalid');
  assert.deepEqual(stateDigest(f.home), before);
  const state = f.service.store.read();
  state.notes[0].record = { tampered: true };
  fs.writeFileSync(f.service.paths.state, JSON.stringify(state));
  assert.equal((await call(client, 'nova_verify_action_receipt', input)).data.error, 'action_result_integrity_failure');
});

test('missing initialization and invalid local policy fail without creating state', { timeout: 20_000 }, async t => {
  const f = setup(t, false);
  const { client } = await connect(t, f);
  assert.equal((await call(client, 'nova_status')).data.error, 'nova_not_initialized');
  assert.equal(fs.existsSync(f.home), false);
  const policy = policyFile(f, ['nova_issue_credential']);
  fs.writeFileSync(policy, JSON.stringify({ version: 1, home: path.join(f.directory, 'wrong-home'), allowWriteTools: ['nova_issue_credential'] }));
  const run = spawnSync(process.execPath, [entry], { encoding: 'utf8', input: '',
    env: { ...process.env, NOVA_HOME: f.home, NOVA_MCP_POLICY_FILE: policy } });
  assert.equal(run.status, 2);
  assert.equal(run.stdout, '');
  assert.equal(JSON.parse(run.stderr).error, 'invalid_mcp_policy');
  assert.equal(fs.existsSync(f.home), false);
});

test('legacy JSONL tools/list remains a separate compatible transport', t => {
  const f = setup(t);
  const run = spawnSync(process.execPath, [path.join(root, 'agent-tools/stdio.mjs')], {
    input: `${JSON.stringify({ id: 'legacy', method: 'tools/list' })}\n`, encoding: 'utf8',
    env: { ...process.env, NOVA_HOME: f.home },
  });
  assert.equal(run.status, 0, run.stderr);
  const response = JSON.parse(run.stdout);
  assert.equal(response.id, 'legacy');
  assert.deepEqual(response.result.tools.map(tool => tool.name), NOVA_TOOL_CONTRACTS.map(tool => tool.name));
});

test('MCP help and version require no state and do not open the protocol transport', t => {
  const f = setup(t, false);
  for (const flag of ['--help', '--version']) {
    const result = spawnSync(process.execPath, [entry, flag], {
      encoding: 'utf8', input: '', env: { ...process.env, NOVA_HOME: '', NOVA_MCP_POLICY_FILE: '' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.ok(result.stdout.trim());
  }
  const rejected = spawnSync(process.execPath, [entry, '--allow-all'], {
    encoding: 'utf8', input: '', env: { ...process.env, NOVA_HOME: f.home },
  });
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).error, 'invalid_mcp_arguments');
  assert.equal(fs.existsSync(f.home), false);
});
