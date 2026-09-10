import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createNovaService } from '../src/service.mjs';
import { runAutomation, verifyAutomationReport } from '../automation/runner.mjs';

const sample = JSON.parse(fs.readFileSync(new URL('../workflows/local-record.json', import.meta.url), 'utf8'));
function fixture(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-automation-runner-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const service = createNovaService({ home }); service.initialize(); return { home, service, task: structuredClone(sample) };
}

test('default dry-run verifies an ephemeral report without actions or persistent state', async t => {
  const { service, task } = fixture(t); const before = fs.readFileSync(service.paths.state, 'utf8');
  const report = await runAutomation({ service, task });
  assert.equal(report.mode, 'dry-run'); assert.equal(report.actionExecuted, false); assert.equal(report.actionReceipt, null); assert.equal(report.verification.verified, true); assert.equal(report.verification.persisted, false);
  assert.equal(fs.readFileSync(service.paths.state, 'utf8'), before); assert.equal(verifyAutomationReport({ service, report, task }).verified, true);
  const tampered = structuredClone(report); tampered.mode = 'execute'; assert.throws(() => verifyAutomationReport({ service, report: tampered, task, runKey: 'preview' }));
});

test('execution requires a run key, retries reuse one action receipt, and verification is read-only', async t => {
  const { service, task } = fixture(t);
  await assert.rejects(runAutomation({ service, task, execute: true }), error => error.code === 'run_key_required');
  const first = await runAutomation({ service, task, execute: true, runKey: 'review-001' }); const second = await runAutomation({ service, task, execute: true, runKey: 'review-001' });
  assert.deepEqual(second.actionReceipt, first.actionReceipt); assert.equal(service.store.read().actions.length, 1); assert.equal(service.store.read().notes.length, 1);
  const before = fs.readFileSync(service.paths.state, 'utf8'); assert.equal(verifyAutomationReport({ service, report: first, task, runKey: 'review-001' }).verified, true); assert.equal(fs.readFileSync(service.paths.state, 'utf8'), before);
  assert.throws(() => verifyAutomationReport({ service, report: first, task }), error => error.code === 'run_key_required');
  assert.throws(() => verifyAutomationReport({ service, report: first, task, runKey: 'another-run' }), error => error.code === 'automation_context_mismatch');
});

test('valid receipt substitution, trace tampering and changed policy with reused key fail closed', async t => {
  const { service, task } = fixture(t);
  const first = await runAutomation({ service, task, execute: true, runKey: 'run-a' }); const other = await runAutomation({ service, task, execute: true, runKey: 'run-b' });
  const swapped = structuredClone(first); swapped.actionReceipt = other.actionReceipt;
  assert.throws(() => verifyAutomationReport({ service, report: swapped, task, runKey: 'run-a' }), error => error.code === 'automation_action_mismatch');
  const tampered = structuredClone(first); tampered.trace.binding.outputHash = '0'.repeat(64);
  assert.throws(() => verifyAutomationReport({ service, report: tampered, task, runKey: 'run-a' }), error => error.code === 'automation_receipt_invalid');
  const changed = structuredClone(task); changed.policy.revision += 1;
  assert.throws(() => verifyAutomationReport({ service, report: first, task: changed, runKey: 'run-a' }), error => error.code === 'automation_context_mismatch');
  await assert.rejects(runAutomation({ service, task: changed, execute: true, runKey: 'run-a' }), error => error.code === 'idempotency_conflict');
  const state = service.store.read(); assert.equal(state.actions.length, 2); assert.equal(state.auditEntries.at(-1).event, 'security.workflow_failed');
});

test('task schema and runner prevent external capability escalation', async t => {
  const { service, task, home } = fixture(t); task.workflow.action.type = 'webhook.dispatch';
  await assert.rejects(runAutomation({ service, task, execute: true, runKey: 'external' }), error => error.code === 'invalid_automation_task'); assert.equal(service.store.read().actions.length, 0);
  const enabled = createNovaService({ home, allowNetwork: true });
  await assert.rejects(runAutomation({ service: enabled, task: sample }), error => error.code === 'automation_external_disabled');
});

test('CLI writes a report, verifies expected context without execution and exits nonzero on mismatch', t => {
  const { home, service, task } = fixture(t); const file = path.join(home, 'task.json'); const out = path.join(home, 'report.json'); fs.writeFileSync(file, JSON.stringify(task));
  const bin = new URL('../bin/nova-one.mjs', import.meta.url); const cli = (...args) => spawnSync(process.execPath, [bin.pathname, ...args], { encoding: 'utf8' });
  const executed = cli('automation', '--file', file, '--execute', '--run-key', 'cli-001', '--home', home, '--out', out); assert.equal(executed.status, 0, executed.stderr); assert.equal(JSON.parse(executed.stdout).verification.verified, true);
  const before = fs.readFileSync(service.paths.state, 'utf8'); const verified = cli('automation', 'verify', '--file', out, '--task', file, '--run-key', 'cli-001', '--home', home); assert.equal(verified.status, 0, verified.stderr); assert.equal(JSON.parse(verified.stdout).verified, true); assert.equal(fs.readFileSync(service.paths.state, 'utf8'), before);
  const invalid = cli('automation', 'verify', '--file', out, '--task', file, '--run-key', 'wrong', '--home', home); assert.equal(invalid.status, 1); assert.equal(JSON.parse(invalid.stderr).error, 'automation_context_mismatch');
});

test('report verification rejects altered displayed output and another NOVA home', async t => {
  const { service, task } = fixture(t); const other = fixture(t).service;
  const report = await runAutomation({ service, task });
  const tampered = structuredClone(report); tampered.output.claims[0].value = 999;
  assert.throws(() => verifyAutomationReport({ service, report: tampered, task }), error => error.code === 'automation_output_mismatch');
  assert.throws(() => verifyAutomationReport({ service: other, report, task }), error => error.code === 'automation_receipt_invalid');
});

test('CLI report targets are reserved before actions and failed runs remove their reservation', t => {
  const { home, service, task } = fixture(t); const file = path.join(home, 'task.json'); fs.writeFileSync(file, JSON.stringify(task));
  const bin = new URL('../bin/nova-one.mjs', import.meta.url); const cli = (...args) => spawnSync(process.execPath, [bin.pathname, ...args], { encoding: 'utf8' });
  const occupied = path.join(home, 'occupied.json'); fs.writeFileSync(occupied, 'preserve this report');
  const before = fs.readFileSync(service.paths.state, 'utf8');
  const existing = cli('automation', '--file', file, '--execute', '--run-key', 'blocked-output', '--home', home, '--out', occupied);
  assert.equal(existing.status, 1); assert.equal(JSON.parse(existing.stderr).error, 'report_target_exists'); assert.equal(fs.readFileSync(occupied, 'utf8'), 'preserve this report'); assert.equal(fs.readFileSync(service.paths.state, 'utf8'), before);
  const missing = cli('automation', '--file', file, '--execute', '--run-key', 'blocked-output', '--home', home, '--out', path.join(home, 'missing', 'report.json'));
  assert.equal(missing.status, 1); assert.equal(JSON.parse(missing.stderr).error, 'report_directory_unavailable'); assert.equal(fs.readFileSync(service.paths.state, 'utf8'), before);
  const invalidParent = cli('automation', '--file', file, '--execute', '--run-key', 'blocked-output', '--home', home, '--out', path.join(occupied, 'report.json'));
  assert.equal(invalidParent.status, 1); assert.equal(JSON.parse(invalidParent.stderr).error, 'report_directory_unavailable'); assert.equal(service.store.read().actions.length, 0);
  task.workflow.fixtures[1].payload.claims.capacity = 121; fs.writeFileSync(file, JSON.stringify(task)); const reserved = path.join(home, 'failed.json');
  const failed = cli('automation', '--file', file, '--execute', '--run-key', 'failed-output', '--home', home, '--out', reserved);
  assert.equal(failed.status, 1); assert.equal(JSON.parse(failed.stderr).error, 'evidence_conflict'); assert.equal(fs.existsSync(reserved), false); assert.equal(service.store.read().actions.length, 0);
});
