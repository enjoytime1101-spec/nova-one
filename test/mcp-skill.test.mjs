import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { sha256 } from '../src/canonical.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
function homeDigest(home) {
  return Object.fromEntries(fs.readdirSync(home).sort().map(file => [file, sha256(fs.readFileSync(path.join(home, file)))]));
}

test('copied Skill fixture works with installed-style CLI preview, execute, keyed verification and idempotent retry', { timeout: 30_000 }, t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-installed-skill-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const skill = path.join(directory, '.agents/skills/nova-one-trust-workflow');
  fs.cpSync(path.join(root, 'skills/nova-one-trust-workflow'), skill, { recursive: true });
  const binDirectory = path.join(directory, 'installed-bin');
  fs.mkdirSync(binDirectory);
  fs.symlinkSync(path.join(root, 'bin/nova-one.mjs'), path.join(binDirectory, 'nova-one'));
  const home = path.join(directory, 'reference-state');
  const task = path.join(skill, 'assets/local-record.json');
  const report = path.join(directory, 'report.json');
  const preview = path.join(directory, 'preview.json');
  const env = { ...process.env, NOVA_HOME: '', PATH: `${binDirectory}${path.delimiter}${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH || ''}` };
  const run = (args, expectedCode = 0) => {
    const result = spawnSync('nova-one', args, { cwd: directory, env, encoding: 'utf8' });
    assert.equal(result.status, expectedCode, result.stderr);
    return JSON.parse(expectedCode === 0 ? result.stdout : result.stderr);
  };
  run(['init', '--home', home]);
  const initial = homeDigest(home);
  const planned = run(['automation', '--file', task, '--home', home, '--out', preview]);
  assert.equal(planned.mode, 'dry-run');
  assert.equal(planned.actionExecuted, false);
  assert.deepEqual(homeDigest(home), initial, 'preview must not modify persistent state');
  assert.equal(run(['automation', 'verify', '--file', preview, '--task', task, '--run-key', 'preview', '--home', home]).verified, true);
  const executionArgs = ['automation', '--file', task, '--execute', '--run-key', 'skill-reference-001', '--home', home, '--out', report];
  const executed = run(executionArgs);
  assert.equal(executed.actionExecuted, true);
  assert.equal(executed.trustLevel, 'untrusted-fixture');
  const afterExecute = homeDigest(home);
  const verificationArgs = ['automation', 'verify', '--file', report, '--task', task, '--run-key', 'skill-reference-001', '--home', home];
  const verified = run(verificationArgs);
  assert.equal(verified.verified, true);
  assert.equal(verified.persisted, true);
  assert.deepEqual(homeDigest(home), afterExecute, 'verification must not re-run or modify the action');
  const wrongKey = [...verificationArgs];
  wrongKey[wrongKey.indexOf('--run-key') + 1] = 'another-execution';
  assert.equal(run(wrongKey, 1).error, 'automation_context_mismatch');
  assert.deepEqual(homeDigest(home), afterExecute);
  const retry = [...executionArgs];
  retry[retry.indexOf('--out') + 1] = path.join(directory, 'retry-report.json');
  run(retry);
  const state = JSON.parse(fs.readFileSync(path.join(home, 'state.json'), 'utf8'));
  assert.equal(state.notes.length, 1, 'same task and retained key must not append a second local record');
});
