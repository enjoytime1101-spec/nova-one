import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';

const cache = path.join(os.tmpdir(), 'nova-one-npm-cache');
const executable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const result = spawnSync(executable, ['pack', '--dry-run', '--cache', cache], {
  cwd: process.cwd(),
  env: process.env,
  stdio: 'inherit',
});

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
