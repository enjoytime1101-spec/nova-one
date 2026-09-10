import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { root } from './sbom.mjs';

const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const out = path.join(root, 'artifacts');
fs.mkdirSync(out, { recursive: true });
const command = (file, args) => execFileSync(file, args, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
const commit = command('git', ['rev-parse', 'HEAD']).trim();
if (command('git', ['status', '--porcelain']).trim()) throw new Error('Commit reviewed source before building a release.');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packed = JSON.parse(command(npm, ['pack', '--ignore-scripts', '--json', '--pack-destination', out]));
const prefix = `nova-one-${manifest.version}`;
const source = `${prefix}-source.zip`;
const skill = `${prefix}-skill.zip`;
command('git', ['archive', '--format=zip', `--prefix=${prefix}/`, `--output=${path.join(out, source)}`, commit]);
command('git', ['archive', '--format=zip', `--output=${path.join(out, skill)}`, commit, 'skills/nova-one-trust-workflow']);
const records = [packed[0].filename, source, skill].map(name => {
  const data = fs.readFileSync(path.join(out, name));
  return { name, bytes: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') };
});
const release = {
  schema: 'nova-release-manifest-1', name: manifest.name, version: manifest.version, sourceCommit: commit,
  maturity: 'local-reference-prerelease', license: manifest.license, artifacts: records,
  sourceDependencyPolicy: 'npm ci with package-lock.json',
  runtimeBoundaries: ['external-actions-disabled', 'business-zkp-disabled', 'no-production-acceptance'],
};
fs.writeFileSync(path.join(out, 'RELEASE.json'), `${JSON.stringify(release, null, 2)}\n`);
const releaseHash = crypto.createHash('sha256').update(fs.readFileSync(path.join(out, 'RELEASE.json'))).digest('hex');
fs.writeFileSync(path.join(out, 'SHA256SUMS'), [...records.map(item => `${item.sha256}  ${item.name}`), `${releaseHash}  RELEASE.json`].join('\n') + '\n');
console.log(JSON.stringify(release, null, 2));
