import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createSbom } from './sbom.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceDirectories = ['src', 'bin', 'agent-tools', 'examples', 'scripts', 'skills', 'test', 'automation', 'playground'];
const runtimeDirectories = ['src', 'bin', 'agent-tools', 'examples', 'skills', 'automation', 'playground'];

function modules(directories) {
  return directories.flatMap(directory => {
    const start = path.join(root, directory);
    if (!fs.existsSync(start)) return [];
    const walk = current => fs.readdirSync(current, { withFileTypes: true }).flatMap(entry => (
      entry.isDirectory() ? walk(path.join(current, entry.name)) : [path.join(current, entry.name)]
    ));
    return walk(start).filter(file => /\.(?:mjs|cjs|js)$/.test(file));
  });
}

const files = modules(sourceDirectories);
const runtimeFiles = modules(runtimeDirectories);

function repositoryFiles(current = root) {
  return fs.readdirSync(current, { withFileTypes: true }).flatMap(entry => {
    if (['node_modules', '.git', '.nova', '.local-nova-state', 'artifacts', 'coverage'].includes(entry.name) || entry.name.endsWith('.tgz')) return [];
    const selected = path.join(current, entry.name);
    return entry.isDirectory() ? repositoryFiles(selected) : [selected];
  });
}

for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    process.stderr.write(result.stderr);
    process.exit(result.status || 1);
  }
}

const forbiddenProjectValues = [
  ['', 'Users', ''].join('/'),
  ['', 'home', ''].join('/'),
];
const forbiddenLegacyRuntime = [
  'nova-shamir-gf256-0.1',
  'nova-salted-claim-digest-0.1',
  'Schnorr-PoK-Fiat-Shamir',
  'createZkpKey',
  'createZkpProof',
  'verifyZkpProof',
];

for (const file of runtimeFiles) {
  const content = fs.readFileSync(file, 'utf8');
  for (const value of [...forbiddenProjectValues, ...forbiddenLegacyRuntime]) {
    if (content.includes(value)) {
      console.error(`Forbidden project-specific or retired content in ${path.relative(root, file)}: ${value}`);
      process.exit(1);
    }
  }
}

for (const file of repositoryFiles()) {
  const buffer = fs.readFileSync(file);
  if (buffer.includes(0)) continue;
  const content = buffer.toString('utf8');
  for (const value of forbiddenProjectValues) {
    if (content.includes(value)) {
      console.error(`Forbidden project-specific content in ${path.relative(root, file)}: ${value}`);
      process.exit(1);
    }
  }
  if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(content)) {
    console.error(`Private key material is present in ${path.relative(root, file)}.`);
    process.exit(1);
  }
}

const expectedDependencies = Object.freeze({
  '@modelcontextprotocol/sdk': '1.30.0',
  '@owf/identity-common': '0.3.2',
  '@sd-jwt/core': '0.20.1',
  'ipaddr.js': '2.2.0',
  'shamir-secret-sharing': '0.0.4',
});
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const sameEntries = (a, b) => JSON.stringify(Object.entries(a || {}).sort()) === JSON.stringify(Object.entries(b || {}).sort());
function verify(condition, message) { if (!condition) throw new Error(message); }
verify(sameEntries(manifest.dependencies, expectedDependencies), 'Direct dependencies differ from the reviewed exact-version policy.');
verify(sameEntries(lock.packages[''].dependencies, expectedDependencies), 'Lockfile root dependencies do not match package.json.');
verify(lock.version === manifest.version && lock.packages[''].version === manifest.version, 'Lockfile version mismatch.');
for (const [name, version] of Object.entries(expectedDependencies)) {
  verify(lock.packages[`node_modules/${name}`]?.version === version, `Locked direct version mismatch: ${name}`);
}
const expectedSbom = createSbom();
const sbom = JSON.parse(fs.readFileSync(path.join(root, 'docs/sbom.cdx.json'), 'utf8'));
verify(JSON.stringify(sbom) === JSON.stringify(expectedSbom), 'SBOM differs from the complete lockfile graph. Run npm run sbom and review it.');
const notice = fs.readFileSync(path.join(root, 'NOTICE'), 'utf8');
for (const [name, version] of Object.entries(expectedDependencies)) {
  verify(notice.includes(`- ${name} ${version}`), `NOTICE is missing direct dependency ${name}@${version}.`);
}
console.log(`PASS syntax, retired-surface, independence, secret and dependency checks (${files.length} modules; ${sbom.components.length} locked components)`);
