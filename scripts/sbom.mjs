import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function createSbom() {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  const purl = (name, version) => `pkg:npm/${name.replace('@', '%40')}@${version}`;
  const records = new Map(Object.entries(lock.packages).filter(([key]) => key).map(([key, value]) => {
    const name = value.name || key.slice(key.lastIndexOf('node_modules/') + 13);
    return [key, { ...value, name, ref: purl(name, value.version) }];
  }));
  const components = new Map();
  const dependencies = new Map();
  const resolve = (directory, name) => {
    let cursor = directory;
    while (true) {
      const candidate = records.get(path.posix.join(cursor, 'node_modules', name));
      if (candidate) return candidate.ref;
      if (!cursor || cursor === '.') return undefined;
      cursor = path.posix.dirname(cursor);
      if (cursor === '.') cursor = '';
    }
  };
  for (const [location, value] of records) {
    const hash = value.integrity?.split('-', 2);
    if (!value.license || hash?.[0] !== 'sha512') throw new Error(`Missing license or SHA-512 integrity: ${location}`);
    components.set(value.ref, {
      type: 'library', 'bom-ref': value.ref, name: value.name, version: value.version,
      scope: value.dev ? 'optional' : 'required', purl: value.ref,
      licenses: [{ license: { id: value.license } }],
      hashes: [{ alg: 'SHA-512', content: Buffer.from(hash[1], 'base64').toString('hex') }],
    });
    const refs = dependencies.get(value.ref) || new Set();
    for (const name of Object.keys({ ...value.dependencies, ...value.optionalDependencies, ...value.peerDependencies })) {
      const ref = resolve(location, name);
      if (ref) refs.add(ref);
    }
    dependencies.set(value.ref, refs);
  }
  const application = purl(manifest.name, manifest.version);
  dependencies.set(application, new Set(Object.keys(manifest.dependencies).map(name => {
    const ref = resolve('', name);
    if (!ref) throw new Error(`Missing direct dependency ${name}`);
    return ref;
  })));
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: { component: { type: 'application', 'bom-ref': application, name: manifest.name, version: manifest.version, purl: application, licenses: [{ license: { id: manifest.license } }] } },
    components: [...components.values()].sort((a, b) => a.purl.localeCompare(b.purl, 'en')),
    dependencies: [...dependencies].map(([ref, refs]) => ({ ref, dependsOn: [...refs].sort() })).sort((a, b) => a.ref.localeCompare(b.ref, 'en')),
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const sbom = createSbom();
  fs.writeFileSync(path.join(root, 'docs/sbom.cdx.json'), `${JSON.stringify(sbom, null, 2)}\n`);
  console.log(`Updated SBOM: ${sbom.components.length} locked components.`);
}
