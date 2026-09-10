import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { startNovaHttpServer } from '../src/http.mjs';
import { createNovaService } from '../src/service.mjs';

const temporaryHome = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-one-http-example-'));
const nova = createNovaService({ home: temporaryHome });
const initialized = nova.initialize({ issuer: 'https://example.local/nova' });
const running = await startNovaHttpServer({ service: nova, host: '127.0.0.1', port: 0, bodyLimit: 4096 });

try {
  const headers = { authorization: `Bearer ${initialized.apiToken}`, 'content-type': 'application/json' };
  const healthResponse = await fetch(`${running.url}/health`);
  const health = await healthResponse.json();
  if (!healthResponse.ok || !health.ok) throw new Error(JSON.stringify(health));

  const unauthenticatedResponse = await fetch(`${running.url}/v1/status`);
  if (unauthenticatedResponse.status !== 401) throw new Error(`Expected unauthenticated status 401, received ${unauthenticatedResponse.status}.`);

  const oversizedResponse = await fetch(`${running.url}/v1/demo`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ subject: 'x'.repeat(8192) }),
  });
  if (oversizedResponse.status !== 413) throw new Error(`Expected oversized status 413, received ${oversizedResponse.status}.`);

  const issuedResponse = await fetch(`${running.url}/v1/credentials/issue`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      type: 'IdentityCredential',
      subject: 'did:example:http-client',
      claims: { accountActive: true, assurance: 'local-issuer-attestation' },
      audience: 'http-example',
      purpose: 'demonstrate-http-api',
    }),
  });
  const issuedBody = await issuedResponse.json();
  if (!issuedResponse.ok) throw new Error(JSON.stringify(issuedBody));

  const verifiedResponse = await fetch(`${running.url}/v1/credentials/verify`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      token: issuedBody.result.token,
      subject: 'did:example:http-client',
      audience: 'http-example',
      purpose: 'demonstrate-http-api',
    }),
  });
  const verifiedBody = await verifiedResponse.json();
  if (!verifiedResponse.ok) throw new Error(JSON.stringify(verifiedBody));
  process.stdout.write(`${JSON.stringify({
    health,
    protections: { unauthenticatedStatus: unauthenticatedResponse.status, oversizedStatus: oversizedResponse.status },
    verification: verifiedBody,
  }, null, 2)}\n`);
} finally {
  await running.close();
  fs.rmSync(temporaryHome, { recursive: true, force: true });
}
