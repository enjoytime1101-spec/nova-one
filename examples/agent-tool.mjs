import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createNovaToolExecutor } from '../agent-tools/index.mjs';
import { createNovaService } from '../src/service.mjs';

const temporaryHome = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-one-tool-example-'));
try {
  const service = createNovaService({ home: temporaryHome });
  service.initialize({ issuer: 'https://example.local/nova' });
  const tools = createNovaToolExecutor({ service });
  const issued = await tools.callTool('nova_issue_credential', {
    type: 'IdentityCredential',
    subject: 'did:example:agent-tool',
    claims: { accountActive: true, assurance: 'local-issuer-attestation' },
    audience: 'agent-tool-example',
    purpose: 'demonstrate-agent-tool',
  });
  const verified = await tools.callTool('nova_verify_credential', {
    token: issued.token,
    subject: 'did:example:agent-tool',
    audience: 'agent-tool-example',
    purpose: 'demonstrate-agent-tool',
  });
  process.stdout.write(`${JSON.stringify({ credentialId: issued.id, verified }, null, 2)}\n`);
} finally {
  fs.rmSync(temporaryHome, { recursive: true, force: true });
}
