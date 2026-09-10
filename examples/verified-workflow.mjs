import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createNovaService } from '../src/service.mjs';

const temporaryHome = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-one-example-'));
try {
  const nova = createNovaService({ home: temporaryHome });
  nova.initialize({ issuer: 'https://example.local/nova' });
  const result = await nova.runDemo();
  process.stdout.write(`${JSON.stringify({
    demo: result.demo,
    workflowId: result.workflow.workflowId,
    mode: result.workflow.mode,
    snapshotCount: result.workflow.snapshots.length,
    claims: result.workflow.context.claims.map(claim => ({ name: claim.name, status: claim.status })),
    agentCredential: {
      id: result.workflow.agentCredential.id,
      verified: result.verifiedAgentCredential.verified,
    },
    localAction: {
      id: result.workflow.action.action.id,
      status: result.workflow.action.action.status,
      receiptId: result.workflow.action.receipt.id,
    },
    auditCheckpointRoot: result.workflow.auditReceipt.checkpoint.root,
    capabilities: result.capabilities,
  }, null, 2)}\n`);
} finally {
  fs.rmSync(temporaryHome, { recursive: true, force: true });
}
