import assert from 'node:assert/strict';
import test from 'node:test';
import { isPublicIp } from '../src/sources.mjs';

test('strict external transport rejects private, reserved and transition-network targets', () => {
  for (const address of [
    '127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.1.2', '198.51.100.7',
    '::1', '0:0:0:0:0:0:0:1', '0:0:0:0:0:ffff:127.0.0.1',
    'fd00::1', 'fe80::1', 'fec0::1', '64:ff9b::127.0.0.1', '0064:ff9b:0:0:0:0:7f00:1',
    '64:ff9b:1::a00:1', '0064:ff9b:0001:0:0:0:7f00:1',
    '100::1', '100:0:0:1::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2',
    '2001:2::1', '2002:7f00:1::', '3fff::1', '5f00::1',
  ]) assert.equal(isPublicIp(address), false, address);
  assert.equal(isPublicIp('8.8.8.8'), true);
  assert.equal(isPublicIp('2606:4700:4700::1111'), true);
});
