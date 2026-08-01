import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runVerificationSurfaceProbe } from './verification-surface-probe.js';

test('P0-14 verifyBundle preserves checkpoint retirement and gate-only checkpoint authority', () => {
  const { honest, direct, wrapped, authority, authorityCheckpointKid } = runVerificationSurfaceProbe();
  assert.equal(
    honest.verdict,
    'VALID_FULL_CHAIN',
    `wrapper control cannot accept the committed valid bundle: ${honest.verdict} (${honest.reason ?? ''})`,
  );

  assert.equal(direct.verdict, 'INVALID', 'direct verifyEvidence accepted the retired checkpoint key');
  assert.match(direct.reason ?? '', /retired/i, 'direct control refused for a reason other than retirement');

  assert.equal(
    wrapped.verdict,
    'INVALID',
    `verifyBundle discarded retirement and returned ${wrapped.verdict}`,
  );
  assert.match(wrapped.reason ?? '', /retired/i, 'wrapper refused for a reason other than retirement');

  assert.equal(authorityCheckpointKid, 'approver-crit-5', 'authority attack is not using the intended non-gate signer');
  assert.equal(
    authority.verdict,
    'VALID_SEGMENT_ONLY',
    `an approver-signed checkpoint was not confined to unanchored segment validity: ${authority.verdict} (${authority.reason ?? ''})`,
  );
});
