import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import type { KeyEntry } from 'noa-approval-artifacts';
import { verifyEvidence, type EvidenceBundle } from 'noa-approval-evidence';
import type { GateTrust } from 'noa-gate';
import { encodeDocument } from '../src/bytes.js';
import { verifyBundle } from '../src/evidence.js';
import type { Clock } from '../src/support.js';

type J = Record<string, unknown>;

const fixture = JSON.parse(
  readFileSync(new URL('../../evidence/conformance/valid/executed.json', import.meta.url), 'utf8'),
) as {
  bundle: EvidenceBundle;
  tenantRoot: Record<string, KeyEntry>;
  checkpointKeyring: Record<string, string>;
  now: string;
  maxAgeHours: number;
};

const authorityFixture = JSON.parse(
  readFileSync(new URL('../../evidence/conformance/control/step18-checkpoint-signer-current.json', import.meta.url), 'utf8'),
) as {
  bundle: EvidenceBundle;
  tenantRoot: Record<string, KeyEntry>;
  checkpointKeyring: Record<string, string>;
  now: string;
  maxAgeHours: number;
};

function trustWithCheckpointLifecycle(retiredAt: string | null): GateTrust {
  const checkpoint = fixture.bundle.checkpoint as unknown as J;
  const kid = (checkpoint['sig'] as J)['kid'] as string;
  const publicKey = fixture.checkpointKeyring[kid];
  if (!publicKey) throw new Error(`fixture checkpoint key ${kid} is absent from its control keyring`);
  return {
    gate: { kid, publicKey, privateKey: '' },
    receiptKeyring: {
      spec: 'noa.signing-key-lifecycle/0.1',
      keys: { [kid]: { publicKey, retiredAt } },
    },
  } as unknown as GateTrust;
}

export function runVerificationSurfaceProbe() {
  const checkpoint = fixture.bundle.checkpoint as unknown as J;
  const retiredAt = new Date(Date.parse(checkpoint['ts'] as string) + 30_000).toISOString();
  const currentTrust = trustWithCheckpointLifecycle(null);
  const retiredTrust = trustWithCheckpointLifecycle(retiredAt);
  const clock = { iso: () => fixture.now } as Clock;

  const honest = verifyBundle(fixture.bundle, currentTrust, fixture.tenantRoot, clock);
  const direct = verifyEvidence(encodeDocument(fixture.bundle), {
    tenantRoot: encodeDocument(fixture.tenantRoot),
    checkpointKeyring: encodeDocument(retiredTrust.receiptKeyring),
    now: fixture.now,
    maxAgeMs: fixture.maxAgeHours * 60 * 60 * 1000,
  });
  const wrapped = verifyBundle(fixture.bundle, retiredTrust, fixture.tenantRoot, clock);

  const manifestKeys = ((authorityFixture.bundle.keyManifest as unknown as J)['keys'] as J[]);
  const gateKey = manifestKeys.find((entry) => entry['kid'] === 'gate-prod-1');
  const checkpointKid = ((authorityFixture.bundle.checkpoint as unknown as J)['sig'] as J)['kid'] as string;
  const checkpointKey = manifestKeys.find((entry) => entry['kid'] === checkpointKid);
  if (!gateKey || !checkpointKey) throw new Error('authority fixture is missing its gate/checkpoint manifest entries');
  const mixedTrust = {
    gate: { kid: 'gate-prod-1', publicKey: gateKey['publicKey'], privateKey: '' },
    receiptKeyring: {
      spec: 'noa.signing-key-lifecycle/0.1',
      keys: {
        'gate-prod-1': { publicKey: gateKey['publicKey'], retiredAt: gateKey['revokedAt'] },
        [checkpointKid]: { publicKey: checkpointKey['publicKey'], retiredAt: checkpointKey['revokedAt'] },
      },
    },
  } as unknown as GateTrust;
  const authority = verifyBundle(
    authorityFixture.bundle,
    mixedTrust,
    authorityFixture.tenantRoot,
    { iso: () => authorityFixture.now } as Clock,
  );
  const authorityDirect = verifyEvidence(encodeDocument(authorityFixture.bundle), {
    tenantRoot: encodeDocument(authorityFixture.tenantRoot),
    checkpointKeyring: encodeDocument(authorityFixture.checkpointKeyring),
    now: authorityFixture.now,
    maxAgeMs: authorityFixture.maxAgeHours * 60 * 60 * 1000,
  });
  return { honest, direct, wrapped, authorityDirect, authority, authorityCheckpointKid: checkpointKid };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stdout.write(`${JSON.stringify(runVerificationSurfaceProbe())}\n`);
}
