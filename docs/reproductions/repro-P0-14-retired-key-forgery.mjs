/**
 * P0-14 regression probe: atomic key lifecycle, backdated outcomes, and fresh chain segments.
 *
 * The outcome verifier refuses every retired-key outcome because its standalone signer-chosen `ts`
 * cannot distinguish genuine history from attacker backdating. The chain verifier retains a
 * retirement cutoff so timestamped pre-cutoff chain history remains readable. The final LIMIT probe
 * deliberately shows why this is not complete stolen-key containment: the retired key can backdate a
 * fresh chain segment until an independent time witness (packages/tsa-anchor, unpublished) is used.
 */
import {
  generateKeyPair,
  buildReceipt,
  buildCheckpoint,
  verifyChain,
  sha256Prefixed,
} from "/Users/toratoraman/noa-receipt/dist/src/index.js";
import { createRotatableSigner } from "/Users/toratoraman/noa-receipt/packages/mcp-proxy/src/rotatable-signer.mjs";
import { buildOutcomeReceipt, verifyOutcomeReceipt } from "/Users/toratoraman/noa-receipt/packages/mcp-proxy/src/outcome-receipt.mjs";

const b = (value) => new TextEncoder().encode(JSON.stringify(value));
const RETIRED_AT = "2026-08-01T08:36:12.643Z";
const AFTER = "2026-08-01T08:36:12.644Z";
const BEFORE = "2020-01-01T00:00:00.000Z";

const decisionReceipt = {
  id: "dec-0001",
  chain: { hash: `sha256:${"a".repeat(64)}` },
};

const mkOutcome = (signer, ts) => buildOutcomeReceipt(
  { decisionReceipt, tool: "wire.transfer", outcome: "success", ts },
  signer,
);

const mkSegment = (signer, id, ts) => buildReceipt({
  id,
  ts,
  scope: { chain: `chain-${id}`, tenant: "tenant-p0-14" },
  agent: { id: "proxy-p0-14", model: null, principal: "SERVICE" },
  action: {
    id: "wire.transfer",
    canonical: "wire.transfer",
    riskClass: "HIGH",
    paramsHash: sha256Prefixed(id),
    reversible: false,
    rollbackRef: null,
  },
  governance: { mode: "on", verdict: "EXECUTED", ruleId: null, approval: null, sandboxed: false },
}, null, { kid: signer.kid, privateKey: signer.privateKey });

const oldKey = generateKeyPair("repro-p0-14-old");
const currentKey = generateKeyPair("repro-p0-14-current");
const unknownKey = generateKeyPair("repro-p0-14-unknown");
const staticKey = generateKeyPair("repro-p0-14-static");
const rotatable = createRotatableSigner(oldKey, { now: () => Date.parse(RETIRED_AT) });

const genuineHistoricalOutcome = mkOutcome(oldKey, BEFORE);
rotatable.rotate(currentKey);
const lifecycle = rotatable.verificationLifecycle();
const historicalKeyring = rotatable.historicalKeyring();

const currentOutcome = verifyOutcomeReceipt(mkOutcome(rotatable, AFTER), { verification: lifecycle });
const unknownOutcome = verifyOutcomeReceipt(mkOutcome(unknownKey, AFTER), { verification: lifecycle });
const retiredAfter = verifyOutcomeReceipt(mkOutcome(oldKey, AFTER), { verification: lifecycle });
const retiredBackdated = verifyOutcomeReceipt(mkOutcome(oldKey, BEFORE), { verification: lifecycle });
const historicalUnwitnessed = verifyOutcomeReceipt(genuineHistoricalOutcome, { verification: lifecycle });
const missingLifecycle = verifyOutcomeReceipt(mkOutcome(oldKey, AFTER), { verification: historicalKeyring });
const staticOutcome = verifyOutcomeReceipt(mkOutcome(staticKey, AFTER), {
  verification: { [staticKey.kid]: staticKey.publicKey },
});

const currentSegment = mkSegment(currentKey, "current", AFTER);
const currentChain = verifyChain(b([currentSegment]), { keyring: b(lifecycle) });
const retiredFreshChain = verifyChain(b([mkSegment(oldKey, "retired-fresh", AFTER)]), { keyring: b(lifecycle) });
const historicalChain = verifyChain(b([mkSegment(oldKey, "historical", BEFORE)]), { keyring: b(lifecycle) });
const backdatedFreshChain = verifyChain(b([mkSegment(oldKey, "retired-backdated", BEFORE)]), { keyring: b(lifecycle) });
const staticChain = verifyChain(
  b([mkSegment(staticKey, "static", AFTER)]),
  { keyring: b({ [staticKey.kid]: staticKey.publicKey }) },
);
const retiredCheckpoint = verifyChain(b([currentSegment]), {
  keyring: b(lifecycle),
  checkpoint: b(buildCheckpoint(currentSegment, AFTER, oldKey)),
});
const currentCheckpoint = verifyChain(b([currentSegment]), {
  keyring: b(lifecycle),
  checkpoint: b(buildCheckpoint(currentSegment, AFTER, currentKey)),
});

console.log("CONTROL current outcome                         ->", JSON.stringify(currentOutcome));
console.log("CONTROL static non-rotating outcome             ->", JSON.stringify(staticOutcome));
console.log("CONTROL unknown kid                              ->", JSON.stringify(unknownOutcome));
console.log("ATTACK  retired outcome ts AFTER retirement      ->", JSON.stringify(retiredAfter));
console.log("ATTACK  retired outcome ts BEFORE (BACKDATED)    ->", JSON.stringify(retiredBackdated));
console.log("DESIGN  genuine pre-retirement outcome, no TSA   ->", JSON.stringify(historicalUnwitnessed));
console.log("ATTACK  missing lifecycle, historical flat map   ->", JSON.stringify(missingLifecycle));
console.log("CONTROL current-key fresh chain segment          ->", currentChain.status, currentChain.reason ?? "");
console.log("ATTACK  retired-key fresh chain segment          ->", retiredFreshChain.status, retiredFreshChain.reason ?? "");
console.log("CONTROL pre-cutoff historical chain segment      ->", historicalChain.status, historicalChain.reason ?? "");
console.log("CONTROL static non-rotating chain consumer       ->", staticChain.status, staticChain.reason ?? "");
console.log("CONTROL current-key checkpoint                  ->", currentCheckpoint.status, `tailChecked=${currentCheckpoint.tailChecked}`);
console.log("ATTACK  retired-key post-cutoff checkpoint       ->", retiredCheckpoint.status, retiredCheckpoint.reason ?? "");
console.log("LIMIT   retired-key BACKDATED fresh chain segment ->", backdatedFreshChain.status, backdatedFreshChain.reason ?? "");

const controlsPass = currentOutcome.ok
  && staticOutcome.ok
  && !unknownOutcome.ok
  && unknownOutcome.reason === `kid ${JSON.stringify(unknownKey.kid)} not in keyring`
  && currentChain.status === "VALID"
  && historicalChain.status === "VALID"
  && staticChain.status === "VALID"
  && currentCheckpoint.status === "VALID"
  && currentCheckpoint.tailChecked;
const attacksRefused = !retiredAfter.ok
  && !retiredBackdated.ok
  && !historicalUnwitnessed.ok
  && !missingLifecycle.ok
  && retiredFreshChain.status === "TAMPERED"
  && retiredCheckpoint.status === "TAMPERED";
const nonClaimMeasured = backdatedFreshChain.status === "VALID";

console.log("\ncontrols:", controlsPass ? "PASS" : "BROKEN");
console.log("bounded defenses:", attacksRefused ? "PASS" : "BROKEN");
console.log(
  "non-claim:",
  nonClaimMeasured
    ? "MEASURED — cutoff is not complete containment; independent time witness still required"
    : "CHANGED — re-evaluate the documented independent-time-witness limitation",
);
if (!controlsPass || !attacksRefused || !nonClaimMeasured) process.exitCode = 1;
