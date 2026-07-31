/**
 * REGRESSION DEMONSTRATION for P0-14 / codex QA finding F-5.
 *
 * `createRotatableSigner(...).retirements()` supplies the separate temporal bounds that keep the
 * string-valued `keyring()` compatible with verifyChain. The defence refuses a NEW post-retirement
 * receipt when the caller passes those bounds. Omitting `retirements` intentionally preserves the
 * published-0.2.0 behaviour, so non-adopting library consumers remain exposed and the same receipt
 * still verifies in the BACKWARD-COMPATIBILITY control below.
 *
 * Read-only against the repo: this script imports the shipped source and writes nothing.
 * Anti-vacuity: the honest current-key path must VERIFY in the same run, and an unknown key must be
 * REFUSED — otherwise "it verified" would prove nothing about retirement specifically.
 */
import { generateKeyPairSync } from "node:crypto";
import { createRotatableSigner } from "/Users/toratoraman/noa-receipt/packages/mcp-proxy/src/rotatable-signer.mjs";
import { buildOutcomeReceipt, verifyOutcomeReceipt } from "/Users/toratoraman/noa-receipt/packages/mcp-proxy/src/outcome-receipt.mjs";

function kp(kid) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    kid,
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

const decisionReceipt = {
  id: "dec-0001",
  chain: { hash: "sha256:" + "a".repeat(64) },
};

const mkReceipt = (signer, ts) =>
  buildOutcomeReceipt(
    { decisionReceipt, tool: "wire.transfer", outcome: "success", ts },
    signer,
  );

const old = kp("kid-OLD");
const fresh = kp("kid-NEW");

const rot = createRotatableSigner(old, { now: () => Date.UTC(2026, 6, 15, 0, 0, 0, 0) });

// ── CONTROL 1: before any rotation, the current key signs and verifies. Harness works. ──────────
const before = mkReceipt(rot, "2026-07-14T12:00:00.000Z");
const r0 = verifyOutcomeReceipt(before, { keyring: rot.keyring() });
console.log("CONTROL 1  current key, pre-rotation      ->", JSON.stringify(r0));

// ── ROTATE. `old` is now RETIRED. In reality the operator rotates BECAUSE the old key is gone. ──
rot.rotate(fresh);
console.log("retiredKids after rotate                 ->", JSON.stringify(rot.retiredKids()));
console.log("keyring kids after rotate                ->", JSON.stringify(Object.keys(rot.keyring())));

// ── CONTROL 2: the NEW current key still signs and verifies. ────────────────────────────────────
const afterNew = mkReceipt(rot, "2026-07-15T12:00:00.000Z");
const r1 = verifyOutcomeReceipt(afterNew, { keyring: rot.keyring() });
console.log("CONTROL 2  new current key, post-rotation ->", JSON.stringify(r1));

// ── CONTROL 3: a key that was NEVER in the keyring is REFUSED. Proves the keyring gates anything.
const stranger = kp("kid-STRANGER");
const strangerSigner = { get kid() { return stranger.kid; }, get privateKey() { return stranger.privateKey; } };
const forgedByStranger = mkReceipt(strangerSigner, "2099-01-01T00:00:00.000Z");
const r2 = verifyOutcomeReceipt(forgedByStranger, { keyring: rot.keyring() });
console.log("CONTROL 3  unknown key                   ->", JSON.stringify(r2));

// ── THE ATTACK: the RETIRED private key signs a BRAND-NEW outcome, dated long after retirement. ──
const retiredSigner = { get kid() { return old.kid; }, get privateKey() { return old.privateKey; } };
const forged = mkReceipt(retiredSigner, "2099-01-01T00:00:00.000Z");
const attack = verifyOutcomeReceipt(forged, { keyring: rot.keyring(), retirements: rot.retirements() });
console.log("ATTACK     RETIRED key, ts=2099          ->", JSON.stringify(attack));
const backwardCompatibility = verifyOutcomeReceipt(forged, { keyring: rot.keyring() });
console.log("BACKWARD-COMPATIBILITY without retirements ->", JSON.stringify(backwardCompatibility));

console.log("\nreceipt kid   :", forged.sig.kid);
console.log("receipt ts    :", forged.ts);
console.log(
  "\nVERDICT:",
  !attack.ok && backwardCompatibility.ok
    ? "DEFENCE ACTIVE FOR ADOPTERS — retired key refused with retirements; legacy omission remains exposed"
    : "BROKEN — expected adopter refusal plus published-0.2.0 backward-compatible acceptance",
);
console.log(
  "controls:",
  r0.ok && r1.ok && !r2.ok
    ? "ALL GREEN (honest paths verify, unknown key refused) — the attack result is meaningful"
    : "BROKEN — the attack result means NOTHING, fix the harness first",
);
