/**
 * #77-C — WHAT THE HUMAN SEES MUST BE WHAT WAS SEALED.
 *
 * This is the product's core failure mode reached without touching a key, forging a signature, or
 * holding a network position. Every cryptographic check passes and the human approves the wrong
 * thing.
 *
 * ─── C/1: THE DISPLAY IS INTERPRETED THROUGH WRITABLE GLOBALS *AFTER* THE AEAD VERIFIES ─────────
 *
 *     const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
 *
 * By this line the ciphertext has already been authenticated. Both `TextDecoder.prototype.decode`
 * and the global `JSON.parse` are writable slots, so what the approver is SHOWN is decided after
 * authentication by something an attacker can replace. MEASURED, real seal→open with a real x25519
 * device key, live control and clean restoration:
 *
 *     CONTROL  human is shown -> "Wire EUR 2,400,000 to NEW payee GmbH"
 *     ATTACK   human is shown -> "Refund EUR 1.00 to Alice"      (via TextDecoder.decode)
 *     ATTACK   human is shown -> "Refund EUR 1.00 to Alice"      (via JSON.parse)
 *     POST     human is shown -> "Wire EUR 2,400,000 to NEW payee GmbH"
 *
 * ─── C/2: THE RECIPIENT SET IS BUILT THROUGH `Array.prototype.map` AT SEAL TIME ─────────────────
 *
 * MEASURED — this was a reviewer CLAIM until it was run:
 *     sealed recipients -> attacker-device
 *     attacker opens    -> "Wire EUR 2,400,000 to NEW payee GmbH"
 *     real approver     -> LOCKED OUT ("no recipient entry")
 * At seal time the CEK is in hand, so substituting the list genuinely hands the display to the
 * attacker AND denies it to the intended approver.
 *
 * ─── ATTACKER · VICTIM · CAPABILITY · OUTCOME ───────────────────────────────────────────────────
 *
 *   attacker    same-realm code loaded before the approval is rendered
 *   victim      the human approver, and the tenant they approve for
 *   capability  prototype pollution ONLY — no key, no signature forgery, no network position
 *   outcome     a genuine, correctly-signed approval attributed to a real human for an action they
 *               were never shown
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { sealEncryptedDisplay, openEncryptedDisplay } from "../src/encrypted-display.js";
import { bytesToHex } from "../src/bytes.js";
import { x25519 } from "@noble/curves/ed25519.js";

const DANGEROUS = { title: "Wire EUR 2,400,000 to NEW payee GmbH", risk: "CRITICAL", summary: ["payee: unrecognised"] };
const BENIGN_TITLE = "Refund EUR 1.00 to Alice";

/** Install a poisoned member, run `body`, restore the EXACT prior descriptor. */
function withPoison<T>(target: object, key: string, value: unknown, body: () => T): T {
  const prior = Object.getOwnPropertyDescriptor(target, key);
  Object.defineProperty(target, key, { value, writable: true, configurable: true });
  try {
    return body();
  } finally {
    if (prior === undefined) delete (target as Record<string, unknown>)[key];
    else Object.defineProperty(target, key, prior);
  }
}

function fixture() {
  const device = x25519.keygen();
  const kid = "approver-1-device-1";
  const ed = sealEncryptedDisplay({
    tenant: "acme-tenant",
    holdId: "hold-abc",
    deferredReceiptHash: "sha256:" + "a".repeat(64),
    expiresAt: "2026-07-15T12:05:00.000Z",
    display: DANGEROUS,
    recipients: [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }],
  });
  return { device, kid, ed, open: () => openEncryptedDisplay(ed, { kid, secretKey: device.secretKey }) };
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// C/1 — the rendered display must come from the authenticated plaintext, not from a live global.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-C/1: a poisoned `TextDecoder.prototype.decode` cannot substitute what the human sees", () => {
  const f = fixture();
  assert.equal(f.open()["title"], DANGEROUS.title, "the control is broken before the attack even starts");

  // PROOF THE VEHICLE IS LIVE: the poison must actually be reachable in this runtime.
  let fired = 0;
  withPoison(TextDecoder.prototype, "decode", function () { fired++; return "{}"; }, () => {
    new TextDecoder().decode(new Uint8Array([1]));
  });
  assert.ok(fired > 0, "`TextDecoder.prototype.decode` was not consulted — the fixture is not hostile");

  const shown = withPoison(TextDecoder.prototype, "decode",
    function () { return JSON.stringify({ title: BENIGN_TITLE, risk: "LOW" }); },
    () => {
      try { return { ok: true as const, title: f.open()["title"] }; }
      catch (e) { return { ok: false as const, err: e as Error }; }
    });

  if (shown.ok) {
    assert.equal(shown.title, DANGEROUS.title,
      "THE AEAD VERIFIED AND THE HUMAN WAS SHOWN A DIFFERENT ACTION THAN THE ONE SEALED. The " +
      "approval this produces is genuine, correctly signed, and attributed to a human who never " +
      "saw the action they authorised");
  }
  assert.equal(f.open()["title"], DANGEROUS.title, "the guarantee did not return after the poison was removed");
});

test("#77-C/1: a poisoned global `JSON.parse` cannot substitute what the human sees", () => {
  const f = fixture();
  const shown = withPoison(JSON, "parse", function () { return { title: BENIGN_TITLE, risk: "LOW" }; },
    () => {
      try { return { ok: true as const, title: f.open()["title"] }; }
      catch (e) { return { ok: false as const, err: e as Error }; }
    });
  if (shown.ok) {
    assert.equal(shown.title, DANGEROUS.title,
      "the display was replaced through the global `JSON.parse` after the AEAD had verified");
  }
  assert.equal(f.open()["title"], DANGEROUS.title, "the guarantee did not return after the poison was removed");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// C/2 — the sealed recipient set must be the caller's, not a poisoned iterator's.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-C/2: a poisoned `Array.prototype.map` cannot substitute the trusted device list", () => {
  const device = x25519.keygen();
  const attacker = x25519.keygen();
  const kid = "approver-1-device-1";
  const intended = [{ kid, hpkePublicKey: bytesToHex(device.publicKey) }];
  const realMap = Array.prototype.map;

  const sealed = withPoison(Array.prototype, "map",
    function (this: unknown[], cb: (v: unknown, i: number, a: unknown[]) => unknown, thisArg?: unknown) {
      if (this === intended) {
        return [cb.call(thisArg, { kid: "attacker-device", hpkePublicKey: bytesToHex(attacker.publicKey) }, 0, this)];
      }
      return (realMap as (c: unknown, t?: unknown) => unknown[]).call(this, cb, thisArg);
    },
    () => sealEncryptedDisplay({
      tenant: "acme-tenant", holdId: "hold-abc",
      deferredReceiptHash: "sha256:" + "a".repeat(64), expiresAt: "2026-07-15T12:05:00.000Z",
      display: DANGEROUS, recipients: intended,
    }));

  assert.deepEqual(sealed.recipients.map((r) => r.kid), [kid],
    "the SEALED recipient list is not the caller's — a poisoned iterator chose who may read this " +
    "approval, handing it to an attacker and locking out the intended approver");

  // and the intended approver must still be able to open it
  const opened = openEncryptedDisplay(sealed, { kid, secretKey: device.secretKey });
  assert.equal(opened["title"], DANGEROUS.title, "the intended approver cannot open a display sealed for them");
});

// ────────────────────────────────────────────────────────────────────────────────────────────────
// ANTI-VACUITY — the honest path must keep working, or "refuse everything" would pass above.
// ────────────────────────────────────────────────────────────────────────────────────────────────

test("#77-C ANTI-VACUITY: an ordinary seal→open round-trip returns the EXACT sealed display", () => {
  const f = fixture();
  assert.deepEqual(f.open(), DANGEROUS, "the ordinary round trip does not return the sealed display");
});

test("#77-C ANTI-VACUITY: the AEAD still rejects a tampered ciphertext and a wrong key", () => {
  const f = fixture();
  const tampered = structuredClone(f.ed) as typeof f.ed;
  tampered.payload.ciphertext = tampered.payload.ciphertext.slice(0, -4) + "AAAA";
  assert.throws(() => openEncryptedDisplay(tampered, { kid: f.kid, secretKey: f.device.secretKey }),
    /invalid tag|decrypt/i, "a tampered ciphertext was accepted");

  const stranger = x25519.keygen();
  assert.throws(() => openEncryptedDisplay(f.ed, { kid: f.kid, secretKey: stranger.secretKey }),
    /invalid tag|decrypt/i, "a wrong device key opened the display");
});

test("#77-C ANTI-VACUITY: the AAD still binds tenant, holdId, deferredReceiptHash and expiresAt", () => {
  // These four are what the AAD actually covers — measured. The binding audit's OPEN items
  // (recipient set, projection identity, challenge/nonce) are recorded in task #80 and PROGRESS.md
  // as an owner decision, NOT silently treated as bound here.
  for (const mutate of [
    (e: Record<string, unknown>) => { e["tenant"] = "other-tenant"; },
    (e: Record<string, unknown>) => { e["holdId"] = "hold-other"; },
    (e: Record<string, unknown>) => { e["deferredReceiptHash"] = "sha256:" + "b".repeat(64); },
    (e: Record<string, unknown>) => { e["expiresAt"] = "2099-01-01T00:00:00.000Z"; },
  ]) {
    const f = fixture();
    const t = structuredClone(f.ed) as unknown as Record<string, unknown>;
    mutate(t);
    assert.throws(() => openEncryptedDisplay(t, { kid: f.kid, secretKey: f.device.secretKey }),
      /aadHash|invalid tag/i, "an AAD-bound field was altered without detection");
  }
});
