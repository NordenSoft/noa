/**
 * P1-9 — THE KEY ENCODER MUST NOT HAND THE PRIVATE SEED TO A REPLACEABLE METHOD.
 *
 * `rawSeedToPkcs8Der` used to assemble its output with `der.set(seed, 16)`.
 * `Uint8Array.prototype.set` is a WRITABLE GLOBAL, and that call passed it the **raw 32-byte Ed25519
 * private seed as its first argument**.
 *
 * ─── WHY THE ASSERTION IS A HIT-COUNT AND NOT AN OUTPUT COMPARISON ───────────────────────────────
 *
 * This is a different consequence from the one #77-A closed in `signing.ts`. There, a replaced `set`
 * made the signed message a constant — the OUTPUT changed, so comparing output caught it.
 *
 * Here a replacement does not need to change anything. It can copy the seed, then call the real
 * method and return. **The DER is byte-identical, every existing test stays green, and the private
 * key has left the process.** Corruption is a bug; this is exfiltration of the key the product exists
 * to protect — and an output comparison is structurally blind to it.
 *
 * So the discriminator is: **was the replaceable method consulted at all?** A poison that is never
 * called cannot copy anything. That also makes the test honest about its own reach — an "output
 * unchanged" assertion passes trivially against a poison that never ran, which is the
 * `UNMEASURED`-scored-as-`HELD` failure `lint-verdict-differential.mjs` already names.
 *
 * The poison below is deliberately NON-DESTRUCTIVE: it counts, records what it was shown, and calls
 * through. If the encoder still used `.set()`, every assertion about the DER bytes would pass and
 * only `hits` would betray it. That is the whole point.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { rawSeedToPkcs8Der, rawPublicKeyToSpkiDer, pkcs8Ed25519ToRawSeed, spkiEd25519ToRawPublicKey } from "../src/der.js";

const SEED = Uint8Array.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff));
const PUB = Uint8Array.from(Array.from({ length: 32 }, (_, i) => (i * 11 + 5) & 0xff));

/** Install a counting, call-through poison on `Uint8Array.prototype.set`. Restores in `finally`. */
function withCountingPoison<T>(fn: () => T): { value: T; hits: number; sawSeed: boolean } {
  const real = Uint8Array.prototype.set;
  let hits = 0;
  let sawSeed = false;
  // eslint-disable-next-line no-extend-native
  Uint8Array.prototype.set = function poisoned(this: Uint8Array, src: ArrayLike<number>, offset?: number) {
    hits++;
    // What an exfiltrating replacement would do: read the argument, keep it, call through.
    if (src && (src as ArrayLike<number>).length === 32) {
      let same = true;
      for (let i = 0; i < 32; i++) if ((src as ArrayLike<number>)[i] !== SEED[i]) { same = false; break; }
      if (same) sawSeed = true;
    }
    return (real as (s: ArrayLike<number>, o?: number) => void).call(this, src, offset);
  } as typeof Uint8Array.prototype.set;
  try {
    return { value: fn(), hits, sawSeed };
  } finally {
    Uint8Array.prototype.set = real;
  }
}

/** ANTI-VACUITY, FIRST. If the poison cannot be observed at all, every hit-count of 0 below is
 *  meaningless — it would prove the harness is broken, not that the encoder is clean. */
test("CONTROL — the counting poison IS observable on a call site that still uses .set()", () => {
  const probe = withCountingPoison(() => {
    const out = new Uint8Array(32);
    out.set(SEED, 0); // a deliberate `.set()` call, so the harness must see it
    return out;
  });
  assert.equal(probe.hits, 1, "the poison was not installed or not consulted — the tests below prove nothing");
  assert.equal(probe.sawSeed, true, "the poison could not read its argument, so it cannot model exfiltration");
});

test("P1-9: encoding a PRIVATE seed to PKCS8 DER never consults Uint8Array.prototype.set", () => {
  const run = withCountingPoison(() => rawSeedToPkcs8Der(SEED));

  assert.equal(run.sawSeed, false,
    "THE PRIVATE SEED WAS HANDED TO A REPLACEABLE METHOD. A replacement that copies it and calls " +
      "through leaves the DER byte-identical and every other test green — this is exfiltration, not " +
      "corruption, and no output comparison can see it.");
  assert.equal(run.hits, 0,
    "the key encoder dispatched through Uint8Array.prototype.set. Assemble by index: integer-indexed " +
      "writes on a typed array are handled by the exotic object's own internal method and consult no " +
      "prototype.");

  // The encoding must still be CORRECT — a hardening that broke the format would pass the two
  // assertions above and ship an unusable key.
  const roundTripped = pkcs8Ed25519ToRawSeed(run.value);
  assert.deepEqual(Array.from(roundTripped), Array.from(SEED), "the hardened encoder no longer round-trips");
});

test("P1-9: encoding a PUBLIC key to SPKI DER never consults Uint8Array.prototype.set either", () => {
  // Lower stakes — no secret passes through — but a replaced `set` can still swap the encoded key,
  // and a keyring entry that is not the key it claims to be is its own defect. Fixed as the
  // neighbour, because this project produced a CRITICAL in three consecutive releases by fixing one
  // site and leaving the one beside it.
  const run = withCountingPoison(() => rawPublicKeyToSpkiDer(PUB));
  assert.equal(run.hits, 0, "the public-key encoder still dispatches through a replaceable method");
  assert.deepEqual(Array.from(spkiEd25519ToRawPublicKey(run.value)), Array.from(PUB),
    "the hardened public-key encoder no longer round-trips");
});

test("CONTROL — with NO poison installed the encoders produce the identical bytes", () => {
  // Pins that the hit-count assertions above are not passing because the encoders stopped working.
  assert.equal(rawSeedToPkcs8Der(SEED).length > 0, true);
  assert.deepEqual(Array.from(pkcs8Ed25519ToRawSeed(rawSeedToPkcs8Der(SEED))), Array.from(SEED));
  assert.deepEqual(Array.from(spkiEd25519ToRawPublicKey(rawPublicKeyToSpkiDer(PUB))), Array.from(PUB));
});
