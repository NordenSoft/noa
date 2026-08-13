/**
 * S4 round-1 F14 — the grant-nonce format tripwire at the trust boundary.
 *
 * `nonces` is a public `CreateTrustInput` member and `localExecutionSigner` performs no post-sign
 * schema self-check, so before this guard an injected `() => "zz"` source minted gate-signed grants
 * that failed their own schema only downstream — and `() => "00".repeat(32)` would mint schema-valid
 * constant-nonce grants silently. Format is validated on EVERY draw (a construction-time probe draw
 * would shift injected deterministic sequences); entropy remains unenforceable at this boundary and
 * is deliberately not claimed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createAlphaTrust } from "../src/trust.js";

test("F14: an injected non-hex64 nonce source fails at the gate, loudly, on the draw", () => {
  const trust = createAlphaTrust({ tenant: "tenant-acme", nonces: () => "zz" });
  assert.throws(() => trust.newNonce(), /64 lowercase hex/, "a bad injected nonce must be refused with the named format rule");
});

test("F14: uppercase and short hex are refused too (the schema pins lowercase, exactly 64)", () => {
  for (const bad of ["9C".repeat(32), "9c".repeat(31), "9c".repeat(33), "", "9c".repeat(31) + "g1"]) {
    const trust = createAlphaTrust({ tenant: "tenant-acme", nonces: () => bad });
    assert.throws(() => trust.newNonce(), /64 lowercase hex/, `accepted: ${JSON.stringify(bad)}`);
  }
});

test("F14 anti-vacuity: a conforming injected source passes through verbatim, per draw", () => {
  const seq = ["9c".repeat(32), "8b".repeat(32)];
  let i = 0;
  const trust = createAlphaTrust({ tenant: "tenant-acme", nonces: () => seq[i++] as string });
  assert.equal(trust.newNonce(), "9c".repeat(32), "first draw must be the injected sequence's first value");
  assert.equal(trust.newNonce(), "8b".repeat(32), "the guard must not consume or reorder draws");
});

test("F14 anti-vacuity: the CSPRNG default satisfies its own gate and draws are distinct", () => {
  const trust = createAlphaTrust({ tenant: "tenant-acme" });
  const a = trust.newNonce();
  const b = trust.newNonce();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.match(b, /^[0-9a-f]{64}$/);
  assert.notEqual(a, b, "two default draws must differ");
});
