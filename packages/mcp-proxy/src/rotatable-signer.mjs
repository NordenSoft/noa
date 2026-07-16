/**
 * rotatable-signer.mjs (R2 #5) — signing-key ROTATION for the proxy's LOCAL signer.
 *
 * The problem it solves: a long-lived proxy should be able to retire its signing key and start
 * signing new receipts under a fresh key WITHOUT invalidating the receipts it already signed. In a
 * hash-chained, offline-verifiable design that reduces to one requirement — the verification keyring
 * must map EVERY kid the proxy has ever signed under (retired + current) to its public key, while
 * the private key used to SIGN is only ever the current one.
 *
 * This wraps a local `{ kid, privateKey, publicKey }` identity in an object that:
 *   - exposes `kid` + `privateKey` as live GETTERS reflecting the CURRENT key, so the exact same
 *     object can be handed to `createProxyServer({ signer })` and every subsequent buildReceipt call
 *     transparently picks up the current key — no proxy-code change, no per-transport fork; and
 *   - has NO `sign` method, so create-proxy-server.mjs's `typeof signer.sign === "function"` check
 *     keeps it firmly on the synchronous LOCAL path (this rotation helper is for local keys; a
 *     remote sidecar signer rotates on the sidecar's own side, out of this module's scope).
 *
 * `rotate(newKeyPair)` records the OUTGOING key's public key into a retired set and swaps the
 * current key in place. `keyring()` returns `{ [kid]: publicKey }` for retired + current keys — the
 * exact shape `verifyChain` / `verifyOutcomeReceipt` take — so every historical SEGMENT still
 * verifies (under just its own old kid, or under the combined keyring), while segments signed
 * post-rotation genuinely require the new kid (proving the swap is real, not cosmetic).
 *
 * ⚠️ ROTATE ONLY AT A CHAIN-SEGMENT BOUNDARY (between sessions, or at a process restart) — NEVER
 * mid-segment. This is a hard invariant, not a style preference: `verifyChain` enforces "one agent,
 * one kid PER CHAIN" and flags a kid swap for the same `agent.id` WITHIN a single chain as
 * **TAMPERED** (its whole point is to catch an attacker substituting keys mid-chain). Each proxy
 * session is its own segment (distinct `scope.chain`), so the realistic rotation is: session/segment
 * N signs under the old kid, the operator rotates, session/segment N+1 signs under the new kid.
 * Group receipts by `scope.chain` and verify each segment on its own (exactly as noa-receipt's
 * README already instructs) — the retired kid keeps verifying the old segments, the new kid verifies
 * the new ones, and the combined `keyring()` verifies them all. (This is DISTINCT from the R4
 * human-approval flow, where two DIFFERENT agent.ids — the proxy and the approver — legitimately
 * co-sign one chain under different kids; that is not a per-agent swap and is not flagged.)
 *
 * HONEST LIMITS: rotation does NOT re-key or re-sign historical receipts (that would destroy their
 * provenance), and covers the LOCAL signer only — a remote sidecar signer rotates on the sidecar's
 * own side. If an operator pins agent identity with a verifyChain identityManifest, that manifest
 * must list the kid each SEGMENT was signed under, or that segment reads UNTRUSTED — the manifest
 * doing its job, not a rotation bug.
 */

/**
 * @param {{ kid: string, privateKey: string, publicKey: string }} initialKeyPair
 * @returns {{
 *   readonly kid: string,
 *   readonly privateKey: string,
 *   readonly publicKey: string,
 *   readonly currentKid: string,
 *   rotate: (newKeyPair: { kid: string, privateKey: string, publicKey: string }) => any,
 *   keyring: () => Record<string,string>,
 *   retiredKids: () => string[],
 * }}
 */
export function createRotatableSigner(initialKeyPair) {
  if (!initialKeyPair || !initialKeyPair.kid || !initialKeyPair.privateKey || !initialKeyPair.publicKey) {
    throw new Error("createRotatableSigner: `initialKeyPair` with { kid, privateKey, publicKey } is required");
  }
  let current = { ...initialKeyPair };
  const retired = new Map(); // kid -> publicKey (historical verification material only; NO private keys kept)

  const signer = {
    // Live getters — buildReceipt reads `signer.kid` / `signer.privateKey` fresh on every call, so a
    // rotation between two calls takes effect immediately with zero proxy-code involvement.
    get kid() {
      return current.kid;
    },
    get privateKey() {
      return current.privateKey;
    },
    get publicKey() {
      return current.publicKey;
    },
    get currentKid() {
      return current.kid;
    },
    rotate(newKeyPair) {
      if (!newKeyPair || !newKeyPair.kid || !newKeyPair.privateKey || !newKeyPair.publicKey) {
        throw new Error("rotate: `newKeyPair` with { kid, privateKey, publicKey } is required");
      }
      if (newKeyPair.kid === current.kid) {
        throw new Error(`rotate: new kid "${newKeyPair.kid}" is identical to the current kid — rotation must change the kid`);
      }
      if (retired.has(newKeyPair.kid)) {
        throw new Error(`rotate: kid "${newKeyPair.kid}" was already retired — refusing to re-activate a retired signing identity`);
      }
      // Keep ONLY the retiring key's PUBLIC material for historical verification; drop its private key.
      retired.set(current.kid, current.publicKey);
      current = { ...newKeyPair };
      return signer;
    },
    keyring() {
      const kr = {};
      for (const [kid, pub] of retired) kr[kid] = pub;
      kr[current.kid] = current.publicKey; // current wins if a kid somehow appears twice (it cannot)
      return kr;
    },
    retiredKids() {
      return [...retired.keys()];
    },
  };
  return signer;
}
