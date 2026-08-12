import { parseCanonicalInstant, SIGNING_KEY_LIFECYCLE_SPEC } from "./outcome-receipt.mjs";
import { intrinsics } from "noa-mcp-adapter-core";

// The kernel's module-load capture, for the ONE thing this file cannot capture for itself: an array
// prototype with no `Object.prototype` at the end of it (see `retiredKids` below).
const { objectSetPrototypeOf, INERT_ARRAY_PROTOTYPE } = intrinsics;

// Capture the default clock when this module loads, so replacing Date.now afterwards cannot move a
// retirement bound. This defends post-load mutation only: a Date.now poisoned before module
// evaluation is already the captured input and is outside this module's ability to detect. Callers
// that require a trustworthy retirement instant must inject `options.now` from a trusted source;
// this helper cannot self-verify a clock input.
const moduleLoadDateNow = Date.now;
const freezeCaptured = Object.freeze;
const createCaptured = Object.create;
const definePropertiesCaptured = Object.defineProperties;
const getPrototypeOfCaptured = Object.getPrototypeOf;
const applyCaptured = Reflect.apply;
const MapCaptured = Map;
const mapEntriesCaptured = MapCaptured.prototype.entries;
const mapHasCaptured = MapCaptured.prototype.has;
const mapSetCaptured = MapCaptured.prototype.set;
const emptyMapIterator = applyCaptured(mapEntriesCaptured, new MapCaptured(), []);
const mapIteratorNextCaptured = getPrototypeOfCaptured(emptyMapIterator).next;

function forEachMapEntryCaptured(map, visit) {
  const iterator = applyCaptured(mapEntriesCaptured, map, []);
  while (true) {
    const step = applyCaptured(mapIteratorNextCaptured, iterator, []);
    if (step.done) return;
    visit(step.value[0], step.value[1]);
  }
}

/**
 * rotatable-signer.mjs (R2 #5) — signing-key ROTATION for the proxy's LOCAL signer.
 *
 * The problem it solves: a long-lived proxy should be able to retire its signing key and start
 * signing new receipts under a fresh key while keeping the old public key plus its retirement state
 * available for explicit rejection and audit display. The verification lifecycle maps every kid the proxy signed under
 * to its public key and temporal state, while the private key used to SIGN is only the current one.
 *
 * This wraps a local `{ kid, privateKey, publicKey }` identity in an object that:
 *   - exposes `kid` + `privateKey` as live GETTERS reflecting the CURRENT key, so the exact same
 *     object can be handed to `createProxyServer({ signer })` and every subsequent buildReceipt call
 *     transparently picks up the current key — no proxy-code change, no per-transport fork; and
 *   - has NO `sign` method, so create-proxy-server.mjs's `typeof signer.sign === "function"` check
 *     keeps it firmly on the synchronous LOCAL path (this rotation helper is for local keys; a
 *     remote sidecar signer rotates on the sidecar's own side, out of this module's scope).
 *
 * `rotate(newKeyPair)` records the OUTGOING key's public key + retirement instant and swaps the
 * current key in place. `verificationLifecycle()` returns one stable, frozen handle whose `keys`
 * getter produces a fresh frozen snapshot on every read. A caller may cache the handle without
 * caching pre-rotation authority. The previous `keyring()` + `retirements()` pair was removed in
 * 0.3.0: rotation could occur between those calls, and omitting the second call silently discarded
 * the only retirement information.
 *
 * There is deliberately no historical flat-key export. Such an export would strip the only field
 * that distinguishes a retired key from a current key and turn a security downgrade into a
 * convenience API. `verifyChain` accepts the atomic lifecycle document through its existing
 * `keyring` option, while a genuinely static, non-rotating keyring keeps its flat shape.
 *
 * ⚠️ ROTATE ONLY AT A CHAIN-SEGMENT BOUNDARY (between sessions, or at a process restart) — NEVER
 * mid-segment. This is a hard invariant, not a style preference: `verifyChain` enforces "one agent,
 * one kid PER CHAIN" and flags a kid swap for the same `agent.id` WITHIN a single chain as
 * **TAMPERED** (its whole point is to catch an attacker substituting keys mid-chain). Each proxy
 * session is its own segment (distinct `scope.chain`), so the realistic rotation is: session/segment
 * N signs under the old kid, the operator rotates, session/segment N+1 signs under the new kid.
 * Group receipts by `scope.chain` and verify each segment on its own (exactly as noa-receipt's
 * README already instructs) — the lifecycle handle makes old segments explicitly unverifiable after
 * retirement and lets the new kid verify current segments. (This is DISTINCT from the R4
 * human-approval flow, where two DIFFERENT agent.ids — the proxy and the approver — legitimately
 * co-sign one chain under different kids; that is not a per-agent swap and is not flagged.)
 *
 * HONEST LIMITS: rotation does NOT re-key or re-sign historical receipts (that would destroy their
 * provenance), and covers the LOCAL signer only — a remote sidecar signer rotates on the sidecar's
 * own side. A compromised key can backdate a chain receipt because its timestamp is covered only by
 * that same key; distinguishing genuine history from a backdated forgery requires an independent
 * time witness. Until one is supplied, every non-null retirement is refused. If an
 * operator pins agent identity with a verifyChain identityManifest, that manifest must list the kid
 * each SEGMENT was signed under, or that segment reads UNTRUSTED.
 */

/**
 * @param {{ kid: string, privateKey: string, publicKey: string }} initialKeyPair
 * @param {{ now?: () => number }} [options] clock returning epoch milliseconds (defaults to the module-load snapshot of Date.now)
 * @returns {{
 *   readonly kid: string,
 *   readonly privateKey: string,
 *   readonly publicKey: string,
 *   readonly currentKid: string,
 *   rotate: (newKeyPair: { kid: string, privateKey: string, publicKey: string }) => any,
 *   verificationLifecycle: () => { spec: string, keys: Record<string,{ publicKey: string, retiredAt: string|null }> },
 *   retiredKids: () => string[],
 * }}
 */
export function createRotatableSigner(initialKeyPair, options = {}) {
  if (!initialKeyPair || !initialKeyPair.kid || !initialKeyPair.privateKey || !initialKeyPair.publicKey) {
    throw new Error("createRotatableSigner: `initialKeyPair` with { kid, privateKey, publicKey } is required");
  }
  const now = options?.now ?? moduleLoadDateNow;
  if (typeof now !== "function") throw new Error("createRotatableSigner: `now` must be a function");
  let current = { ...initialKeyPair };
  // kid -> { publicKey, retiredAt }; historical verification material only, with NO private keys kept.
  const retired = new MapCaptured();

  const snapshotKeys = () => {
    const keys = createCaptured(null);
    forEachMapEntryCaptured(retired, (kid, entry) => {
      keys[kid] = freezeCaptured({ publicKey: entry.publicKey, retiredAt: entry.retiredAt });
    });
    keys[current.kid] = freezeCaptured({ publicKey: current.publicKey, retiredAt: null });
    return freezeCaptured(keys);
  };
  const lifecycleHandle = createCaptured(null);
  definePropertiesCaptured(lifecycleHandle, {
    spec: { value: SIGNING_KEY_LIFECYCLE_SPEC, enumerable: true },
    keys: { get: snapshotKeys, enumerable: true },
  });
  freezeCaptured(lifecycleHandle);

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
      if (applyCaptured(mapHasCaptured, retired, [newKeyPair.kid])) {
        throw new Error(`rotate: kid "${newKeyPair.kid}" was already retired — refusing to re-activate a retired signing identity`);
      }
      const nowMs = now();
      if (typeof nowMs !== "number" || !Number.isFinite(nowMs)) {
        throw new Error("rotate: clock `now()` must return finite epoch milliseconds");
      }
      if (!Number.isInteger(nowMs)) {
        throw new Error("rotate: clock `now()` must return integer epoch milliseconds");
      }
      // WITHDRAWN CLAIM (preserved verbatim): "It either yields the required YYYY-MM-DDTHH:MM:SS.mmmZ form or throws before state changes, so a malformed retirement instant can never be recorded by this helper."
      // That claim trusted mutable Date.prototype.toISOString. The formatter output is now accepted
      // only when the Date-free canonical parser round-trips it to the injected clock exactly.
      const retiredAt = new Date(nowMs).toISOString();
      if (parseCanonicalInstant(retiredAt) !== nowMs) {
        throw new Error("rotate: clock/formatter produced an instant that does not represent `now()`; rotation was not recorded");
      }
      // Keep ONLY the retiring key's PUBLIC material + retirement bound; drop its private key.
      applyCaptured(mapSetCaptured, retired, [current.kid, { publicKey: current.publicKey, retiredAt }]);
      current = { ...newKeyPair };
      return signer;
    },
    verificationLifecycle() {
      return lifecycleHandle;
    },
    retiredKids() {
      // INERT FROM ITS FIRST WRITE: `kids[kids.length] = kid` is a `[[Set]]`, and `[[Set]]` walks
      // the receiver's prototype chain. An accessor at `Object.prototype["0"]` swallows the first
      // retired kid while `length` still advances, so a retired signing key would be reported as
      // never retired. Same class as the params-hash substitution measured in adapter-core.
      const kids = [];
      objectSetPrototypeOf(kids, INERT_ARRAY_PROTOTYPE);
      forEachMapEntryCaptured(retired, (kid) => {
        kids[kids.length] = kid;
      });
      return kids;
    },
  };
  return signer;
}
