/**
 * Unicode NFC conformance for receipt payloads.
 *
 * The spec says every string in a receipt MUST be Unicode NFC. Until now nothing enforced that at
 * any layer: `src/jcs.ts` deliberately does not normalize (normalizing at the canonicalizer would
 * MASK a producer/verifier disagreement instead of surfacing it — that reasoning is correct and is
 * unchanged here), and no verifier or builder checked. A receipt carrying an NFD `agent.id`
 * verified VALID in all four independent implementations. An unenforced MUST is how two
 * conforming implementations drift apart later, and it is how a canonicalization-map collision
 * stops being a paper problem.
 *
 * The asymmetry below is the point, and it is deliberate:
 *
 *   PRODUCE — hard failure. `buildReceipt` refuses to sign a non-NFC payload. This costs nothing in
 *   compatibility (a producer emitting non-NFC was already violating the spec) and it means this
 *   implementation can never mint another non-NFC receipt.
 *
 *   VERIFY — report, do not reject, by default. Receipts already issued must keep verifying;
 *   silently breaking them would be the worse failure. A non-NFC receipt is surfaced in `warnings`,
 *   and an operator who wants the strict rule today can pass `requireNFC: true` to get MALFORMED.
 *
 * The migration path to a mandatory verifier check is a wire-version boundary, not a patch: see
 * `docs/ietf/draft-noa-scitt-ai-agent-receipt.md` (Canonicalization parameters) and CHANGELOG.md.
 *
 * NOTE ON COST: `String.prototype.normalize` is not free, so the scan walks only the receipt's own
 * string fields (a receipt is a small, fixed-shape object) and short-circuits on the first
 * difference per string. It is O(total string bytes), once, on a surface that is already being
 * hashed.
 */
import { arrayPush, strCharCodeAt, strNormalize, isArray, objectKeys, arrayLength } from "./intrinsics.js";

/**
 * True iff `s` is already in Unicode Normalization Form C.
 *
 * Both lookups are CAPTURED (2026-07-29, round-1 re-run). They used to be live, and either one
 * flipped the opt-in `requireNFC: true` path from MALFORMED to VALID on a genuinely-signed
 * external receipt: `String.prototype.normalize -> identity` makes the comparison trivially true,
 * and `String.prototype.charCodeAt -> 65` never reports a byte above 0x7f, so the ASCII fast path
 * returns `true` without normalizing at all. The second one is the sharper lesson — the poison
 * catalogue already carried `charCodeAt -> always 65`, and it still could not see this call site,
 * because no fixture exercised `requireNFC` with a non-NFC receipt.
 */
export function isNFC(s: string): boolean {
  // Fast path: pure ASCII is always NFC, and receipts are overwhelmingly ASCII.
  for (let i = 0; i < s.length; i++) {
    if (strCharCodeAt(s, i) > 0x7f) return strNormalize(s, "NFC") === s;
  }
  return true;
}

/**
 * Walk an arbitrary JSON-ish value and return the dotted paths of every string — key OR value —
 * that is not NFC. Member NAMES are checked too: a non-NFC key is the same hazard as a non-NFC
 * value, and it additionally perturbs the JCS member sort.
 *
 * Returns an empty array for a fully-conforming value. Paths are capped (`limit`) so a hostile
 * payload cannot turn a diagnostic into an allocation attack.
 */
export function nonNfcPaths(value: unknown, limit = 16): string[] {
  const out: string[] = [];

  const walk = (v: unknown, path: string): void => {
    if (out.length >= limit) return;
    if (typeof v === "string") {
      if (!isNFC(v)) arrayPush(out, path);
      return;
    }
    if (isArray(v)) {
      const n = arrayLength(v);
      for (let i = 0; i < n && out.length < limit; i++) walk(v[i], `${path}[${i}]`);
      return;
    }
    if (typeof v === "object" && v !== null) {
      // CAPTURED (2026-07-29, round-2, R3-04). This walk was `for (const k of Object.keys(...))` with a
      // LIVE `Object.keys` and a LIVE `%ArrayIteratorPrototype%.next`: poisoning either (`Object.keys ->
      // []`, or an empty array iterator) hid the offending member so a genuinely non-NFC, correctly-signed
      // receipt passed `requireNFC:true` as VALID. `isNFC` was captured last round; `nonNfcPaths`, one call
      // deeper on the SAME verdict path, was not. Membership is now the captured `objectKeys` walked by
      // index — no live global read, no iterator dispatch.
      const keys = objectKeys(v as Record<string, unknown>);
      const kn = arrayLength(keys);
      for (let ki = 0; ki < kn; ki++) {
        if (out.length >= limit) return;
        const k = keys[ki]!;
        const child = path === "" ? k : `${path}.${k}`;
        if (!isNFC(k)) arrayPush(out, `${child} (member name)`);
        walk((v as Record<string, unknown>)[k], child);
      }
    }
  };

  walk(value, "");
  return out;
}
