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
import { arrayPush } from "./intrinsics.js";

/** True iff `s` is already in Unicode Normalization Form C. */
export function isNFC(s: string): boolean {
  // Fast path: pure ASCII is always NFC, and receipts are overwhelmingly ASCII.
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7f) return s.normalize("NFC") === s;
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
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length && out.length < limit; i++) walk(v[i], `${path}[${i}]`);
      return;
    }
    if (typeof v === "object" && v !== null) {
      for (const k of Object.keys(v as Record<string, unknown>)) {
        if (out.length >= limit) return;
        const child = path === "" ? k : `${path}.${k}`;
        if (!isNFC(k)) arrayPush(out, `${child} (member name)`);
        walk((v as Record<string, unknown>)[k], child);
      }
    }
  };

  walk(value, "");
  return out;
}
