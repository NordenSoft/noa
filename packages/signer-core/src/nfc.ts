/**
 * Unicode NFC conformance for receipt payloads — the signer-core mirror of `src/nfc.ts` in
 * noa-receipt.
 *
 * This package is an INDEPENDENT signing implementation (its own JCS, its own builder), which is
 * exactly why this file has to exist rather than importing the other one: the producer-side NFC
 * invariant was enforced in noa-receipt's builder only, so anything signed through THIS package
 * bypassed it and the guarantee "nothing NOA signs is non-NFC" was not universal. A rule enforced
 * in one of two producers is not an invariant, it is a coincidence.
 *
 * Kept deliberately small and dependency-free, matching this package's posture. Behaviour is
 * identical to noa-receipt's: pure-ASCII fast path, member NAMES checked as well as values, output
 * capped so a hostile payload cannot turn a diagnostic into an allocation attack.
 */

/** True iff `s` is already in Unicode Normalization Form C. */
export function isNFC(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7f) return s.normalize("NFC") === s;
  }
  return true;
}

/** Dotted paths of every non-NFC string (key or value) in `value`; empty when fully conforming. */
export function nonNfcPaths(value: unknown, limit = 16): string[] {
  const out: string[] = [];
  const walk = (v: unknown, path: string): void => {
    if (out.length >= limit) return;
    if (typeof v === "string") {
      if (!isNFC(v)) out.push(path);
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
        if (!isNFC(k)) out.push(`${child} (member name)`);
        walk((v as Record<string, unknown>)[k], child);
      }
    }
  };
  walk(value, "");
  return out;
}
