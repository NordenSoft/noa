import { parseDocument } from "./bytes.js";
import type { Keyring } from "./keys.js";
import {
  arrayIncludes,
  dateParse,
  isArray,
  isNaNValue,
  jsonStringify,
  objectCreateNull,
  objectGetOwnPropertyNames,
} from "./intrinsics.js";
import { isRfc3339 } from "./scan.js";

/** Atomic public-key plus lifecycle-state trust document. */
export const SIGNING_KEY_LIFECYCLE_SPEC = "noa.signing-key-lifecycle/0.1";

export interface SigningKeyLifecycleEntry {
  readonly publicKey: string;
  /** Any non-null value marks the key retired. Artifact timestamps never override this state. */
  readonly retiredAt: string | null;
}

export interface SigningKeyLifecycle {
  readonly spec: typeof SIGNING_KEY_LIFECYCLE_SPEC;
  readonly keys: Readonly<Record<string, SigningKeyLifecycleEntry>>;
}

export interface ParsedVerificationKeyring {
  readonly keyring: Keyring;
  readonly retiredKids: Readonly<Record<string, true>>;
  readonly lifecycle: boolean;
}

export type ParseVerificationKeyringResult =
  | { readonly ok: true; readonly value: ParsedVerificationKeyring }
  | { readonly ok: false; readonly reason: string };

/**
 * Parse the one trust-root shape used by every JavaScript/TypeScript verification surface.
 *
 * Static `{ kid: publicKey }` maps remain supported for non-rotating consumers. Once lifecycle
 * state is supplied, it is inseparable from the public key: every non-null `retiredAt` marks that
 * kid unusable for all newly presented artifacts. A signer-chosen artifact timestamp cannot prove
 * that an artifact predates compromise; that requires an independent time witness.
 */
export function parseVerificationKeyring(
  document: Uint8Array | string,
  label = "keyring",
): ParseVerificationKeyringResult {
  const parsed = parseDocument(document, label);
  if (!parsed.ok) return parsed;
  const value = parsed.value;
  if (typeof value !== "object" || value === null || isArray(value)) {
    return { ok: false, reason: `${label} must be an object (static kid map or atomic signing key lifecycle)` };
  }

  const top = value as Record<string, unknown>;
  const topNames = objectGetOwnPropertyNames(top);
  const hasLifecycleSpec = arrayIncludes(topNames, "spec") && top.spec === SIGNING_KEY_LIFECYCLE_SPEC;
  const hasStructuredKeys = arrayIncludes(topNames, "keys") && typeof top.keys !== "string";
  const looksLikeLifecycle = hasLifecycleSpec || hasStructuredKeys;
  const keyring = objectCreateNull<Keyring>();
  const retiredKids = objectCreateNull<Record<string, true>>();

  if (!looksLikeLifecycle) {
    for (let i = 0; i < topNames.length; i++) {
      const kid = topNames[i] as string;
      const publicKey = top[kid];
      if (typeof publicKey !== "string" || publicKey.length === 0) {
        return { ok: false, reason: `${label} public key for signing key ${jsonStringify(kid)} must be a non-empty string` };
      }
      keyring[kid] = publicKey;
    }
    return { ok: true, value: { keyring, retiredKids, lifecycle: false } };
  }

  if (
    top.spec !== SIGNING_KEY_LIFECYCLE_SPEC
    || topNames.length !== 2
    || !arrayIncludes(topNames, "spec")
    || !arrayIncludes(topNames, "keys")
  ) {
    return { ok: false, reason: "malformed signing key lifecycle" };
  }
  const entries = top.keys;
  if (typeof entries !== "object" || entries === null || isArray(entries)) {
    return { ok: false, reason: "signing key lifecycle keys must be an object" };
  }
  const kids = objectGetOwnPropertyNames(entries);
  if (kids.length === 0) return { ok: false, reason: "signing key lifecycle must contain at least one key" };

  for (let i = 0; i < kids.length; i++) {
    const kid = kids[i] as string;
    const entry = (entries as Record<string, unknown>)[kid];
    if (typeof entry !== "object" || entry === null || isArray(entry)) {
      return { ok: false, reason: `lifecycle entry for signing key ${jsonStringify(kid)} must be an object` };
    }
    const fields = objectGetOwnPropertyNames(entry);
    if (
      fields.length !== 2
      || !arrayIncludes(fields, "publicKey")
      || !arrayIncludes(fields, "retiredAt")
    ) {
      return { ok: false, reason: `lifecycle entry for signing key ${jsonStringify(kid)} must contain exactly publicKey + retiredAt` };
    }
    const publicKey = (entry as Record<string, unknown>).publicKey;
    const retiredAt = (entry as Record<string, unknown>).retiredAt;
    if (typeof publicKey !== "string" || publicKey.length === 0) {
      return { ok: false, reason: `lifecycle publicKey for signing key ${jsonStringify(kid)} must be a non-empty string` };
    }
    if (
      retiredAt !== null
      && (typeof retiredAt !== "string" || !isRfc3339(retiredAt) || isNaNValue(dateParse(retiredAt)))
    ) {
      return { ok: false, reason: `lifecycle retiredAt for signing key ${jsonStringify(kid)} must be null or a parseable RFC 3339 instant` };
    }
    keyring[kid] = publicKey;
    if (retiredAt !== null) retiredKids[kid] = true;
  }

  return { ok: true, value: { keyring, retiredKids, lifecycle: true } };
}

export type ResolveVerificationKeyResult =
  | { readonly ok: true; readonly publicKey: string; readonly lifecycle: boolean }
  | { readonly ok: false; readonly reason: string };

/** Resolve a kid without permitting lifecycle state to be narrowed away. */
export function resolveVerificationKey(
  document: Uint8Array | string,
  kid: string,
): ResolveVerificationKeyResult {
  const parsed = parseVerificationKeyring(document);
  if (!parsed.ok) return parsed;
  if (parsed.value.retiredKids[kid] === true) {
    return {
      ok: false,
      reason: `signing key ${jsonStringify(kid)} is retired; signer-chosen artifact time is not an independent witness`,
    };
  }
  const publicKey = parsed.value.keyring[kid];
  if (!publicKey) return { ok: false, reason: `signing key ${jsonStringify(kid)} not in keyring` };
  return { ok: true, publicKey, lifecycle: parsed.value.lifecycle };
}
