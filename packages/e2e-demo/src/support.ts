/**
 * Small deterministic support primitives: a controllable clock (so the timeout state machine and
 * checkpoint-freshness are testable with ZERO wall-clock sleeps), a monotonic id source, and the
 * one key-format conversion the relay needs (its device registry stores raw-hex Ed25519 keys,
 * while the manifest/keyring everywhere else uses base64 DER SPKI).
 */
import { spkiEd25519ToRawPublicKey, bytesToHex } from 'noa-signer';

/** A mutable logical clock. The gate + relay read `now()`; tests `advance()` it to cross a TTL
 *  boundary instantly. Real deployments pass `Date.now`. */
export interface Clock {
  now(): number;
  iso(): string;
  advance(ms: number): void;
}

export function makeClock(startIso = '2026-07-14T12:00:00.000Z'): Clock {
  let t = Date.parse(startIso);
  return {
    now: () => t,
    iso: () => new Date(t).toISOString(),
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** Deterministic, monotonic id source (hex counter) so a run is reproducible. */
export function makeIds(prefix = 'id'): () => string {
  let n = 0;
  return () => `${prefix}-${(n++).toString(16).padStart(8, '0')}`;
}

/** base64 DER SPKI Ed25519 public key → raw 32-byte lowercase hex (the relay device-registry shape). */
export function spkiToRawHex(spkiB64: string): string {
  return bytesToHex(spkiEd25519ToRawPublicKey(spkiB64));
}
