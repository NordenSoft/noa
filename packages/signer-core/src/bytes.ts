/**
 * Portable byte <-> string codecs. Deliberately built on ONLY `atob`/`btoa` (ambient globals in
 * every browser AND in Node >= 16 — no `Buffer` import, so this file has zero Node-specific
 * surface and runs unmodified in a browser/webview/service-worker bundle). This is the "hard
 * compile-time boundary" the parent build spec requires: this package's tsconfig `lib` excludes
 * `"dom"`, so any accidental `window`/`document`/`Buffer` reference fails `tsc`, not just a
 * runtime check — see ../README.md "Compile-time boundary".
 */

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length hex string (${hex.length} chars)`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`hexToBytes: invalid hex byte at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

const HEX_CHARS = "0123456789abcdef";

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    out += HEX_CHARS[(b >> 4) & 0xf]! + HEX_CHARS[b & 0xf]!;
  }
  return out;
}

/** Encode raw bytes as standard (RFC 4648 §4) base64 — no Buffer, `btoa` operates on a
 *  "binary string" (one JS char per byte, 0-255), so we build that string ourselves first. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
