/**
 * Structural verification of a stamp record against the anchor it claims to cover: recomputes the
 * anchor hash, DER-parses the stored .tsr bytes, and checks the TSTInfo messageImprint matches.
 *
 * THIS IS A BASIC PARSE-AND-COMPARE, NOT A FULL CRYPTOGRAPHIC VERIFICATION: it does NOT validate
 * the CMS SignerInfo signature or the TSA's own certificate chain — doing that trustworthily needs
 * a pinned TSA CA root (the same class of out-of-band trust input as the receipt keyring; see
 * README.md "What noa-tsa does NOT verify"). For full cryptographic verification, run the
 * documented `openssl ts -verify` command (README.md) against the .tsr bytes. verifyStamp NEVER
 * throws: any parse failure, malformed input, or mismatch returns { ok: false, reason }. Malformed-
 * INPUT failures (bad base64 / undecodable DER) additionally carry `code: "MALFORMED"` so a caller
 * (cli.mjs) can map them to the MALFORMED exit code rather than conflating them with a genuine
 * anchor/stamp MISMATCH.
 */
import { parseTimeStampResp, SHA256_OID } from "./tsq.mjs";
import { anchorHash, anchorHashDigest } from "./anchor-hash.mjs";

export function verifyStamp(anchor, stampRecord) {
  let expectedDigest;
  let expectedHash;
  try {
    expectedDigest = anchorHashDigest(anchor);
    expectedHash = anchorHash(anchor);
  } catch (e) {
    return { ok: false, code: "MALFORMED", reason: `malformed anchor: ${e.message}` };
  }

  if (typeof stampRecord !== "object" || stampRecord === null || typeof stampRecord.tsr !== "string" || stampRecord.tsr.length === 0) {
    return { ok: false, code: "MALFORMED", reason: "stampRecord.tsr must be a non-empty base64 string" };
  }
  if (stampRecord.anchorHash !== undefined && stampRecord.anchorHash !== expectedHash) {
    return {
      ok: false,
      reason: `stampRecord.anchorHash "${stampRecord.anchorHash}" does not match the recomputed anchor hash "${expectedHash}" (wrong anchor/stamp pairing)`,
    };
  }

  let raw;
  try {
    raw = Buffer.from(stampRecord.tsr, "base64");
    if (raw.length === 0) throw new Error("empty");
  } catch {
    return { ok: false, code: "MALFORMED", reason: "stampRecord.tsr is not valid non-empty base64" };
  }

  let parsed;
  try {
    parsed = parseTimeStampResp(raw);
  } catch (e) {
    return { ok: false, code: "MALFORMED", reason: `malformed TimeStampResp: ${e.message}` };
  }
  if (!parsed.granted) {
    return { ok: false, reason: `TSA response did not grant the request (status=${parsed.status})` };
  }
  // Bind the digest comparison to sha256: expectedDigest IS a sha256, so a token that carries the
  // same 32 bytes but claims a different hashAlgorithm OID must NOT be accepted as covering it.
  if (parsed.hashAlgOid !== SHA256_OID) {
    return { ok: false, reason: `TSA token uses hashAlgorithm ${parsed.hashAlgOid}, expected sha256 (${SHA256_OID})` };
  }
  if (!parsed.hashedMessage.equals(expectedDigest)) {
    return {
      ok: false,
      reason: `TSA messageImprint does not match the anchor's own hash (anchor hash ${expectedHash}, token covers sha256:${parsed.hashedMessage.toString("hex")}) — this .tsr does NOT prove this anchor`,
    };
  }
  return {
    ok: true,
    reason: "messageImprint matches the anchor hash; genTime is TSA-asserted (run the documented `openssl ts -verify` for full cryptographic verification of the TSA's own signature)",
    genTime: parsed.genTime,
    hashAlgOid: parsed.hashAlgOid,
  };
}
