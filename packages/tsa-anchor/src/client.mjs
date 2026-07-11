/**
 * The RFC 3161 network client: requests ONE timestamp over ONE anchor from a TSA (POST
 * application/timestamp-query, expect application/timestamp-reply), and returns a self-contained
 * stamp record ready to be written into a .tsr sidecar file (see cli.mjs `stamp`). Uses Node's
 * built-in `fetch` (stable since Node 18/20) — zero extra runtime dependencies.
 */
import { randomBytes } from "node:crypto";
import { buildTimeStampReq, parseTimeStampResp, SHA256_OID } from "./tsq.mjs";
import { anchorHash, anchorHashDigest } from "./anchor-hash.mjs";

export class TsaError extends Error {
  constructor(m) {
    super(m);
    this.name = "TsaError";
  }
}

const TSQ_CONTENT_TYPE = "application/timestamp-query";
const TSR_CONTENT_TYPE = "application/timestamp-reply";

function randomNonce() {
  return BigInt("0x" + randomBytes(8).toString("hex"));
}

/**
 * Request an RFC 3161 timestamp over `anchor` from `opts.tsaUrl`. Fail-closed: any transport
 * error, non-2xx response, wrong content-type, a malformed TimeStampResp, a non-granted PKIStatus,
 * or — critically — a response whose OWN messageImprint does NOT match the hash we submitted, all
 * throw TsaError. This function NEVER returns a stamp record that does not provably cover the
 * exact anchor it was asked to stamp.
 */
export async function stampAnchor(anchor, opts) {
  if (typeof opts !== "object" || opts === null || typeof opts.tsaUrl !== "string" || opts.tsaUrl.length === 0) {
    throw new TypeError("stampAnchor: opts.tsaUrl is required");
  }
  const digest = anchorHashDigest(anchor); // throws TypeError on a malformed/unsigned anchor — propagates as-is
  const includeNonce = opts.includeNonce ?? true;
  const nonce = includeNonce ? (opts.nonceValue ?? randomNonce()) : undefined;
  const certReq = opts.certReq ?? true;
  const req = buildTimeStampReq(digest, { certReq, ...(nonce !== undefined ? { nonce } : {}) });

  let res;
  try {
    res = await fetch(opts.tsaUrl, {
      method: "POST",
      headers: { "content-type": TSQ_CONTENT_TYPE },
      body: req,
      signal: opts.timeoutMs ? AbortSignal.timeout(opts.timeoutMs) : undefined,
    });
  } catch (e) {
    throw new TsaError(`stampAnchor: request to ${opts.tsaUrl} failed: ${e.message}`);
  }
  if (!res.ok) throw new TsaError(`stampAnchor: TSA ${opts.tsaUrl} returned HTTP ${res.status}`);
  const ct = res.headers.get("content-type") ?? "";
  if (!ct.includes(TSR_CONTENT_TYPE)) {
    throw new TsaError(`stampAnchor: unexpected content-type "${ct}" from ${opts.tsaUrl} (expected ${TSR_CONTENT_TYPE})`);
  }
  const raw = Buffer.from(await res.arrayBuffer());

  let parsed;
  try {
    parsed = parseTimeStampResp(raw);
  } catch (e) {
    throw new TsaError(`stampAnchor: malformed TimeStampResp from ${opts.tsaUrl}: ${e.message}`);
  }
  if (!parsed.granted) {
    throw new TsaError(`stampAnchor: TSA ${opts.tsaUrl} did not grant the request (status=${parsed.status})`);
  }
  // We always submit a sha256 messageImprint (buildTimeStampReq defaults to SHA256_OID); a token
  // echoing a different hashAlgorithm OID is non-conformant — reject rather than store it.
  if (parsed.hashAlgOid !== SHA256_OID) {
    throw new TsaError(`stampAnchor: TSA ${opts.tsaUrl} responded with hashAlgorithm ${parsed.hashAlgOid}, expected sha256 (${SHA256_OID})`);
  }
  // Fail-closed self-check: the token's OWN messageImprint must echo exactly what we submitted —
  // never trust a validly-formed token that silently diverges from the digest we asked to stamp.
  if (!parsed.hashedMessage.equals(digest)) {
    throw new TsaError(
      `stampAnchor: TSA response messageImprint does not match the submitted anchor hash (sent ${digest.toString("hex")}, got ${parsed.hashedMessage.toString("hex")})`,
    );
  }
  // Anti-replay freshness: RFC 3161 §2.4.2 requires the TSA to echo the request nonce verbatim. If
  // we sent one, reject a token that omits it or returns a different value — that token could be a
  // replayed/substituted response for the same digest rather than a fresh stamp of THIS request.
  if (nonce !== undefined) {
    const sent = BigInt(nonce);
    if (parsed.nonce === undefined) {
      throw new TsaError(`stampAnchor: TSA ${opts.tsaUrl} did not echo the request nonce (RFC 3161 requires it) — replay-freshness cannot be confirmed`);
    }
    if (parsed.nonce !== sent) {
      throw new TsaError(`stampAnchor: TSA ${opts.tsaUrl} echoed nonce ${parsed.nonce} != the ${sent} we sent (possible replayed/substituted response)`);
    }
  }

  return {
    anchorHash: anchorHash(anchor),
    chain: anchor.chain,
    highestSeq: anchor.highestSeq,
    headHash: anchor.headHash,
    witnessKid: anchor.sig.kid,
    tsaUrl: opts.tsaUrl,
    genTime: parsed.genTime,
    hashAlgOid: parsed.hashAlgOid,
    tsr: raw.toString("base64"),
  };
}
