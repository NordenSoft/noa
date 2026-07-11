/**
 * RFC 3161 §2.4.1/§2.4.2 wire structures — TimeStampReq builder + TimeStampResp/TSTInfo parser.
 * Built entirely on top of ./der.mjs's generic DER primitives; owns zero cryptography of its own
 * (it never verifies a signature — see verify.mjs's docstring for why, and README.md for the
 * documented `openssl ts -verify` command that does).
 */
import { DerError, encInteger, encOid, encNull, encOctetString, encBoolean, encSequence, derDecode, readInteger, readOid, readGeneralizedTime } from "./der.mjs";

export const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const PKI_STATUS = { 0: "granted", 1: "grantedWithMods", 2: "rejection", 3: "waiting", 4: "revocationWarning", 5: "revocationNotification" };

/**
 * Build a DER-encoded RFC 3161 TimeStampReq over an ALREADY-COMPUTED digest. `hashedMessage` MUST
 * be the raw digest bytes (32 bytes for sha256) — never a hex/base64 string; the caller computes
 * the hash (see anchor-hash.mjs), this module only encodes the wire request. Field order (RFC 3161
 * §2.4.1): version, messageImprint, [nonce], [certReq] — reqPolicy/extensions are never emitted.
 */
export function buildTimeStampReq(hashedMessage, opts = {}) {
  if (!Buffer.isBuffer(hashedMessage) || hashedMessage.length === 0) {
    throw new TypeError("buildTimeStampReq: hashedMessage must be a non-empty Buffer");
  }
  const hashAlgOid = opts.hashAlgOid ?? SHA256_OID;
  const certReq = opts.certReq ?? true; // default true: most public TSAs (e.g. FreeTSA) embed the signing cert only when asked
  const messageImprint = encSequence([encSequence([encOid(hashAlgOid), encNull()]), encOctetString(hashedMessage)]);
  const parts = [encInteger(1), messageImprint];
  if (opts.nonce !== undefined) parts.push(encInteger(opts.nonce));
  if (certReq) parts.push(encBoolean(true)); // DER canonical: DEFAULT FALSE is OMITTED, never encoded as FALSE
  return encSequence(parts);
}

function assertSequence(node, label) {
  if (!node || node.tagClass !== 0 || !node.constructed || node.tagNumber !== 0x10) {
    throw new DerError(`expected ${label} to be a SEQUENCE`);
  }
}
function unwrapExplicit(node, label) {
  if (!node || node.tagClass !== 2 || !node.constructed || !node.children || node.children.length !== 1) {
    throw new DerError(`expected ${label} to be an EXPLICIT context tag wrapping exactly one value`);
  }
  return node.children[0];
}

/**
 * Parse a DER-encoded RFC 3161 TimeStampResp far enough to extract what this package needs: the
 * PKIStatus, and — on a granted response — the embedded TSTInfo's genTime and messageImprint
 * (hashAlgorithm OID + hashedMessage bytes). STRUCTURAL PARSE ONLY: does NOT validate the CMS
 * SignerInfo signature or the TSA's certificate chain — see README.md "What noa-tsa does NOT
 * verify" / verify.mjs. Navigates TimeStampResp -> ContentInfo -> SignedData -> encapContentInfo ->
 * eContent(OCTET STRING) -> TSTInfo BY FIXED FIELD POSITION (all fields read here are MANDATORY,
 * always-present, always-first-N fields per RFC 3161/CMS — optional trailing fields like
 * certificates/crls/signerInfos never shift an earlier mandatory field's position).
 */
export function parseTimeStampResp(buf) {
  const resp = derDecode(buf);
  assertSequence(resp, "TimeStampResp");
  const statusInfo = resp.children[0];
  assertSequence(statusInfo, "PKIStatusInfo");
  const statusCode = readInteger(statusInfo.children[0]);
  const status = PKI_STATUS[statusCode] ?? `unknown(${statusCode})`;
  if (statusCode !== 0 && statusCode !== 1) {
    return { granted: false, statusCode, status };
  }
  if (resp.children.length < 2) throw new DerError("TimeStampResp: status granted but timeStampToken is missing");

  const contentInfo = resp.children[1];
  assertSequence(contentInfo, "ContentInfo");
  const contentType = readOid(contentInfo.children[0]);
  if (contentType !== ID_SIGNED_DATA) throw new DerError(`ContentInfo.contentType is not id-signedData (got ${contentType})`);
  const signedData = unwrapExplicit(contentInfo.children[1], "ContentInfo.content");
  assertSequence(signedData, "SignedData");

  const encapContentInfo = signedData.children[2]; // [0]=version [1]=digestAlgorithms [2]=encapContentInfo
  assertSequence(encapContentInfo, "EncapsulatedContentInfo");
  const eContentType = readOid(encapContentInfo.children[0]);
  if (eContentType !== ID_CT_TST_INFO) throw new DerError(`EncapsulatedContentInfo.eContentType is not id-ct-TSTInfo (got ${eContentType})`);
  if (encapContentInfo.children.length < 2) throw new DerError("EncapsulatedContentInfo: eContent is missing");
  const eContentOctets = unwrapExplicit(encapContentInfo.children[1], "EncapsulatedContentInfo.eContent");
  if (eContentOctets.tagClass !== 0 || eContentOctets.constructed || eContentOctets.tagNumber !== 0x04) {
    throw new DerError("EncapsulatedContentInfo.eContent is not an OCTET STRING");
  }

  const tstInfo = derDecode(eContentOctets.content);
  assertSequence(tstInfo, "TSTInfo");
  const messageImprint = tstInfo.children[2]; // [0]=version [1]=policy [2]=messageImprint [3]=serialNumber [4]=genTime
  assertSequence(messageImprint, "TSTInfo.messageImprint");
  const hashAlgSeq = messageImprint.children[0];
  assertSequence(hashAlgSeq, "MessageImprint.hashAlgorithm");
  const hashAlgOid = readOid(hashAlgSeq.children[0]);
  const hashedMessageNode = messageImprint.children[1];
  if (hashedMessageNode.tagClass !== 0 || hashedMessageNode.constructed || hashedMessageNode.tagNumber !== 0x04) {
    throw new DerError("MessageImprint.hashedMessage is not an OCTET STRING");
  }
  const genTime = readGeneralizedTime(tstInfo.children[4]);

  return { granted: true, statusCode, status, hashAlgOid, hashedMessage: hashedMessageNode.content, genTime };
}
