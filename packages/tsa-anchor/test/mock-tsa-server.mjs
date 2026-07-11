/**
 * In-process mock RFC 3161 TSA for tests — NO network dependency, NO real TSA needed. Decodes an
 * incoming TimeStampReq with this package's own der.mjs, echoes the submitted hashAlgorithm +
 * hashedMessage back inside a freshly-built (UNSIGNED — no CMS SignerInfo, no cert) TimeStampResp.
 * verify.mjs never checks the CMS signature (see its docstring), so an unsigned mock is sufficient
 * to exercise the full stamp/verify round-trip. `mode` lets a test simulate a TSA that rejects the
 * request or returns a WRONG hash (for the "reject a mismatched .tsr" test in verify.test.mjs).
 */
import { createServer } from "node:http";
import { encInteger, encOid, encNull, encOctetString, encSequence, encSet, encContext, encGeneralizedTime, derDecode, readOid, readIntegerBig } from "../src/der.mjs";

const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";

function buildTstInfo({ hashAlgOid, hashedMessage, genTime, serial, nonce }) {
  const messageImprint = encSequence([encSequence([encOid(hashAlgOid), encNull()]), encOctetString(hashedMessage)]);
  const fields = [encInteger(1), encOid("1.2.3.4.5"), messageImprint, encInteger(serial), encGeneralizedTime(genTime)];
  if (nonce !== undefined) fields.push(encInteger(nonce)); // RFC 3161: echo the request nonce when present
  return encSequence(fields);
}

function buildContentInfo(tstInfoBytes) {
  const encapContentInfo = encSequence([encOid(ID_CT_TST_INFO), encContext(0, encOctetString(tstInfoBytes))]);
  const signedData = encSequence([
    encInteger(3),
    encSet([encSequence([encOid(SHA256_OID), encNull()])]),
    encapContentInfo,
    encSet([]), // signerInfos — EMPTY: this mock never signs; verify.mjs does not check this field
  ]);
  return encSequence([encOid(ID_SIGNED_DATA), encContext(0, signedData)]);
}

function buildTimeStampResp({ hashAlgOid, hashedMessage, genTime = new Date(), serial = 1, statusCode = 0, nonce }) {
  const statusInfo = encSequence([encInteger(statusCode)]);
  if (statusCode !== 0 && statusCode !== 1) return encSequence([statusInfo]); // rejection: no timeStampToken (RFC 3161 §2.4.2)
  return encSequence([statusInfo, buildContentInfo(buildTstInfo({ hashAlgOid, hashedMessage, genTime, serial, nonce }))]);
}

/** Start a mock TSA on 127.0.0.1:0 (OS-assigned port). `mode`: "ok" | "reject" | "wrong-hash" | "drop-nonce". */
export function startMockTsa({ mode = "ok" } = {}) {
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      let reqNode;
      try {
        reqNode = derDecode(body);
      } catch (e) {
        res.writeHead(400).end(`bad request: ${e.message}`);
        return;
      }
      const messageImprint = reqNode.children[1];
      const hashAlgOid = readOid(messageImprint.children[0].children[0]);
      let hashedMessage = messageImprint.children[1].content;
      // Echo the request nonce (RFC 3161-compliant): the first bare INTEGER after messageImprint
      // (version is children[0], messageImprint children[1], so the scan starts at index 2).
      let nonce;
      for (let k = 2; k < reqNode.children.length; k++) {
        const ch = reqNode.children[k];
        if (ch.tagClass === 0 && !ch.constructed && ch.tagNumber === 0x02) {
          nonce = readIntegerBig(ch);
          break;
        }
      }
      let statusCode = 0;
      if (mode === "reject") statusCode = 2;
      if (mode === "wrong-hash") hashedMessage = Buffer.alloc(hashedMessage.length, 0xee);
      if (mode === "drop-nonce") nonce = undefined; // simulate an RFC-noncompliant TSA that ignores the nonce
      const respBuf = buildTimeStampResp({ hashAlgOid, hashedMessage, statusCode, nonce });
      res.writeHead(200, { "content-type": "application/timestamp-reply" });
      res.end(respBuf);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}/tsr`, close: () => new Promise((r) => server.close(r)) });
    });
  });
}
