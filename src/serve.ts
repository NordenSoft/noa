/**
 * `noa --serve` — Stage 0.5 PROTOCOL REHEARSAL server. Spec: docs/kernel-wire-protocol.md.
 *
 * ── THE LABEL ────────────────────────────────────────────────────────────────────────────────────
 * This is a PROTOCOL REHEARSAL, NOT a security deliverable, and NOT the isolated Go kernel of
 * ADR-0002. It is same-realm TypeScript behind an ordinary process boundary: everything in this
 * process — parser, verifier, envelope signer, the ephemeral key below — is poisonable INSIDE the
 * process (ADR-0002 §2–§3). What it rehearses is the WIRE CONTRACT (framing, signed-response
 * envelope, error taxonomy) so the future Go kernel can be written against executable conformance
 * vectors instead of prose. Reading this file as a security boundary is the overclaim NON-CLAIMS.md
 * exists to prevent.
 *
 * Framing: u32be length ‖ payload, MAX_FRAME hard cap. A protocol error CLOSES the connection and
 * is never a verdict (spec §7). Verdicts come from `verifyChain` and are signed over
 * (request_digest ‖ request_id ‖ nonce ‖ sha256(verdict)) with a domain tag that names the
 * rehearsal, so these bytes can never satisfy the future kernel's envelope domain.
 */

import { generateKeyPair, signEd25519 } from "./keys.js";
import { sha256Digest } from "./hash.js";
import { verifyChain, type VerifyOptions } from "./verify.js";

/** Spec §4.1 — distinct from RECEIPT_SIG_DOMAIN / CHECKPOINT_SIG_DOMAIN (src/signing.ts), and it
 * names the rehearsal: a rehearsal envelope signature can never be replayed as a receipt,
 * checkpoint, or future-kernel envelope signature. */
export const REHEARSAL_SIG_DOMAIN = "NOA-KernelRehearsal-v0.1-sig";
/** Spec §2 — the protocol id string carried in HELLO; names the rehearsal on the wire. */
export const PROTO_ID = "noa-kernel-rehearsal/0";
/** Spec §1 — equals the one-shot CLI's MAX_FILE_BYTES (src/cli.ts). */
export const MAX_FRAME = 64 * 1024 * 1024;
export const VERSION = 0x01;

export const TYPE = {
  HELLO: 0x01,
  REQUEST: 0x02,
  RESPONSE: 0x03,
  PROTOCOL_ERROR: 0x7f,
} as const;

export const ERR = {
  FRAME_OVERSIZE: 0x01,
  FRAME_UNDERSIZE: 0x02,
  BAD_VERSION: 0x03,
  BAD_TYPE: 0x04,
  BAD_REQUEST_GRAMMAR: 0x05,
  ID_NOT_MONOTONIC: 0x06,
  FRAME_TIMEOUT: 0x07,
  EOF_MID_FRAME: 0x08,
  INTERNAL: 0x09,
} as const;

/** Request TLV tags (spec §3): strictly ascending, each at most once, document required. */
export const TAG = { DOCUMENT: 0x01, KEYRING: 0x02, CHECKPOINT: 0x03, IDENTITY: 0x04 } as const;

const REQUEST_FIXED_HEADER = 1 + 1 + 8 + 32 + 1; // version type id nonce op
const OP_VERIFY_CHAIN = 0x01;

export type ParsedRequest =
  | {
      ok: true;
      id: bigint;
      nonce: Buffer;
      /** All sections are OPAQUE BYTES (T-2): the transport never parses or re-encodes them. */
      document: Uint8Array;
      keyring?: Uint8Array;
      checkpoint?: Uint8Array;
      identityManifest?: Uint8Array;
    }
  | { ok: false; code: number };

/**
 * Parse a REQUEST payload (version/type already checked by the frame loop). Closed, canonical
 * grammar: unknown tag, duplicate, non-ascending order, overrun, missing document or trailing
 * bytes → BAD_REQUEST_GRAMMAR. Sections are returned as subarray views of the payload — bytes,
 * never parsed values.
 */
export function parseRequest(payload: Buffer): ParsedRequest {
  if (payload.length < REQUEST_FIXED_HEADER) return { ok: false, code: ERR.FRAME_UNDERSIZE };
  const id = payload.readBigUInt64BE(2);
  const nonce = payload.subarray(10, 42);
  const op = payload[42]!;
  if (op !== OP_VERIFY_CHAIN) return { ok: false, code: ERR.BAD_REQUEST_GRAMMAR };
  const sections: Partial<Record<number, Uint8Array>> = {};
  let lastTag = 0;
  let off = REQUEST_FIXED_HEADER;
  while (off < payload.length) {
    if (off + 5 > payload.length) return { ok: false, code: ERR.BAD_REQUEST_GRAMMAR };
    const tag = payload[off]!;
    const len = payload.readUInt32BE(off + 1);
    off += 5;
    if (tag <= lastTag || tag > TAG.IDENTITY) return { ok: false, code: ERR.BAD_REQUEST_GRAMMAR };
    if (off + len > payload.length) return { ok: false, code: ERR.BAD_REQUEST_GRAMMAR };
    sections[tag] = payload.subarray(off, off + len);
    off += len;
    lastTag = tag;
  }
  const document = sections[TAG.DOCUMENT];
  if (document === undefined) return { ok: false, code: ERR.BAD_REQUEST_GRAMMAR };
  const out: ParsedRequest = { ok: true, id, nonce, document };
  if (sections[TAG.KEYRING] !== undefined) out.keyring = sections[TAG.KEYRING];
  if (sections[TAG.CHECKPOINT] !== undefined) out.checkpoint = sections[TAG.CHECKPOINT];
  if (sections[TAG.IDENTITY] !== undefined) out.identityManifest = sections[TAG.IDENTITY];
  return out;
}

/** Spec §4.1 — fixed-width preimage: tag ‖ ":" ‖ digest(32) ‖ id(8) ‖ nonce(32) ‖ sha256(verdict)(32). */
export function envelopePreimage(requestDigest: Buffer, requestId: bigint, nonce: Buffer, verdictBytes: Buffer): Buffer {
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64BE(requestId);
  return Buffer.concat([
    Buffer.from(REHEARSAL_SIG_DOMAIN + ":", "utf8"),
    requestDigest,
    idBuf,
    nonce,
    sha256Digest(verdictBytes),
  ]);
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

export function buildHelloPayload(publicKeySpkiDer: Buffer): Buffer {
  const protoId = Buffer.from(PROTO_ID, "ascii");
  const pkLen = Buffer.alloc(2);
  pkLen.writeUInt16BE(publicKeySpkiDer.length);
  return Buffer.concat([
    Buffer.from([VERSION, TYPE.HELLO, protoId.length]),
    protoId,
    u32(MAX_FRAME),
    pkLen,
    publicKeySpkiDer,
  ]);
}

export function buildResponsePayload(
  requestPayload: Buffer,
  requestId: bigint,
  nonce: Buffer,
  verdictBytes: Buffer,
  privateKeyB64: string,
): Buffer {
  const requestDigest = sha256Digest(requestPayload);
  const sig = Buffer.from(signEd25519(privateKeyB64, envelopePreimage(requestDigest, requestId, nonce, verdictBytes)), "base64");
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64BE(requestId);
  return Buffer.concat([
    Buffer.from([VERSION, TYPE.RESPONSE]),
    idBuf,
    nonce,
    requestDigest,
    u32(verdictBytes.length),
    verdictBytes,
    sig,
  ]);
}

const LABEL_BANNER =
  "noa --serve: PROTOCOL REHEARSAL (ADR-0002 Stage 0.5) — NOT a security boundary, NOT the isolated " +
  "kernel. Same-realm TypeScript behind a process boundary is still poisonable inside the process. " +
  "Spec: docs/kernel-wire-protocol.md";

/**
 * Long-lived serve loop: length-framed requests on stdin, length-framed signed responses on stdout.
 * Sequential processing (in-flight = 1, spec §6). Returns the process exit code: 0 on clean EOF at
 * a frame boundary, 1 after a protocol error, 4 on bad CLI arguments.
 */
export function runServe(args: string[]): Promise<number> {
  let frameTimeoutMs = 30_000;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--frame-timeout-ms") {
      const v = args[++i];
      const n = Number(v);
      if (v === undefined || !Number.isSafeInteger(n) || n <= 0) {
        process.stderr.write("error: --frame-timeout-ms must be a positive integer\n");
        return Promise.resolve(4);
      }
      frameTimeoutMs = n;
    } else {
      process.stderr.write(`error: unknown --serve flag: ${a}\n`);
      return Promise.resolve(4);
    }
  }

  process.stderr.write(LABEL_BANNER + "\n");

  // Spec §5: EPHEMERAL envelope key, generated at process start, held in ordinary process memory,
  // announced in the (unsigned) HELLO, dies with the process. Its compromise voids every §4
  // guarantee for this process lifetime. T-7 provisioning and T-9 key custody are deliberately NOT
  // rehearsed here — that requires operator/KMS input this rehearsal must not invent.
  const kp = generateKeyPair("kernel-rehearsal-ephemeral");

  const writeFrame = (payload: Buffer): void => {
    process.stdout.write(Buffer.concat([u32(payload.length), payload]));
  };

  writeFrame(buildHelloPayload(Buffer.from(kp.publicKey, "base64")));

  return new Promise<number>((resolve) => {
    let acc: Buffer = Buffer.alloc(0);
    let need: number | null = null; // payload length awaited; null = awaiting header
    let lastId = 0n;
    let timer: NodeJS.Timeout | null = null;
    let done = false;

    const clearTimer = () => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
    };
    const finish = (code: number) => {
      if (done) return;
      done = true;
      clearTimer();
      process.stdin.pause();
      resolve(code);
    };
    // Spec §7: best-effort error frame, then CLOSE. Never signed, never a verdict.
    const protoError = (code: number) => {
      try {
        writeFrame(Buffer.from([VERSION, TYPE.PROTOCOL_ERROR, code]));
      } catch {
        /* best-effort */
      }
      finish(1);
    };

    const handlePayload = (payload: Buffer): number | null => {
      if (payload.length < 2) return ERR.FRAME_UNDERSIZE;
      if (payload[0] !== VERSION) return ERR.BAD_VERSION;
      // The server accepts REQUEST only; HELLO/RESPONSE/PROTOCOL_ERROR sent TO it are BAD_TYPE.
      if (payload[1] !== TYPE.REQUEST) return ERR.BAD_TYPE;
      const parsed = parseRequest(payload);
      if (!parsed.ok) return parsed.code;
      if (parsed.id < 1n || parsed.id <= lastId) return ERR.ID_NOT_MONOTONIC;
      lastId = parsed.id;
      let verdictBytes: Buffer;
      try {
        const opts: VerifyOptions = {};
        if (parsed.keyring !== undefined) opts.keyring = parsed.keyring;
        if (parsed.checkpoint !== undefined) opts.checkpoint = parsed.checkpoint;
        if (parsed.identityManifest !== undefined) opts.identityManifest = parsed.identityManifest;
        // Document problems are VERDICTS (verifyChain never throws on hostile input — it returns
        // MALFORMED/TAMPERED/…); only a server DEFECT lands in the catch below, and a defect is a
        // protocol error, never a verdict.
        const verdict = verifyChain(parsed.document, opts);
        verdictBytes = Buffer.from(JSON.stringify(verdict), "utf8");
      } catch {
        return ERR.INTERNAL;
      }
      try {
        writeFrame(buildResponsePayload(payload, parsed.id, parsed.nonce, verdictBytes, kp.privateKey));
      } catch {
        return ERR.INTERNAL;
      }
      return null;
    };

    const pump = (): void => {
      for (;;) {
        if (need === null) {
          if (acc.length < 4) break;
          const declared = acc.readUInt32BE(0);
          acc = acc.subarray(4);
          // Checked BEFORE any payload byte is read or buffered for this frame (spec §1).
          if (declared > MAX_FRAME) return protoError(ERR.FRAME_OVERSIZE);
          if (declared === 0) return protoError(ERR.FRAME_UNDERSIZE);
          need = declared;
        }
        if (acc.length < need) break;
        const payload = acc.subarray(0, need);
        acc = acc.subarray(need);
        need = null;
        const err = handlePayload(payload);
        if (err !== null) return protoError(err);
      }
      // Frame-assembly deadline (spec §6): armed only while a PARTIAL frame is pending.
      clearTimer();
      if (!done && (need !== null || acc.length > 0)) {
        timer = setTimeout(() => protoError(ERR.FRAME_TIMEOUT), frameTimeoutMs);
      }
    };

    process.stdin.on("data", (chunk: Buffer) => {
      if (done) return;
      acc = acc.length === 0 ? Buffer.from(chunk) : Buffer.concat([acc, chunk]);
      pump();
    });
    process.stdin.on("end", () => {
      if (done) return;
      // EOF at a frame boundary is a clean shutdown; EOF inside a frame is a protocol error.
      if (need !== null || acc.length > 0) protoError(ERR.EOF_MID_FRAME);
      else finish(0);
    });
    process.stdin.on("error", () => {
      if (!done) protoError(ERR.EOF_MID_FRAME);
    });
  });
}
