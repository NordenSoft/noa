/**
 * Test client for the Stage 0.5 PROTOCOL REHEARSAL server (`noa --serve`).
 * Spec: docs/kernel-wire-protocol.md. This client is the CALLER side of the rehearsal.
 *
 * KNOCKOUT HONESTY: every constant and the whole §4.1/§4.2 envelope verification are
 * DELIBERATELY re-implemented here from the spec, using node:crypto directly — nothing is
 * imported from src/serve.ts. A server-side knockout must therefore be CAUGHT by this client,
 * not silently mirrored by shared code (the same discipline the external oracles follow).
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const CLI = join(__dirname, "..", "..", "src", "cli.js");

// Spec constants, restated from docs/kernel-wire-protocol.md (NOT imported from src/serve.ts).
export const DOMAIN = "NOA-KernelRehearsal-v0.1-sig";
export const PROTO_ID = "noa-kernel-rehearsal/0";
export const MAX_FRAME = 67_108_864;
export const T_HELLO = 0x01;
export const T_REQUEST = 0x02;
export const T_RESPONSE = 0x03;
export const T_ERROR = 0x7f;
export const CODE = {
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

export function sha256(b: Buffer): Buffer {
  return createHash("sha256").update(b).digest();
}

export function frame(payload: Buffer): Buffer {
  const l = Buffer.alloc(4);
  l.writeUInt32BE(payload.length);
  return Buffer.concat([l, payload]);
}

function tlv(tag: number, bytes: Buffer): Buffer {
  const h = Buffer.alloc(5);
  h.writeUInt8(tag, 0);
  h.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([h, bytes]);
}

export interface RequestSpec {
  id: bigint;
  nonce: Buffer;
  doc: Buffer;
  keyring?: Buffer;
  checkpoint?: Buffer;
  identity?: Buffer;
  /** override the op byte (default 0x01) for grammar vectors */
  op?: number;
}

/** The caller's own record of a sent request — what §4.2 verifies a response AGAINST. */
export interface RequestRecord {
  id: bigint;
  nonce: Buffer;
  payload: Buffer;
  digest: Buffer; // the caller's OWN SHA-256 of the payload it sent (§4.2 check 4)
}

export function buildRequest(spec: RequestSpec): RequestRecord {
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64BE(spec.id);
  const parts = [Buffer.from([0x01, T_REQUEST]), idBuf, spec.nonce, Buffer.from([spec.op ?? 0x01]), tlv(0x01, spec.doc)];
  if (spec.keyring) parts.push(tlv(0x02, spec.keyring));
  if (spec.checkpoint) parts.push(tlv(0x03, spec.checkpoint));
  if (spec.identity) parts.push(tlv(0x04, spec.identity));
  const payload = Buffer.concat(parts);
  return { id: spec.id, nonce: spec.nonce, payload, digest: sha256(payload) };
}

export interface ParsedResponse {
  id: bigint;
  nonce: Buffer;
  requestDigest: Buffer;
  verdictBytes: Buffer;
  sig: Buffer;
}

/** §4.2 check 1 — exact fixed-width layout, sig is the FINAL 64 bytes, no trailing bytes. */
export function parseResponse(payload: Buffer): ParsedResponse | null {
  if (payload.length < 142) return null;
  if (payload[0] !== 0x01 || payload[1] !== T_RESPONSE) return null;
  const vlen = payload.readUInt32BE(74);
  if (payload.length !== 78 + vlen + 64) return null;
  return {
    id: payload.readBigUInt64BE(2),
    nonce: payload.subarray(10, 42),
    requestDigest: payload.subarray(42, 74),
    verdictBytes: payload.subarray(78, 78 + vlen),
    sig: payload.subarray(78 + vlen),
  };
}

export function parseErrorFrame(payload: Buffer): { code: number } | null {
  if (payload.length !== 3 || payload[0] !== 0x01 || payload[1] !== T_ERROR) return null;
  return { code: payload[2]! };
}

export type EnvelopeVerdict = { ok: true; verdict: unknown } | { ok: false; reason: string };

/**
 * §4.2, all five checks in normative order, independently implemented. The response is verified
 * against the CALLER'S OWN request record — never against the response's self-description.
 */
export function verifyEnvelope(helloPubkeyDer: Buffer, record: RequestRecord, payload: Buffer): EnvelopeVerdict {
  const r = parseResponse(payload); // check 1 (structure)
  if (r === null) return { ok: false, reason: "structural" };
  if (r.id !== record.id) return { ok: false, reason: "id-mismatch" }; // check 2
  if (!r.nonce.equals(record.nonce)) return { ok: false, reason: "nonce-mismatch" }; // check 3
  if (!r.requestDigest.equals(record.digest)) return { ok: false, reason: "digest-mismatch" }; // check 4
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64BE(record.id);
  const preimage = Buffer.concat([
    Buffer.from(DOMAIN + ":", "utf8"),
    record.digest,
    idBuf,
    record.nonce,
    sha256(r.verdictBytes),
  ]);
  const key = createPublicKey({ key: helloPubkeyDer, format: "der", type: "spki" });
  if (!cryptoVerify(null, preimage, key, r.sig)) return { ok: false, reason: "bad-signature" }; // check 5
  return { ok: true, verdict: JSON.parse(r.verdictBytes.toString("utf8")) };
}

export interface Hello {
  protoId: string;
  maxFrame: number;
  pubkeyDer: Buffer;
}

export function parseHello(payload: Buffer): Hello | null {
  if (payload.length < 3 || payload[0] !== 0x01 || payload[1] !== T_HELLO) return null;
  const pidLen = payload[2]!;
  let off = 3 + pidLen;
  if (payload.length < off + 6) return null;
  const protoId = payload.subarray(3, 3 + pidLen).toString("ascii");
  const maxFrame = payload.readUInt32BE(off);
  off += 4;
  const pkLen = payload.readUInt16BE(off);
  off += 2;
  if (payload.length !== off + pkLen) return null;
  return { protoId, maxFrame, pubkeyDer: payload.subarray(off, off + pkLen) };
}

/** A spawned `noa --serve` process with frame-level reads. */
export class ServeProc {
  private child: ChildProcessWithoutNullStreams;
  private acc: Buffer = Buffer.alloc(0);
  private frames: Buffer[] = [];
  private waiters: Array<(f: Buffer | null) => void> = [];
  private closed = false;
  private stderrBuf = "";
  readonly exited: Promise<number | null>;
  hello: Hello | null = null;

  constructor(serveArgs: string[] = []) {
    this.child = spawn(process.execPath, [CLI, "--serve", ...serveArgs], { stdio: ["pipe", "pipe", "pipe"] });
    this.child.stderr.on("data", (d: Buffer) => (this.stderrBuf += d.toString("utf8")));
    this.child.stdout.on("data", (d: Buffer) => {
      this.acc = Buffer.concat([this.acc, d]);
      while (this.acc.length >= 4) {
        const len = this.acc.readUInt32BE(0);
        if (this.acc.length < 4 + len) break;
        const f = this.acc.subarray(4, 4 + len);
        this.acc = this.acc.subarray(4 + len);
        const w = this.waiters.shift();
        if (w) w(f);
        else this.frames.push(f);
      }
    });
    this.exited = new Promise((res) => {
      this.child.on("exit", (code) => {
        this.closed = true;
        for (const w of this.waiters.splice(0)) w(null);
        res(code);
      });
    });
  }

  static async start(serveArgs: string[] = []): Promise<ServeProc> {
    const p = new ServeProc(serveArgs);
    const first = await p.nextFrame(5000);
    if (first === null) throw new Error("serve: no HELLO frame");
    const hello = parseHello(first);
    if (hello === null) throw new Error("serve: first frame is not a HELLO");
    p.hello = hello;
    return p;
  }

  write(bytes: Buffer): void {
    this.child.stdin.write(bytes);
  }

  endInput(): void {
    this.child.stdin.end();
  }

  stderrText(): string {
    return this.stderrBuf;
  }

  /** Next complete frame, or null if the process exits / times out first. */
  nextFrame(timeoutMs = 5000): Promise<Buffer | null> {
    if (this.frames.length > 0) return Promise.resolve(this.frames.shift()!);
    if (this.closed) return Promise.resolve(null);
    return new Promise((res) => {
      const t = setTimeout(() => {
        const i = this.waiters.indexOf(res);
        if (i >= 0) this.waiters.splice(i, 1);
        res(null);
      }, timeoutMs);
      this.waiters.push((f) => {
        clearTimeout(t);
        res(f);
      });
    });
  }

  kill(): void {
    this.child.kill("SIGKILL");
  }
}
