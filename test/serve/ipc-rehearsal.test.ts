/**
 * Stage 0.5 PROTOCOL REHEARSAL — executable conformance driver.
 * Spec: docs/kernel-wire-protocol.md.  Vectors: conformance/ipc-rehearsal/vectors.json.
 *
 * LABEL: this exercises the WIRE CONTRACT of a protocol rehearsal — NOT a security deliverable and
 * NOT the isolated Go kernel. It proves the framing/envelope/error mechanics behave as specified; it
 * proves nothing about in-process integrity of same-realm TypeScript.
 *
 * The driver runs EVERY vector in vectors.json. An unknown `procedure`, or a vector present in the
 * file but not dispatched, fails the suite — a vector nobody executes is a scoreboard, not a test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ServeProc,
  buildRequest,
  frame,
  parseErrorFrame,
  parseResponse,
  verifyEnvelope,
  CODE,
  type RequestRecord,
} from "../helpers/serve-client.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC = join(__dirname, "..", "..", "..", "conformance", "vectors");
const REHEARSAL = join(__dirname, "..", "..", "..", "conformance", "ipc-rehearsal", "vectors.json");

const DOC = readFileSync(join(VEC, "valid-chain.json"));
const KEYRING = readFileSync(join(VEC, "keyring.json"));
const CHECKPOINT = readFileSync(join(VEC, "checkpoint.json"));
const DUP_KEY = readFileSync(join(VEC, "malformed", "duplicate-key.json"));
const PROTO = readFileSync(join(VEC, "malformed", "proto-pollution.json"));

const CODE_NAME: Record<number, string> = Object.fromEntries(Object.entries(CODE).map(([k, v]) => [v, k]));

function validRecord(id: bigint, nonce = randomBytes(32)): RequestRecord {
  return buildRequest({ id, nonce, doc: DOC, keyring: KEYRING, checkpoint: CHECKPOINT });
}

/** A single request → its response frame, then EOF. Returns {parsed, verdict}. */
async function oneRequest(record: RequestRecord): Promise<{ proc: ServeProc; frameBuf: Buffer }> {
  const proc = await ServeProc.start();
  proc.write(frame(record.payload));
  const f = await proc.nextFrame();
  assert.ok(f, "expected a response frame");
  proc.endInput();
  return { proc, frameBuf: f };
}

/** Expect a PROTOCOL_ERROR frame with a given code, and a non-zero exit / connection close. */
async function expectProtocolError(bytes: Buffer[], code: number, serveArgs: string[] = [], stall = false): Promise<void> {
  const proc = await ServeProc.start(serveArgs);
  for (const b of bytes) proc.write(b);
  // EOF_MID_FRAME fires on stream end, so signal EOF before waiting — UNLESS we are testing the
  // frame-assembly deadline (stall), where the error must come from the timer with the stream open.
  if (!stall) proc.endInput();
  const f = await proc.nextFrame(3000);
  assert.ok(f, `expected a PROTOCOL_ERROR(${CODE_NAME[code]}) frame`);
  const err = parseErrorFrame(f);
  assert.ok(err, `frame is not a PROTOCOL_ERROR (got type 0x${f[1]?.toString(16)})`);
  assert.equal(err.code, code, `expected ${CODE_NAME[code]}, got ${CODE_NAME[err.code] ?? err.code}`);
  const exit = await proc.exited;
  assert.equal(exit, 1, "protocol error must exit non-zero (1)");
}

function tlvBytes(tag: number, bytes: Buffer): Buffer {
  const h = Buffer.alloc(5);
  h.writeUInt8(tag, 0);
  h.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([h, bytes]);
}
function reqHeader(id: bigint, nonce: Buffer, op = 0x01): Buffer {
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64BE(id);
  return Buffer.concat([Buffer.from([0x01, 0x02]), idBuf, nonce, Buffer.from([op])]);
}

// ── One test per vector, dispatched by `procedure` ─────────────────────────────────────────────
const spec = JSON.parse(readFileSync(REHEARSAL, "utf8")) as {
  vectors: Array<{ id: string; threat: string; title: string; procedure: string; rawHex?: string; serveArgs?: string[]; expect: any }>;
};

const dispatched = new Set<string>();

async function runVector(v: (typeof spec.vectors)[number]): Promise<void> {
  const nonce = randomBytes(32);
  switch (v.procedure) {
    case "raw-then-eof": {
      await expectProtocolError([Buffer.from(v.rawHex!, "hex")], CODE[v.expect.code as keyof typeof CODE]);
      return;
    }
    case "stall": {
      await expectProtocolError([Buffer.from(v.rawHex!, "hex")], CODE.FRAME_TIMEOUT, v.serveArgs, true);
      return;
    }
    case "split-writes": {
      const rec = validRecord(1n, nonce);
      const framed = frame(rec.payload);
      const proc = await ServeProc.start();
      // one byte at a time for the first 40, then the rest — forces reassembly on the length prefix
      for (let i = 0; i < 40 && i < framed.length; i++) proc.write(Buffer.from([framed[i]!]));
      proc.write(framed.subarray(40));
      const f = await proc.nextFrame();
      assert.ok(f);
      const env = verifyEnvelope(proc.hello!.pubkeyDer, rec, f);
      assert.equal(env.ok, true, "split-write response envelope must verify");
      assert.equal((env as any).verdict.status, "VALID");
      proc.endInput();
      await proc.exited;
      return;
    }
    case "two-in-one-write": {
      const r1 = validRecord(1n);
      const r2 = validRecord(2n);
      const proc = await ServeProc.start();
      proc.write(Buffer.concat([frame(r1.payload), frame(r2.payload)]));
      const f1 = await proc.nextFrame();
      const f2 = await proc.nextFrame();
      assert.ok(f1 && f2);
      assert.equal(parseResponse(f1!)!.id, 1n);
      assert.equal(parseResponse(f2!)!.id, 2n);
      assert.equal(verifyEnvelope(proc.hello!.pubkeyDer, r1, f1!).ok, true);
      assert.equal(verifyEnvelope(proc.hello!.pubkeyDer, r2, f2!).ok, true);
      proc.endInput();
      await proc.exited;
      return;
    }
    case "grammar-unknown-tag": {
      const p = Buffer.concat([reqHeader(1n, nonce), tlvBytes(0x01, DOC), tlvBytes(0x05, Buffer.from("x"))]);
      await expectProtocolError([frame(p)], CODE.BAD_REQUEST_GRAMMAR);
      return;
    }
    case "grammar-duplicate-tag": {
      const p = Buffer.concat([reqHeader(1n, nonce), tlvBytes(0x01, DOC), tlvBytes(0x01, DOC)]);
      await expectProtocolError([frame(p)], CODE.BAD_REQUEST_GRAMMAR);
      return;
    }
    case "grammar-overrun": {
      const h = Buffer.alloc(5);
      h.writeUInt8(0x01, 0);
      h.writeUInt32BE(DOC.length + 100, 1); // claims more than present
      const p = Buffer.concat([reqHeader(1n, nonce), h, DOC]);
      await expectProtocolError([frame(p)], CODE.BAD_REQUEST_GRAMMAR);
      return;
    }
    case "grammar-trailing": {
      const p = Buffer.concat([reqHeader(1n, nonce), tlvBytes(0x01, DOC), Buffer.from([0x00])]);
      await expectProtocolError([frame(p)], CODE.BAD_REQUEST_GRAMMAR);
      return;
    }
    case "grammar-unknown-op": {
      const p = Buffer.concat([reqHeader(1n, nonce, 0x02), tlvBytes(0x01, DOC)]);
      await expectProtocolError([frame(p)], CODE.BAD_REQUEST_GRAMMAR);
      return;
    }
    case "grammar-missing-doc": {
      const p = Buffer.concat([reqHeader(1n, nonce), tlvBytes(0x02, KEYRING)]);
      await expectProtocolError([frame(p)], CODE.BAD_REQUEST_GRAMMAR);
      return;
    }
    case "after-error-closed": {
      // BAD_TYPE first, then a perfectly valid request: it must get NOTHING (connection closed).
      const proc = await ServeProc.start();
      proc.write(frame(Buffer.from([0x01, 0x42]))); // BAD_TYPE
      const errF = await proc.nextFrame();
      assert.ok(errF && parseErrorFrame(errF)?.code === CODE.BAD_TYPE);
      proc.write(frame(validRecord(1n).payload));
      const after = await proc.nextFrame(500);
      assert.equal(after, null, "no response may follow a protocol-error close");
      const exit = await proc.exited;
      assert.equal(exit, 1);
      return;
    }
    case "doc-duplicate-key": {
      const rec = buildRequest({ id: 1n, nonce, doc: DUP_KEY }); // no keyring
      const { proc, frameBuf } = await oneRequest(rec);
      const env = verifyEnvelope(proc.hello!.pubkeyDer, rec, frameBuf);
      assert.equal(env.ok, true, "a document verdict is a SIGNED response, never a protocol error");
      assert.equal((env as any).verdict.status, "MALFORMED");
      await proc.exited;
      return;
    }
    case "doc-proto-pollution": {
      const rec1 = buildRequest({ id: 1n, nonce, doc: PROTO });
      const proc = await ServeProc.start();
      proc.write(frame(rec1.payload));
      const f1 = await proc.nextFrame();
      assert.ok(f1);
      assert.equal(verifyEnvelope(proc.hello!.pubkeyDer, rec1, f1!).ok, true);
      // the process is not poisoned through the wire: a following VALID request still returns VALID
      const rec2 = validRecord(2n);
      proc.write(frame(rec2.payload));
      const f2 = await proc.nextFrame();
      assert.ok(f2);
      const env2 = verifyEnvelope(proc.hello!.pubkeyDer, rec2, f2!);
      assert.equal(env2.ok, true);
      assert.equal((env2 as any).verdict.status, "VALID");
      proc.endInput();
      await proc.exited;
      return;
    }
    case "tamper-verdict": {
      const rec = validRecord(1n);
      const { proc, frameBuf } = await oneRequest(rec);
      const r = parseResponse(frameBuf)!;
      const tampered = Buffer.from(frameBuf);
      // flip one byte of the verdict region (offset 78)
      tampered[78] = tampered[78]! ^ 0xff;
      const env = verifyEnvelope(proc.hello!.pubkeyDer, rec, tampered);
      assert.equal(env.ok, false);
      assert.equal((env as any).reason, "bad-signature");
      assert.ok(r.verdictBytes.length > 0);
      await proc.exited;
      return;
    }
    case "forge-signature": {
      const rec = validRecord(1n);
      const { proc, frameBuf } = await oneRequest(rec);
      const forged = Buffer.from(frameBuf);
      randomBytes(64).copy(forged, forged.length - 64);
      const env = verifyEnvelope(proc.hello!.pubkeyDer, rec, forged);
      assert.equal(env.ok, false);
      assert.equal((env as any).reason, "bad-signature");
      await proc.exited;
      return;
    }
    case "substitute-digest": {
      const rec = validRecord(1n);
      const { proc, frameBuf } = await oneRequest(rec);
      const swapped = Buffer.from(frameBuf);
      randomBytes(32).copy(swapped, 42); // overwrite request_digest
      const env = verifyEnvelope(proc.hello!.pubkeyDer, rec, swapped);
      assert.equal(env.ok, false);
      assert.equal((env as any).reason, "digest-mismatch");
      await proc.exited;
      return;
    }
    case "replay-fresh-nonce": {
      // capture a response to id=1, then present it to a caller awaiting id=2/fresh nonce
      const rec1 = validRecord(1n);
      const { proc, frameBuf } = await oneRequest(rec1);
      const rec2 = validRecord(2n);
      // unmodified replay: id mismatches first
      const e1 = verifyEnvelope(proc.hello!.pubkeyDer, rec2, frameBuf);
      assert.equal(e1.ok, false);
      assert.equal((e1 as any).reason, "id-mismatch");
      // even if the transport rewrites the id to 2, the signed nonce is rec1's → nonce mismatch
      const rewritten = Buffer.from(frameBuf);
      rewritten.writeBigUInt64BE(2n, 2);
      const e2 = verifyEnvelope(proc.hello!.pubkeyDer, rec2, rewritten);
      assert.equal(e2.ok, false);
      assert.equal((e2 as any).reason, "nonce-mismatch");
      await proc.exited;
      return;
    }
    case "replay-reused-nonce": {
      // SHARP EDGE (spec §8 N-3): caller reuses id+nonce → a byte-identical earlier response verifies.
      const fixedNonce = randomBytes(32);
      const recA = buildRequest({ id: 7n, nonce: fixedNonce, doc: DOC, keyring: KEYRING, checkpoint: CHECKPOINT });
      const { proc, frameBuf } = await oneRequest(recA);
      // the caller issues a SECOND request with the SAME id+nonce+doc (contract violation) and a
      // replayed old response is indistinguishable — it verifies. This is pinned as a NON-guarantee.
      const recB = buildRequest({ id: 7n, nonce: fixedNonce, doc: DOC, keyring: KEYRING, checkpoint: CHECKPOINT });
      const env = verifyEnvelope(proc.hello!.pubkeyDer, recB, frameBuf);
      assert.equal(env.ok, true, "documented sharp edge: reused nonce ⇒ replay is accepted");
      await proc.exited;
      return;
    }
    case "swap-responses": {
      const r1 = validRecord(1n);
      const r2 = validRecord(2n);
      const proc = await ServeProc.start();
      proc.write(frame(r1.payload));
      const f1 = await proc.nextFrame();
      proc.write(frame(r2.payload));
      const f2 = await proc.nextFrame();
      assert.ok(f1 && f2);
      // hand r2's response to the record awaiting r1 and vice versa — both fail at id
      assert.equal((verifyEnvelope(proc.hello!.pubkeyDer, r1, f2!) as any).reason, "id-mismatch");
      assert.equal((verifyEnvelope(proc.hello!.pubkeyDer, r2, f1!) as any).reason, "id-mismatch");
      // and the correct pairing still verifies
      assert.equal(verifyEnvelope(proc.hello!.pubkeyDer, r1, f1!).ok, true);
      assert.equal(verifyEnvelope(proc.hello!.pubkeyDer, r2, f2!).ok, true);
      proc.endInput();
      await proc.exited;
      return;
    }
    case "id-regression": {
      const proc = await ServeProc.start();
      proc.write(frame(validRecord(5n).payload));
      const okF = await proc.nextFrame();
      assert.ok(okF && parseResponse(okF!)?.id === 5n);
      proc.write(frame(validRecord(3n).payload));
      const errF = await proc.nextFrame();
      assert.ok(errF && parseErrorFrame(errF!)?.code === CODE.ID_NOT_MONOTONIC);
      const exit = await proc.exited;
      assert.equal(exit, 1);
      return;
    }
    case "id-repeat": {
      const proc = await ServeProc.start();
      proc.write(frame(validRecord(1n).payload));
      await proc.nextFrame();
      proc.write(frame(validRecord(1n).payload));
      const errF = await proc.nextFrame();
      assert.ok(errF && parseErrorFrame(errF!)?.code === CODE.ID_NOT_MONOTONIC);
      assert.equal(await proc.exited, 1);
      return;
    }
    case "id-zero": {
      await expectProtocolError([frame(validRecord(0n).payload)], CODE.ID_NOT_MONOTONIC);
      return;
    }
    case "no-keyring-equivalence": {
      const rec = buildRequest({ id: 1n, nonce, doc: DOC }); // no keyring
      const { proc, frameBuf } = await oneRequest(rec);
      const env = verifyEnvelope(proc.hello!.pubkeyDer, rec, frameBuf);
      assert.equal(env.ok, true);
      assert.equal((env as any).verdict.status, "UNVERIFIED");
      await proc.exited;
      return;
    }
    default:
      throw new Error(`vector ${v.id}: unknown procedure "${v.procedure}" — driver does not execute it`);
  }
}

for (const v of spec.vectors) {
  test(`${v.id} [${v.threat}] ${v.title}`, { timeout: 8000 }, async () => {
    dispatched.add(v.id);
    await runVector(v);
  });
}

test("every vector in vectors.json was dispatched (no scoreboard entries)", () => {
  const all = new Set(spec.vectors.map((v) => v.id));
  for (const id of all) assert.ok(dispatched.has(id), `vector ${id} was never executed`);
  assert.equal(dispatched.size, all.size);
});
