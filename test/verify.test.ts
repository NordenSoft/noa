import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain, verifyChainText, verifyCheckpoint } from "../src/verify.js";
import { safeParse } from "../src/safe-json.js";
import type { Keyring, Checkpoint } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC = join(__dirname, "..", "..", "conformance", "vectors");

function load(rel: string): unknown {
  return JSON.parse(readFileSync(join(VEC, rel), "utf8"));
}
function raw(rel: string): string {
  return readFileSync(join(VEC, rel), "utf8");
}

const keyring = load("keyring.json") as Keyring;
const checkpoint = load("checkpoint.json") as Checkpoint;

test("valid chain + keyring -> VALID, signatures verified", () => {
  const r = verifyChain(load("valid-chain.json"), { keyring });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.count, 3);
  // honest caveat: tail truncation not checked without a checkpoint
  assert.equal(r.tailChecked, false);
  assert.ok(r.warnings.some((w) => /tail-truncation/.test(w)));
});

test("valid chain + keyring + checkpoint -> VALID, tail checked", () => {
  const r = verifyChain(load("valid-chain.json"), { keyring, checkpoint });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.tailChecked, true);
});

test("valid chain WITHOUT keyring -> UNVERIFIED (honest: signatures not authenticated)", () => {
  const r = verifyChain(load("valid-chain.json"), {});
  assert.equal(r.status, "UNVERIFIED");
  assert.equal(r.signaturesVerified, false);
  assert.ok(r.warnings.some((w) => /not authenticated/i.test(w)));
});

// Every attack vector MUST be rejected. This is the core security property.
const ATTACKS = [
  "attack/tampered-content.json",
  "attack/forged-genesis.json",
  "attack/key-swap.json",
  "attack/key-swap-resigned.json",
  "attack/unknown-kid.json",
  "attack/seq-gap.json",
  "attack/head-truncated.json",
  "attack/cross-chain-splice.json",
  "attack/dup-seq.json",
  "attack/wrong-signature.json",
  "attack/relinked.json",
];
for (const a of ATTACKS) {
  test(`attack rejected (with keyring): ${a}`, () => {
    const r = verifyChain(load(a), { keyring, checkpoint });
    assert.notEqual(r.status, "VALID", `${a} must not verify as VALID`);
    assert.notEqual(r.status, "UNVERIFIED", `${a} must not pass as UNVERIFIED`);
    assert.equal(r.status, "TAMPERED", `${a} -> expected TAMPERED, got ${r.status}: ${r.reason}`);
  });
}

test("unknown-kid: TAMPERED with keyring, UNVERIFIED without (no silent TOFU on attacker input)", () => {
  const withKey = verifyChain(load("attack/unknown-kid.json"), { keyring });
  assert.equal(withKey.status, "TAMPERED");
  assert.match(withKey.reason ?? "", /unknown signing key/);
  const noKey = verifyChain(load("attack/unknown-kid.json"), {});
  assert.equal(noKey.status, "UNVERIFIED");
});

test("signed body commits to seq + scope.chain: head-truncation and cross-chain splice are caught", () => {
  const ht = verifyChain(load("attack/head-truncated.json"), { keyring });
  assert.equal(ht.status, "TAMPERED");
  assert.match(ht.reason ?? "", /seq|genesis/i);
  const xc = verifyChain(load("attack/cross-chain-splice.json"), { keyring });
  assert.equal(xc.status, "TAMPERED");
  assert.match(xc.reason ?? "", /chain partition|duplicate seq/i);
});

test("key-swap-resigned is caught by key-pinning, not signature presence", () => {
  // attacker controls a real keypair; pinning per agent.id still rejects.
  const r = verifyChain(load("attack/key-swap-resigned.json"), { keyring });
  assert.equal(r.status, "TAMPERED");
  assert.match(r.reason ?? "", /key swap/);
});

test("relinked is caught by linkage check (hash + sig are internally valid)", () => {
  const r = verifyChain(load("attack/relinked.json"), { keyring });
  assert.equal(r.status, "TAMPERED");
  assert.match(r.reason ?? "", /linkage/);
});

test("wrong-signature requires a keyring to detect", () => {
  // without keyring, sig can't be authenticated → UNVERIFIED (honest)
  const noKey = verifyChain(load("attack/wrong-signature.json"), {});
  assert.equal(noKey.status, "UNVERIFIED");
  // with keyring → TAMPERED
  const withKey = verifyChain(load("attack/wrong-signature.json"), { keyring });
  assert.equal(withKey.status, "TAMPERED");
  assert.match(withKey.reason ?? "", /signature/);
});

test("forged checkpoint (out-of-keyring key) cannot fake a tail check — trust root applies to checkpoints", () => {
  const truncated = load("attack/forged-checkpoint-chain.json");
  const forgedCp = load("attack/forged-checkpoint-cp.json") as Checkpoint;
  // with keyring → TAMPERED (checkpoint must authenticate against the same trust root as receipts)
  const withKey = verifyChain(truncated, { keyring, checkpoint: forgedCp });
  assert.equal(withKey.status, "TAMPERED");
  assert.match(withKey.reason ?? "", /checkpoint not authenticated/);
  // without keyring → UNVERIFIED, and tailChecked MUST be false (no silently-faked tail check)
  const noKey = verifyChain(truncated, { checkpoint: forgedCp });
  assert.equal(noKey.status, "UNVERIFIED");
  assert.equal(noKey.tailChecked, false);
});

test("verifyChain returns MALFORMED (never throws) on a lone-surrogate receipt fed directly", () => {
  const r = structuredClone(load("valid-chain.json")) as Array<Record<string, any>>;
  r[0]!.action.canonical = "transfer\uD800"; // lone surrogate, bypassing safeParse
  const res = verifyChain(r, { keyring });
  assert.equal(res.status, "MALFORMED");
});

test("tail-truncation: undetectable without checkpoint, detected with checkpoint", () => {
  const noCp = verifyChain(load("attack/tail-truncated.json"), { keyring });
  // honest: without a checkpoint a truncated-but-otherwise-valid prefix verifies, WITH a warning
  assert.equal(noCp.status, "VALID");
  assert.ok(noCp.warnings.some((w) => /tail-truncation/.test(w)));
  const withCp = verifyChain(load("attack/tail-truncated.json"), { keyring, checkpoint });
  assert.equal(withCp.status, "TAMPERED");
  assert.match(withCp.reason ?? "", /tail|head/);
});

// Malformed inputs: the strict parser or the verifier rejects them.
test("malformed: duplicate key rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/duplicate-key.json")));
});
test("malformed: float rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/float-number.json")));
});
test("malformed: proto-pollution rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/proto-pollution.json")));
});
test("malformed: trailing garbage rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/trailing-garbage.json")));
});
test("malformed: deep nesting rejected by safeParse", () => {
  assert.throws(() => safeParse(raw("malformed/deep-nest.json")));
});
test("malformed: unpaired surrogates rejected by safeParse (forgery channel closed)", () => {
  assert.throws(() => safeParse(raw("malformed/lone-high-surrogate.json")));
  assert.throws(() => safeParse(raw("malformed/lone-low-surrogate.json")));
  assert.throws(() => safeParse(raw("malformed/reversed-surrogate-pair.json")));
});
test("malformed: pii-smuggle (unknown field) -> MALFORMED at verify", () => {
  const parsed = safeParse(raw("malformed/pii-smuggle.json"));
  const r = verifyChain(parsed, { keyring });
  assert.equal(r.status, "MALFORMED");
  assert.match(r.reason ?? "", /unknown field/);
});

test("verifyChainText routes through the strict parser: duplicate keys -> MALFORMED at the library level", () => {
  // the strict-parse guarantee (dup-key reject) is a property of verifyChainText, not just the CLI
  const dup = raw("malformed/duplicate-key.json");
  assert.equal(verifyChainText(dup).status, "MALFORMED");
  // and a valid chain text verifies
  assert.equal(verifyChainText(raw("valid-chain.json"), { keyring }).status, "VALID");
});

test("non-array input -> MALFORMED", () => {
  assert.equal(verifyChain({ not: "an array" }).status, "MALFORMED");
});
test("empty array -> MALFORMED", () => {
  assert.equal(verifyChain([]).status, "MALFORMED");
});

// ── round-12 audit regressions ──────────────────────────────────────────────
test("round-12 #9: verifyCheckpoint is fail-closed on null/non-object (malformed, never throws)", () => {
  assert.equal(verifyCheckpoint(null as unknown as Checkpoint, keyring), "malformed checkpoint");
  assert.equal(verifyCheckpoint(undefined as unknown as Checkpoint, keyring), "malformed checkpoint");
  assert.equal(verifyCheckpoint("x" as unknown as Checkpoint, keyring), "malformed checkpoint");
  assert.equal(verifyCheckpoint([] as unknown as Checkpoint, keyring), "malformed checkpoint");
});

test("round-12 #11: checkpoint is strictly schema-validated (unknown field / bad ts / bad headHash → malformed)", () => {
  assert.equal(verifyCheckpoint(checkpoint, keyring), "ok"); // genuine checkpoint still authenticates
  const extra = { ...checkpoint, smuggled: "ssn=123-45-6789" } as unknown as Checkpoint;
  assert.equal(verifyCheckpoint(extra, keyring), "malformed checkpoint"); // additionalProperties:false even in the SIGNED surface
  const badTs = { ...checkpoint, ts: 1718000000 } as unknown as Checkpoint;
  assert.equal(verifyCheckpoint(badTs, keyring), "malformed checkpoint"); // numeric ts rejected
  const badHead = { ...checkpoint, headHash: "deadbeef" } as unknown as Checkpoint;
  assert.equal(verifyCheckpoint(badHead, keyring), "malformed checkpoint"); // headHash must be sha256:<64hex>
});

test("round-12 #3: a non-canonical base64 signature is TAMPERED (sig.value must round-trip to canonical)", () => {
  const chain = structuredClone(load("valid-chain.json")) as Array<Record<string, any>>;
  // embedded whitespace: Buffer.from decodes leniently to the SAME 64 bytes, but it is not canonical base64.
  chain[0]!.sig.value = chain[0]!.sig.value.slice(0, 4) + " " + chain[0]!.sig.value.slice(4);
  assert.equal(verifyChain(chain, { keyring }).status, "TAMPERED");
});

test("round-12 #10: verifyChain on a receipt with a throwing accessor → MALFORMED (never throws out)", () => {
  let res!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res = verifyChain([{ get spec() { throw new Error("boom"); } }], { keyring }); });
  assert.equal(res.status, "MALFORMED");
});

test("round-13 #4: checkpoint sig sub-object is strict (extra field / bad alg → malformed)", () => {
  const sigExtra = { ...checkpoint, sig: { ...checkpoint.sig, smuggled: "ssn=123" } } as unknown as Checkpoint;
  assert.equal(verifyCheckpoint(sigExtra, keyring), "malformed checkpoint"); // additionalProperties on sig
  const badAlg = { ...checkpoint, sig: { ...checkpoint.sig, alg: "rsa" } } as unknown as Checkpoint;
  assert.equal(verifyCheckpoint(badAlg, keyring), "malformed checkpoint"); // unvalidated alg closed
});

test("round-13 #8: throwing identityManifest / array-element accessors → MALFORMED (never throws)", () => {
  const arr: unknown[] = [];
  Object.defineProperty(arr, "0", { enumerable: true, configurable: true, get() { throw new Error("boom"); } });
  let r1!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { r1 = verifyChain(arr, { keyring }); });
  assert.equal(r1.status, "MALFORMED");
  const man: Record<string, unknown> = {};
  Object.defineProperty(man, "a1", { enumerable: true, configurable: true, get() { throw new Error("boom"); } });
  let r2!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { r2 = verifyChain(load("valid-chain.json"), { keyring, identityManifest: man as never }); });
  assert.equal(r2.status, "MALFORMED");
});

// ── round-15 audit regressions (live-object TOCTOU snapshot-once + non-object keyring) ──────────────
test("round-15 #2: a flipping checkpoint accessor cannot yield VALID over a truncated tail (snapshot defeats it)", () => {
  // The chain presents seq 0..2; the legit checkpoint asserts head=seq2. A truncating attacker presents a
  // checkpoint whose highestSeq/headHash FLIP on read: returning the legit head (seq2/realHash) to the
  // signature/validation path, but the truncated head to the tail-match. Snapshotting the checkpoint ONCE
  // means both reads see the SAME bytes → no VALID-over-erased-tail.
  const validChain = load("valid-chain.json") as Array<Record<string, any>>;
  const truncated = validChain.slice(0, 1); // attacker drops seq 1..2, presents only seq 0
  const realCp = structuredClone(checkpoint) as any;
  const truncatedHead = truncated[0]!.chain;
  let seqReads = 0, hashReads = 0;
  const flip: any = {
    spec: realCp.spec, chain: realCp.chain, ts: realCp.ts, sig: realCp.sig,
    // First read (validation/preimage) returns the legit head; later read (tail-match) returns the truncated head.
    get highestSeq() { return seqReads++ === 0 ? realCp.highestSeq : truncatedHead.seq; },
    get headHash() { return hashReads++ === 0 ? realCp.headHash : truncatedHead.hash; },
  };
  const res = verifyChain(truncated, { keyring, checkpoint: flip });
  assert.notEqual(res.status, "VALID", `flipping checkpoint must not verify VALID (got ${res.status})`);
  assert.equal(res.tailChecked, false, "tail must not be reported as checked over a flipped/truncated head");
});

test("round-15 #5: verifyCheckpoint with a throwing accessor → 'malformed checkpoint' (never throws a raw Error)", () => {
  const evil: any = {
    spec: "noa.checkpoint/0.1", chain: "c", highestSeq: 0, ts: "2026-06-21T10:00:00.000Z",
    sig: { alg: "ed25519", kid: "k", value: "x" },
    get headHash(): string { throw new Error("boom"); },
  };
  let verdict!: ReturnType<typeof verifyCheckpoint>;
  assert.doesNotThrow(() => { verdict = verifyCheckpoint(evil as unknown as Checkpoint, keyring); });
  assert.equal(verdict, "malformed checkpoint");
});

test("round-15 #9: a flipping agent.id accessor cannot produce a false VALID attribution (snapshot reads once)", () => {
  // A genuine single-receipt chain whose agent.id FLIPS between reads: returns the real (manifest-authorized)
  // id to the structural/sig path, but a different id later. structuredClone reads each field exactly once, so
  // the value enforced is the value validated — no split that could mis-attribute a VALID result.
  const validChain = load("valid-chain.json") as Array<Record<string, any>>;
  const r0 = structuredClone(validChain[0]!) as any;
  const realAgentId = r0.agent.id;
  let idReads = 0;
  const agentNoId: any = { model: r0.agent.model, principal: r0.agent.principal };
  Object.defineProperty(agentNoId, "id", {
    enumerable: true, configurable: true,
    get() { return idReads++ === 0 ? realAgentId : "attacker-spoofed"; },
  });
  const flipReceipt: any = { ...r0, agent: agentNoId };
  let res!: ReturnType<typeof verifyChain>;
  assert.doesNotThrow(() => { res = verifyChain([flipReceipt], { keyring }); });
  // After the snapshot, agent.id is a frozen value; the genesis-only single-receipt chain stays internally
  // consistent. The KEY property: the result is NOT a VALID attribution computed off a mid-flip read.
  if (res.status === "VALID") {
    // a VALID result must reflect the SNAPSHOT id, not a post-snapshot flip — re-reading the live getter
    // would have advanced idReads beyond the snapshot's single read.
    assert.ok(idReads <= 1, `agent.id must be read at most once before snapshot (got ${idReads} reads)`);
  } else {
    assert.equal(res.status, "TAMPERED"); // a flip that breaks the hash is caught — never a false VALID
  }
});

test("round-15 #7: a non-object keyring (array / null) → MALFORMED (parity with the Python verifier)", () => {
  const arrKr = verifyChain(load("valid-chain.json"), { keyring: [] as unknown as Keyring });
  assert.equal(arrKr.status, "MALFORMED");
  assert.match(arrKr.reason ?? "", /keyring must be an object/);
  const nullKr = verifyChain(load("valid-chain.json"), { keyring: null as unknown as Keyring });
  assert.equal(nullKr.status, "MALFORMED");
  assert.match(nullKr.reason ?? "", /keyring must be an object/);
  // sanity: a genuine keyring still verifies VALID (no regression on the happy path)
  assert.equal(verifyChain(load("valid-chain.json"), { keyring }).status, "VALID");
});
