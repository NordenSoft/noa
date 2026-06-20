import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain } from "../src/verify.js";
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

test("non-array input -> MALFORMED", () => {
  assert.equal(verifyChain({ not: "an array" }).status, "MALFORMED");
});
test("empty array -> MALFORMED", () => {
  assert.equal(verifyChain([]).status, "MALFORMED");
});
