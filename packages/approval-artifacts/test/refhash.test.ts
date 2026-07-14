/**
 * Golden + property tests for the F1 reference-hash convention (§6) and domain-tag distinctness.
 * The three hash rules are load-bearing forgery boundaries, so they are pinned to exact bytes here
 * (a change to canonicalization/hashing that alters any value fails this test), plus the invariants
 * that make them SAFE: JCS key-order independence, sig-inclusion for `refHash` vs sig-exclusion for
 * a receipt's own hash, and all-distinct signing domains (anti cross-protocol replay).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { refHash, virtualHash, receiptRefHash, signHashInput } from "../src/refhash.js";
import { ARTIFACTS, SIGNED_SPECS } from "../src/domains.js";

const SIDE = { b: 2, a: 1, sig: { alg: "ed25519", kid: "k", value: "V" } };
const SIDE_REORDERED = { sig: { value: "V", kid: "k", alg: "ed25519" }, a: 1, b: 2 };
const RECEIPT = { spec: "noa.receipt/0.1", id: "x", chain: { seq: 0, prevHash: null, hash: "IGNORED" }, sig: { alg: "ed25519", kid: "k", value: "IGNORED" } };

test("F1 rule-b refHash golden (JCS over the WHOLE artifact incl. sig)", () => {
  assert.equal(refHash(SIDE), "sha256:64372dc6fb51dd8011d5f7533a819382f2cdd6935f97a043068e153919bbf359");
});

test("F1 rule-a receiptRefHash golden (strips chain.hash + sig.value)", () => {
  // chain.hash="IGNORED" and sig.value="IGNORED" must NOT affect the result.
  assert.equal(receiptRefHash(RECEIPT), "sha256:e5e0f07364113b3edc9d5efb29750536c62d4701941289287928d86d33f85a60");
  const mutated = { ...RECEIPT, chain: { seq: 0, prevHash: null, hash: "DIFFERENT" }, sig: { alg: "ed25519", kid: "k", value: "DIFFERENT" } };
  assert.equal(receiptRefHash(mutated), receiptRefHash(RECEIPT), "chain.hash / sig.value are stripped");
});

test("JCS makes refHash key-order independent", () => {
  assert.equal(refHash(SIDE), refHash(SIDE_REORDERED));
  assert.equal(virtualHash(SIDE), virtualHash(SIDE_REORDERED));
});

test("refHash INCLUDES sig; a receipt's own hash EXCLUDES sig.value — they are different inputs", () => {
  // refHash keeps the whole sig; signHashInput (the signing preimage) drops it entirely.
  assert.notEqual(refHash(SIDE), virtualHash({ b: 2, a: 1 }));
  assert.equal(signHashInput(SIDE), '{"a":1,"b":2}', "signing preimage excludes the entire sig object");
});

test("all signing domains are distinct (anti cross-protocol replay) and disjoint from receipt/checkpoint tags", () => {
  const domains = Object.values(ARTIFACTS).map((m) => m.domain).filter((d): d is string => d !== null);
  assert.equal(domains.length, SIGNED_SPECS.length);
  assert.equal(new Set(domains).size, domains.length, "duplicate domain tag");
  for (const d of domains) {
    assert.ok(d !== "NOA-Receipt-v0.1-sig" && d !== "NOA-Checkpoint-v0.1-sig", `domain ${d} collides with an upstream tag`);
  }
});

test("the two HPKE-AEAD blobs are unsigned (no domain)", () => {
  assert.equal(ARTIFACTS["noa.encrypted-display/0.1"]!.domain, null);
  assert.equal(ARTIFACTS["noa.encrypted-reason/0.1"]!.domain, null);
});
