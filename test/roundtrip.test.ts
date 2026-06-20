import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "../src/keys.js";
import { buildReceipt, buildCheckpoint, type BuildInput, type Signer } from "../src/builder.js";
import { verifyChain, verifyCheckpoint } from "../src/verify.js";
import { sha256Prefixed } from "../src/hash.js";
import type { Receipt } from "../src/index.js";

function mkInput(seqId: string, ts: string): BuildInput {
  return {
    id: `rcpt_${seqId}`,
    ts,
    scope: { tenant: "t", chain: "c1" },
    agent: { id: "a1", model: null, principal: "SERVICE" },
    action: {
      id: "db.delete",
      canonical: "db.delete",
      riskClass: "CRITICAL",
      paramsHash: sha256Prefixed("table=orders;id=1"),
      reversible: true,
      rollbackRef: "snap_1",
    },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "r", approval: null, sandboxed: false },
  };
}

test("build → verify round-trips as VALID with a fresh random key", () => {
  const kp = generateKeyPair("k1");
  const signer: Signer = { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = { [kp.kid]: kp.publicKey };

  const chain: Receipt[] = [];
  let prev: Receipt | null = null;
  for (let i = 0; i < 5; i++) {
    const r = buildReceipt(mkInput(String(i), `2026-06-20T0${i}:00:00.000Z`), prev, signer);
    chain.push(r);
    prev = r;
  }

  const res = verifyChain(chain, { keyring });
  assert.equal(res.status, "VALID", res.reason);
  assert.equal(res.count, 5);

  const cp = buildCheckpoint(chain[chain.length - 1]!, "2026-06-20T06:00:00.000Z", signer);
  assert.equal(verifyCheckpoint(cp, keyring), "ok");

  const res2 = verifyChain(chain, { keyring, checkpoint: cp });
  assert.equal(res2.status, "VALID");
  assert.equal(res2.tailChecked, true);
});

test("a single bit flip anywhere breaks verification", () => {
  const kp = generateKeyPair("k1");
  const signer: Signer = { kid: kp.kid, privateKey: kp.privateKey };
  const keyring = { [kp.kid]: kp.publicKey };
  const r0 = buildReceipt(mkInput("0", "2026-06-20T00:00:00.000Z"), null, signer);
  const r1 = buildReceipt(mkInput("1", "2026-06-20T01:00:00.000Z"), r0, signer);

  // tamper r0 content after the fact
  const tampered = structuredClone([r0, r1]);
  tampered[0]!.action.riskClass = "LOW";
  assert.equal(verifyChain(tampered, { keyring }).status, "TAMPERED");
});
