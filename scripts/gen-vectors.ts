/**
 * Deterministic conformance-vector generator.
 *
 * Produces a known-good chain + a checkpoint + keyring, then derives every attack variant
 * from it. Output is committed so anyone can independently re-derive and diff. The keypair
 * below is a TEST-ONLY fixture (its private key is intentionally public) — NEVER a real key.
 */

import { mkdirSync, writeFileSync, rmSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildReceipt, buildCheckpoint, type Signer } from "../src/builder.js";
import { sha256Prefixed, sha256Hex } from "../src/hash.js";
import { receiptHashInput } from "../src/canonicalize.js";
import { signEd25519 } from "../src/keys.js";
import { signingMessage, RECEIPT_SIG_DOMAIN } from "../src/signing.js";
import type { Receipt, BuildInput } from "../src/index.js";

/** Re-hash + re-sign a hand-mutated receipt so it is self-consistent (valid hash + sig under
 *  the domain-separated scheme). Used to test the linkage/pinning/genesis branches in
 *  isolation — the receipt is internally valid, so only the intended check can reject it. */
function reseal(r: Receipt, privateKey: string): Receipt {
  const hi = receiptHashInput(r);
  r.chain.hash = "sha256:" + sha256Hex(hi);
  r.sig.value = signEd25519(privateKey, signingMessage(RECEIPT_SIG_DOMAIN, hi));
  return r;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = join(__dirname, "..", "..", "conformance", "vectors");

// --- TEST-ONLY fixture key (private key is public on purpose; do not reuse) ---
const KID = "noa-test-key-2026";
const PUBLIC_KEY = "MCowBQYDK2VwAyEAfCMjakcMSx1Azeehv+DU2bchtPTvB+uoloJ0kJNWI24=";
const PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIIE3nsJTdj5WI7d3Nzp6qggQXOgsaAIofegG3vTrvwf4";
const signer: Signer = { kid: KID, privateKey: PRIVATE_KEY };

// TEST-ONLY attacker key — represents an adversary who controls *a* valid keypair but is
// not the pinned chain key. Proves key-pinning, not just signature presence.
const ATTACKER_KID = "kid-attacker";
const ATTACKER_PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIMqFDluCpTmlDEfud4fWHosahDyk9XFkcikj8dsP7X3e";

// agent.model is a vendor-neutral free string in the spec; use a generic example.
const EXAMPLE_MODEL = "example-provider/llm-v1";
const CHAIN = "store_demo_chain";

function ph(s: string): string {
  return sha256Prefixed(s);
}

const inputs: BuildInput[] = [
  {
    id: "rcpt_0000000000000000000000000A",
    ts: "2026-06-20T07:30:54.000Z",
    scope: { tenant: "store_demo", chain: CHAIN },
    agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "SERVICE" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "DEFERRED", ruleId: "high-risk-deferral", approval: null, sandboxed: false },
  },
  {
    id: "rcpt_0000000000000000000000000B",
    ts: "2026-06-20T07:31:10.000Z",
    scope: { tenant: "store_demo", chain: CHAIN },
    agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "HUMAN" },
    action: { id: "payment.refund", canonical: "payment.refund", riskClass: "HIGH", paramsHash: ph("amount=4200;currency=DKK"), reversible: false, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "human-approved", approval: { by: "HUMAN:owner@store.example", at: "2026-06-20T07:31:08.000Z" }, sandboxed: false },
  },
  {
    id: "rcpt_0000000000000000000000000C",
    ts: "2026-06-20T07:45:00.000Z",
    scope: { tenant: "store_demo", chain: CHAIN },
    agent: { id: "agent-refunds", model: EXAMPLE_MODEL, principal: "POLICY" },
    action: { id: "email.send", canonical: "email.send", riskClass: "LOW", paramsHash: ph("template=refund_confirm"), reversible: true, rollbackRef: null },
    governance: { mode: "on", verdict: "EXECUTED", ruleId: "low-risk-auto", approval: null, sandboxed: false },
  },
];

const chain: Receipt[] = [];
let prev: Receipt | null = null;
for (const inp of inputs) {
  const r = buildReceipt(inp, prev, signer);
  chain.push(r);
  prev = r;
}
const head = chain[chain.length - 1]!;
const checkpoint = buildCheckpoint(head, "2026-06-20T07:46:00.000Z", signer);
const keyring = { [KID]: PUBLIC_KEY };

function clone<T>(v: T): T {
  return structuredClone(v);
}

function write(rel: string, data: unknown): void {
  const path = join(OUT, rel);
  mkdirSync(dirname(path), { recursive: true });
  const text = typeof data === "string" ? data : JSON.stringify(data, null, 2) + "\n";
  writeFileSync(path, text);
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

// --- valid fixtures ---
write("valid-chain.json", chain);
write("keyring.json", keyring);
write("checkpoint.json", checkpoint);

// --- attack variants (structurally valid JSON, integrity broken) ---

// 1. content tampered (alter a field without recomputing hash)
const tampered = clone(chain);
tampered[1]!.action.paramsHash = ph("amount=999999;currency=DKK");
write("attack/tampered-content.json", tampered);

// 2. tail truncated (drop the head) — only detectable with checkpoint
write("attack/tail-truncated.json", clone(chain).slice(0, 2));

// 3. forged genesis (prevHash not null at seq 0), re-sealed so only the genesis rule catches it
const forged = clone(chain);
forged[0]!.chain.prevHash = ph("fake-genesis");
reseal(forged[0]!, PRIVATE_KEY);
write("attack/forged-genesis.json", forged);

// 4a. key swap by hash-binding: change sig.kid without re-sealing -> hash mismatch
//     (proves sig.kid is bound into the hash)
const keyswap = clone(chain);
keyswap[2]!.sig.kid = ATTACKER_KID;
write("attack/key-swap.json", keyswap);

// 4b. key swap by a real adversary key: re-seal head with attacker key+kid.
//     Hash + signature are internally valid, but key-pinning per agent.id rejects it.
const keyswapResigned = clone(chain);
keyswapResigned[2]!.sig.kid = ATTACKER_KID;
reseal(keyswapResigned[2]!, ATTACKER_PRIVATE_KEY);
write("attack/key-swap-resigned.json", keyswapResigned);

// 4c. unknown signing key: a fully self-consistent chain signed by an adversary key whose kid
//     is NOT in the trusted keyring. Internally valid (hash+sig+pinning all consistent) but
//     unauthenticated → TAMPERED when a keyring is supplied, UNVERIFIED when none is.
const attackerSigner: Signer = { kid: ATTACKER_KID, privateKey: ATTACKER_PRIVATE_KEY };
const unknownKid: Receipt[] = [];
let pAtk: Receipt | null = null;
for (const inp of inputs) {
  const r = buildReceipt(inp, pAtk, attackerSigner);
  unknownKid.push(r);
  pAtk = r;
}
write("attack/unknown-kid.json", unknownKid);

// 5. seq gap (missing middle)
write("attack/seq-gap.json", [clone(chain[0]!), clone(chain[2]!)]);

// 5b. head truncation: drop the GENESIS receipt and present seq 1.. as the whole chain.
//     Caught because seq is in the signed body and the verifier requires contiguous 0..n-1.
write("attack/head-truncated.json", clone(chain).slice(1));

// 5c. cross-chain splice: a receipt from a DIFFERENT chain lifted into this input.
//     Caught because scope.chain is in the signed body (single-chain-partition check).
const otherGenesis = buildReceipt(
  { ...inputs[0]!, id: "rcpt_other_genesis", scope: { tenant: "store_other", chain: "store_other_chain" } },
  null,
  signer,
);
write("attack/cross-chain-splice.json", [clone(chain[0]!), otherGenesis]);

// 6. duplicate seq
const dupseq = clone(chain);
dupseq[2]!.chain.seq = 1;
write("attack/dup-seq.json", dupseq);

// 7. corrupted signature value (valid structure, bad sig bytes)
const badsig = clone(chain);
const v = badsig[1]!.sig.value;
badsig[1]!.sig.value = v.slice(0, -4) + (v.endsWith("AAAA") ? "BBBB" : "AAAA");
write("attack/wrong-signature.json", badsig);

// 8. broken linkage, re-sealed: head points prevHash at genesis instead of seq 1.
//    Hash + signature valid → ONLY the linkage check catches it.
const relinked = clone(chain);
relinked[2]!.chain.prevHash = chain[0]!.chain.hash;
reseal(relinked[2]!, PRIVATE_KEY);
write("attack/relinked.json", relinked);

// 9. forged checkpoint: attacker truncates the chain (hides seq 2) and signs a checkpoint over
//    the fake head with an OUT-OF-KEYRING key. The receipts still authenticate, so without the
//    trust-root rule for checkpoints this would falsely report VALID + tailChecked:true. Must be
//    TAMPERED when a keyring is supplied. Companion checkpoint written alongside.
const forgedCpChain = clone(chain).slice(0, 2);
const forgedCheckpoint = buildCheckpoint(forgedCpChain[1]!, "2026-06-20T07:50:00.000Z", attackerSigner);
write("attack/forged-checkpoint-chain.json", forgedCpChain);
write("attack/forged-checkpoint-cp.json", forgedCheckpoint);

// --- malformed (raw text / structural rejects) ---

// duplicate object key (cannot be expressed with JS objects → raw text)
write(
  "malformed/duplicate-key.json",
  '[{"spec":"noa.receipt/0.1","id":"x","id":"y","ts":"2026-06-20T00:00:00Z"}]\n',
);
// float number (receipts are integer-only)
write("malformed/float-number.json", '[{"chain":{"seq":1.5}}]\n');
// prototype pollution
write("malformed/proto-pollution.json", '{"__proto__":{"polluted":true}}\n');
// unknown extra field (PII smuggle)
const smuggle = clone(chain) as unknown as Array<Record<string, unknown>>;
smuggle[0]!["customerEmail"] = "victim@example.com";
write("malformed/pii-smuggle.json", smuggle);
// trailing garbage
write("malformed/trailing-garbage.json", "[]trailing\n");
// deeply nested (depth bomb)
let deep = "0";
for (let i = 0; i < 200; i++) deep = "[" + deep + "]";
write("malformed/deep-nest.json", deep + "\n");
// unpaired surrogates (forgery channel — must be rejected, not collapsed to U+FFFD)
write("malformed/lone-high-surrogate.json", '["transfer\\ud800"]\n');
write("malformed/lone-low-surrogate.json", '["transfer\\udfff"]\n');
write("malformed/reversed-surrogate-pair.json", '["x\\udc00\\ud800y"]\n');

const attackCount = readdirSync(join(OUT, "attack")).length;
const malformedCount = readdirSync(join(OUT, "malformed")).length;
process.stdout.write(
  `generated ${chain.length}-receipt chain + checkpoint + ${attackCount} attack + ${malformedCount} malformed vectors -> ${OUT}\n`,
);
