/**
 * Cross-version golden backcompat regression.
 *
 * The files under conformance/golden/<version>/ are FROZEN: they were produced ONCE by an
 * actual tagged release's own build (not HEAD — see conformance/golden/0.3.0/README.md and
 * scripts/gen-golden-vectors.mjs), committed as static bytes, and are loaded here VERBATIM —
 * never regenerated, never re-derived, never mutated. This test answers the one question that
 * `conformance/vectors/` (regenerated every `npm test` run from current source) structurally
 * cannot: does a receipt chain a real past release actually signed still produce the EXACT SAME
 * verdict today?
 *
 * ORACLE DISCIPLINE (why the expected verdicts are HARDCODED here, not read from MANIFEST.json):
 * the manifest and the frozen vectors were produced by the SAME generator run. If this test read
 * its expected verdicts back out of that manifest, it would only prove "today's verifier agrees
 * with whatever v0.3.0 happened to emit" — a tautology that would happily canonize a BROKEN
 * security state (e.g. an impersonation that verified VALID). So every security-critical verdict
 * below is an INDEPENDENT constant, reasoned from the cryptographic/trust semantics of the
 * scenario and annotated with WHY it must be that value. If v0.3.0 (or today's verifier) ever
 * disagrees with one of these literals, THAT disagreement is exactly the bug this file exists to
 * catch. The manifest is documentation + provenance only; this test code is the oracle.
 *
 * A verdict flip in either direction is a backcompat break:
 *  - VALID -> anything else: an already-issued, legitimately-signed receipt chain stopped
 *    verifying (the headline guarantee this test exists to protect).
 *  - TAMPERED/UNTRUSTED -> VALID (or UNVERIFIED): a security check silently stopped firing —
 *    just as serious, and exactly why golden scenarios include known-attack verdicts too.
 *
 * Determinism: purely static JSON in, `verifyChain`/`verifyChainText` out. No RNG, no clock, no
 * regeneration step — same inputs every run, on every machine, forever.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyChain, verifyChainText, type VerifyStatus } from "../src/verify.js";
import type { Keyring, Checkpoint, IdentityManifest, Receipt } from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const V030 = join(__dirname, "..", "..", "conformance", "golden", "0.3.0");

function load(rel: string): unknown {
  return JSON.parse(readFileSync(join(V030, rel), "utf8"));
}
function raw(rel: string): string {
  return readFileSync(join(V030, rel), "utf8");
}
function chain(rel: string): Receipt[] {
  return load(rel) as Receipt[];
}

// Frozen trust inputs (data only — loading these is not the oracle; the verdicts asserted against
// them ARE, and every one is a hardcoded literal below).
const genesisKeyring = load("genesis/keyring.json") as Keyring;
const multiKeyring = load("multi/keyring.json") as Keyring;
const multiCheckpoint = load("multi/checkpoint.json") as Checkpoint;
const identityKeyring = load("identity/keyring.json") as Keyring;
const identityManifest = load("identity/manifest.json") as IdentityManifest;

// ───────────────────────── GENESIS ─────────────────────────

test("golden v0.3.0 [genesis + keyring]: a well-formed single receipt correctly signed under its trusted key -> VALID", () => {
  // WHY VALID: seq-0 genesis, prevHash null, hash + sig internally consistent, kid present in the
  // supplied keyring. Every integrity check passes and the trust root authenticates the signature.
  const r = verifyChain(chain("genesis/chain.json"), { keyring: genesisKeyring });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.count, 1);
});

test("golden v0.3.0 [genesis, NO keyring]: signatures cannot be authenticated -> UNVERIFIED (never VALID)", () => {
  // WHY UNVERIFIED: with no trust root, the hash-chain is intact but no signature can be
  // authenticated. Reporting VALID here would be a lie (TOFU on unauthenticated input); the
  // documented contract is UNVERIFIED.
  const r = verifyChain(chain("genesis/chain.json"), {});
  assert.equal(r.status, "UNVERIFIED");
  assert.equal(r.signaturesVerified, false);
});

// ───────────────────────── MULTI-AGENT + CHECKPOINT ─────────────────────────

test("golden v0.3.0 [multi + keyring]: 4-receipt, 2-signer chain, both kids trusted -> VALID", () => {
  // WHY VALID: contiguous seq 0..3, every prevHash links, every sig authenticates against a
  // keyring-trusted kid, and each agent.id uses one continuous key (no mid-chain swap).
  const r = verifyChain(chain("multi/chain.json"), { keyring: multiKeyring });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.count, 4);
});

test("golden v0.3.0 [multi, NO keyring]: -> UNVERIFIED", () => {
  // WHY UNVERIFIED: same as genesis — no trust root, so signatures are not authenticated.
  const r = verifyChain(chain("multi/chain.json"), {});
  assert.equal(r.status, "UNVERIFIED");
  assert.equal(r.signaturesVerified, false);
});

test("golden v0.3.0 [multi + keyring + checkpoint]: head matches checkpoint -> VALID, tail checked", () => {
  // WHY VALID + tailChecked: the checkpoint (highestSeq 3, headHash = seq-3 hash) is signed by a
  // trusted key and matches the presented head exactly, so tail-truncation detection is armed and
  // finds nothing missing.
  const r = verifyChain(chain("multi/chain.json"), { keyring: multiKeyring, checkpoint: multiCheckpoint });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.tailChecked, true);
  assert.equal(r.count, 4);
});

test("golden v0.3.0 [multi truncated + checkpoint]: dropping the head hides seq 3 -> TAMPERED (CERTAIN)", () => {
  // WHY TAMPERED (a HARD security invariant, not a v0.3.0 quirk): the checkpoint is a signed
  // assertion that the head is seq 3 (headHash pinned). Presenting only seq 0..2 is a
  // tail-truncation attack; a verifier that returned VALID here would let an attacker silently
  // drop the most recent receipt(s). This MUST be caught for as long as `noa.receipt/0.1` is
  // supported — regardless of what any future refactor does to the happy path.
  const full = chain("multi/chain.json");
  assert.equal(full.length, 4, "fixture precondition: multi chain has 4 receipts");
  const truncated = full.slice(0, -1); // drop seq 3, the checkpoint's pinned head
  const r = verifyChain(truncated, { keyring: multiKeyring, checkpoint: multiCheckpoint });
  assert.equal(r.status, "TAMPERED", r.reason);
});

// ───────────────────────── IDENTITY MANIFEST + IMPERSONATION ─────────────────────────

test("golden v0.3.0 [identity + keyring + manifest]: each agent signs with its own authorized key -> VALID", () => {
  // WHY VALID: golden-agent-a is bound to golden-signer-a and golden-agent-b to golden-signer-b in
  // the manifest, and each receipt's (agent.id, sig.kid) pairing matches its binding.
  const r = verifyChain(chain("identity/chain.json"), { keyring: identityKeyring, identityManifest });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.count, 2);
});

test("golden v0.3.0 [identity + keyring, NO manifest]: -> VALID at kid-level attribution (backward compatible)", () => {
  // WHY VALID: without a manifest, the guarantee is the weaker, documented kid-level attribution
  // ("a keyring-trusted key signed"), not per-agent binding. Both receipts are validly signed by
  // trusted kids, so VALID is correct — and MUST stay VALID so pre-manifest callers don't break.
  const r = verifyChain(chain("identity/chain.json"), { keyring: identityKeyring });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.count, 2);
});

test("golden v0.3.0 [impersonation + keyring, NO manifest]: -> VALID but ONLY kid-level (documented weaker guarantee)", () => {
  // WHY VALID-with-warning: the impersonation receipt claims agent.id=golden-agent-a but is signed
  // by golden-signer-b — a genuine signature under a keyring-trusted key. WITHOUT a manifest the
  // verifier cannot know a-vs-b binding, so it honestly returns VALID at kid-level AND must emit
  // the "attribution is kid-level" honesty warning. This is the disclosed limit, frozen so it can
  // neither silently strengthen (false confidence) nor silently weaken.
  const r = verifyChain(chain("identity/impersonation-chain.json"), { keyring: identityKeyring });
  assert.equal(r.status, "VALID", r.reason);
  assert.ok(
    r.warnings.some((w) => /attribution is kid-level/.test(w)),
    "must carry the kid-level-attribution honesty warning",
  );
});

test("golden v0.3.0 [impersonation + keyring + manifest]: agent.id signed by the WRONG agent's key -> UNTRUSTED (CERTAIN)", () => {
  // WHY UNTRUSTED (a HARD security invariant): golden-signer-b is NOT authorized for agent.id
  // golden-agent-a in the manifest. This is the exact cross-agent-impersonation attack the
  // identityManifest exists to stop. A verifier that returned VALID here would let any holder of
  // ANY keyring-trusted key forge receipts under ANY agent identity. It MUST be UNTRUSTED forever.
  const r = verifyChain(chain("identity/impersonation-chain.json"), { keyring: identityKeyring, identityManifest });
  assert.equal(r.status, "UNTRUSTED", r.reason);
  assert.equal(r.signaturesVerified, false);
});

// ───────────────────────── RAW-TEXT ENTRY POINT ─────────────────────────

test("golden v0.3.0 [verifyChainText on raw frozen bytes]: -> VALID (strict-parse path agrees)", () => {
  // Exercises the separately-hardened verifyChainText entry point (safeParse: duplicate-key /
  // __proto__ / surrogate rejection) on the frozen RAW multi-chain text, not JSON.parse+verifyChain.
  const r = verifyChainText(raw("multi/chain.json"), { keyring: multiKeyring, checkpoint: multiCheckpoint });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.tailChecked, true);
  assert.equal(r.count, 4);
});

// ───────────────────────── BYTE-LEVEL PINS ─────────────────────────
// Pin the literal hash/sig bytes (not just the verdict) for the security-load-bearing artifacts:
// a canonicalization or signing change that happened to still VERIFY would still be a silent
// wire-format drift, and these three carry the checkpoint/impersonation trust decisions.

test("golden v0.3.0 [byte-pin genesis]: exact chain.hash + sig.value are what v0.3.0 emitted", () => {
  const g = chain("genesis/chain.json");
  assert.equal(g.length, 1);
  assert.equal(g[0]!.chain.hash, "sha256:c5f7754965f371581ee66e7e0463f4f64c83b329c816229351868f74df41d4af");
  assert.equal(
    g[0]!.sig.value,
    "26rX7oAJjeAss6yWGo1EDihDGmwVgk5cCQBX+pCRg9VJxm6PU7lyTGmz5Ldn9TLwTgitCuW8NTDKR3zAdWenAQ==",
  );
});

test("golden v0.3.0 [byte-pin impersonation]: exact chain.hash + sig.value are frozen (so the UNTRUSTED verdict is over KNOWN bytes)", () => {
  const imp = chain("identity/impersonation-chain.json");
  assert.equal(imp.length, 1);
  assert.equal(imp[0]!.agent.id, "golden-agent-a"); // claims a
  assert.equal(imp[0]!.sig.kid, "golden-signer-b"); // signed by b's key — the impersonation
  assert.equal(imp[0]!.chain.hash, "sha256:bea98da5180a1073544756efdee43d96ba751db3a8c107529372dec4f3e13445");
  assert.equal(
    imp[0]!.sig.value,
    "8gQ2KBcfvw0Pqf/m4dQnsEDLRtFYRduMGdn0jqFknI60OdRcLn8mWkoqSAwuk/uu8ibW/yNQst/OBIFocCtnCg==",
  );
});

test("golden v0.3.0 [byte-pin truncation head + checkpoint]: the seq-3 head and the checkpoint that pins it are frozen", () => {
  // The truncation TAMPERED verdict above hinges on these exact bytes: the checkpoint asserts
  // highestSeq 3 / this headHash, and the dropped receipt is this seq-3 head.
  const m = chain("multi/chain.json");
  assert.equal(m.length, 4);
  const head = m[3]!;
  assert.equal(head.chain.seq, 3);
  assert.equal(head.chain.hash, "sha256:0ea4f941c64d4307776d7fc529472dcaa9247f4bb0af5684809e9f305d64a821");
  assert.equal(
    head.sig.value,
    "jRnrXd1zbfe8qcGGJv4Y1o+KRxxcc/ZemuX9KrGTmpaLU5ukuCx0Ft9qFpEaz+/4xI8hxb+sOOB4eu9jHVnfAg==",
  );
  assert.equal(multiCheckpoint.highestSeq, 3);
  assert.equal(multiCheckpoint.headHash, "sha256:0ea4f941c64d4307776d7fc529472dcaa9247f4bb0af5684809e9f305d64a821");
});

// ───────────────────────── MANIFEST PROVENANCE (documentation guard, NOT the verdict oracle) ─────────────────────────

interface ManifestScenario {
  name: string;
  expected: { status: VerifyStatus };
}
interface Manifest {
  version: string;
  commit: string;
  receiptCount: number;
  checkpointCount: number;
  scenarios: ManifestScenario[];
}

// The verdicts the test CODE asserts (the real oracle above). The manifest is cross-checked
// against THIS map so its human-readable documentation can never silently drift into a lie — but
// note the direction of authority: this hardcoded map is derived from the reasoned assertions
// above, and the manifest must conform to it, never the reverse.
const ORACLE_VERDICTS: Record<string, VerifyStatus> = {
  "genesis-valid-with-keyring": "VALID",
  "genesis-no-keyring": "UNVERIFIED",
  "multi-valid-with-keyring": "VALID",
  "multi-no-keyring": "UNVERIFIED",
  "multi-valid-with-checkpoint": "VALID",
  "multi-truncated-with-checkpoint": "TAMPERED",
  "identity-valid-with-manifest": "VALID",
  "identity-valid-no-manifest-kid-level": "VALID",
  "impersonation-no-manifest-kid-level-valid": "VALID",
  "impersonation-with-manifest-untrusted": "UNTRUSTED",
};

test("golden v0.3.0 [provenance]: MANIFEST records the real v0.3.0 commit SHA + correct artifact counts", () => {
  const m = load("MANIFEST.json") as Manifest;
  assert.equal(m.version, "0.3.0");
  assert.match(m.commit, /^[0-9a-f]{40}$/, "manifest.commit must be the full 40-hex v0.3.0 commit SHA");
  // 8 signed receipts (1 genesis + 4 multi + 2 identity + 1 impersonation) + 1 signed checkpoint.
  assert.equal(m.receiptCount, 8);
  assert.equal(m.checkpointCount, 1);
});

test("golden v0.3.0 [manifest ↔ oracle]: the manifest's documented verdicts match the hardcoded oracle (no doc drift)", () => {
  const m = load("MANIFEST.json") as Manifest;
  for (const sc of m.scenarios) {
    const expected = ORACLE_VERDICTS[sc.name];
    assert.ok(expected !== undefined, `manifest scenario "${sc.name}" has no hardcoded oracle entry — add it`);
    assert.equal(
      sc.expected.status,
      expected,
      `manifest documents ${sc.name} as ${sc.expected.status}, but the test-code oracle says ${expected}`,
    );
  }
  // and every oracle entry must be documented in the manifest (symmetry — neither may drop a scenario)
  const names = new Set(m.scenarios.map((s) => s.name));
  for (const name of Object.keys(ORACLE_VERDICTS)) {
    assert.ok(names.has(name), `oracle scenario "${name}" is missing from MANIFEST.json`);
  }
});
