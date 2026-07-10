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
const GOLDEN_ROOT = join(__dirname, "..", "..", "conformance", "golden");
const V030 = join(GOLDEN_ROOT, "0.3.0");

function load(rel: string): unknown {
  return JSON.parse(readFileSync(join(V030, rel), "utf8"));
}
function raw(rel: string): string {
  return readFileSync(join(V030, rel), "utf8");
}

interface ScenarioFiles {
  chain: string;
  keyring?: string;
  checkpoint?: string;
  identityManifest?: string;
}
interface ScenarioOptions {
  keyring?: boolean;
  checkpoint?: boolean;
  identityManifest?: boolean;
  /** Frozen-data transform applied IN THE TEST (pure JS array op on already-loaded JSON — no
   *  library call, so it introduces no non-determinism and needs no extra frozen file). */
  chainTransform?: "dropLast";
}
interface ScenarioExpected {
  status: VerifyStatus;
  signaturesVerified?: boolean;
  tailChecked?: boolean;
  count?: number;
}
interface Scenario {
  name: string;
  files: ScenarioFiles;
  options: ScenarioOptions;
  expected: ScenarioExpected;
}
interface Manifest {
  version: string;
  scenarios: Scenario[];
}

const manifest = load("MANIFEST.json") as Manifest;
assert.equal(manifest.version, "0.3.0");
assert.ok(manifest.scenarios.length >= 10, "golden manifest should carry the full documented scenario set");

for (const sc of manifest.scenarios) {
  test(`golden v0.3.0: ${sc.name}`, () => {
    let chain = load(sc.files.chain) as Receipt[];
    if (sc.options.chainTransform === "dropLast") {
      assert.ok(chain.length > 1, `${sc.name}: dropLast needs >1 receipts`);
      chain = chain.slice(0, -1);
    }
    const opts: { keyring?: Keyring; checkpoint?: Checkpoint; identityManifest?: IdentityManifest } = {};
    if (sc.options.keyring) {
      assert.ok(sc.files.keyring, `${sc.name}: options.keyring=true needs files.keyring`);
      opts.keyring = load(sc.files.keyring!) as Keyring;
    }
    if (sc.options.checkpoint) {
      assert.ok(sc.files.checkpoint, `${sc.name}: options.checkpoint=true needs files.checkpoint`);
      opts.checkpoint = load(sc.files.checkpoint!) as Checkpoint;
    }
    if (sc.options.identityManifest) {
      assert.ok(sc.files.identityManifest, `${sc.name}: options.identityManifest=true needs files.identityManifest`);
      opts.identityManifest = load(sc.files.identityManifest!) as IdentityManifest;
    }

    const r = verifyChain(chain, opts);
    assert.equal(r.status, sc.expected.status, `${sc.name}: ${r.reason ?? "(no reason)"}`);
    if (sc.expected.signaturesVerified !== undefined) {
      assert.equal(r.signaturesVerified, sc.expected.signaturesVerified, `${sc.name}: signaturesVerified`);
    }
    if (sc.expected.tailChecked !== undefined) {
      assert.equal(r.tailChecked, sc.expected.tailChecked, `${sc.name}: tailChecked`);
    }
    if (sc.expected.count !== undefined) {
      assert.equal(r.count, sc.expected.count, `${sc.name}: count`);
    }
  });
}

// verifyChainText entry point — explicitly exercised on frozen RAW JSON text (not JSON.parse +
// verifyChain), since it is a separately hardened entry point (safeParse's duplicate-key /
// __proto__ / surrogate rejection) and the mandate calls it out by name alongside verifyChain.
test("golden v0.3.0: verifyChainText on raw frozen multi-chain bytes -> VALID", () => {
  const keyring = load("multi/keyring.json") as Keyring;
  const checkpoint = load("multi/checkpoint.json") as Checkpoint;
  const r = verifyChainText(raw("multi/chain.json"), { keyring, checkpoint });
  assert.equal(r.status, "VALID", r.reason);
  assert.equal(r.signaturesVerified, true);
  assert.equal(r.tailChecked, true);
  assert.equal(r.count, 4);
});

test("golden v0.3.0: genesis chain byte-for-byte hash/sig fields are exactly what v0.3.0 produced", () => {
  // Pins the literal bytes, not just the verdict -- a canonicalization change that happened to
  // still verify (e.g. re-signing/re-hashing under new logic) would still be a silent format
  // drift. This guards the raw chain.hash / sig.value strings, not only the pass/fail outcome.
  const chain = load("genesis/chain.json") as Receipt[];
  assert.equal(chain.length, 1);
  assert.equal(
    chain[0]!.chain.hash,
    "sha256:c5f7754965f371581ee66e7e0463f4f64c83b329c816229351868f74df41d4af",
  );
  assert.equal(
    chain[0]!.sig.value,
    "26rX7oAJjeAss6yWGo1EDihDGmwVgk5cCQBX+pCRg9VJxm6PU7lyTGmz5Ldn9TLwTgitCuW8NTDKR3zAdWenAQ==",
  );
});
