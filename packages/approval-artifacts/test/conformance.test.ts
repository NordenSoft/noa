/**
 * §6 conformance runner: loads every committed vector, the shipped schemas, and the shared trust
 * root, and asserts each vector's `verifyArtifact` result matches its declared `expect`. This is the
 * P1b-alpha DoD gate (§15): "1 valid + 7 rejection each ... All 7 rejections MUST fail. CI fixtures,
 * not manual QA." A single mismatch fails the build.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ARTIFACTS } from "../src/domains.js";
import { verifyEd25519 } from "../src/crypto.js";
import { verifyArtifact, type KeyEntry, type VerifyContext } from "../src/verify.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const SCHEMA_DIR = join(ROOT, "schema");
const CONF_DIR = join(ROOT, "conformance");

function loadJson(p: string): unknown {
  return JSON.parse(readFileSync(p, "utf8"));
}

// spec -> shipped schema object (schema/<schemaId>) — the enforced structural validator.
const schemas: Record<string, unknown> = {};
for (const meta of Object.values(ARTIFACTS)) {
  schemas[meta.spec] = loadJson(join(SCHEMA_DIR, meta.schemaId));
}
const keyring = loadJson(join(CONF_DIR, "keyring.json")) as Record<string, KeyEntry>;

interface Vector {
  description: string;
  spec: string;
  expect: "ACCEPT" | "REJECT";
  rejectionClass?: string;
  artifact: unknown;
  context: Omit<VerifyContext, "schemas" | "keyring">;
}

interface Loaded {
  slug: string;
  file: string;
  vec: Vector;
}
const vectors: Loaded[] = [];
for (const entry of readdirSync(CONF_DIR)) {
  const abs = join(CONF_DIR, entry);
  if (!statSync(abs).isDirectory()) continue; // skip keyring.json / INDEX.json
  for (const f of readdirSync(abs)) {
    if (!f.endsWith(".json")) continue;
    vectors.push({ slug: entry, file: f, vec: loadJson(join(abs, f)) as Vector });
  }
}

test("conformance corpus is non-empty and complete (every folder = 1 valid + ≥7 reject)", () => {
  assert.ok(vectors.length >= 100, `expected ≥100 vectors, found ${vectors.length}`);
  const byslug = new Map<string, { valid: number; reject: number }>();
  for (const v of vectors) {
    const c = byslug.get(v.slug) ?? { valid: 0, reject: 0 };
    if (v.vec.expect === "ACCEPT") c.valid++;
    else c.reject++;
    byslug.set(v.slug, c);
  }
  for (const [slug, c] of byslug) {
    assert.equal(c.valid, 1, `${slug}: expected exactly 1 valid vector, got ${c.valid}`);
    assert.ok(c.reject >= 7, `${slug}: expected ≥7 rejection vectors, got ${c.reject}`);
  }
  // Hold and Decision each carry one additional security regression beyond the base seven.
  assert.equal(byslug.get("hold-envelope")!.reject, 8, "hold-envelope must ship 8 rejections (incl. F2 recipients-swap)");
  assert.equal(byslug.get("decision")!.reject, 8, "decision must ship 8 rejections (incl. signer-identity split)");
});

test("every valid vector ACCEPTS and every rejection vector REJECTS", () => {
  const failures: string[] = [];
  for (const { slug, file, vec } of vectors) {
    const ctx: VerifyContext = { ...vec.context, schemas, keyring };
    const res = verifyArtifact(vec.artifact, ctx);
    const wantOk = vec.expect === "ACCEPT";
    if (res.ok !== wantOk) {
      failures.push(`${slug}/${file}: expected ${vec.expect} but verifier returned ok=${res.ok}${res.reason ? ` (${res.reason})` : ""}`);
    }
  }
  assert.deepEqual(failures, [], `\n${failures.join("\n")}`);
});

// Per-vector named subtests give a readable pass/fail line per fixture.
for (const { slug, file, vec } of vectors) {
  test(`${slug}/${file.replace(/\.json$/, "")} → ${vec.expect}`, () => {
    const res = verifyArtifact(vec.artifact, { ...vec.context, schemas, keyring });
    assert.equal(res.ok, vec.expect === "ACCEPT", res.reason);
  });
}

test("strict Ed25519 parity rejects all canonical small-order public keys", () => {
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const smallOrderRaw = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  ];
  const message = Buffer.from("NOA side-artifact strict verifier parity", "utf8");
  const signature = Buffer.alloc(64, 7).toString("base64");
  for (const rawHex of smallOrderRaw) {
    const publicKey = Buffer.concat([spkiPrefix, Buffer.from(rawHex, "hex")]).toString("base64");
    assert.equal(verifyEd25519(publicKey, message, signature), false, rawHex);
  }
});

test("strict Ed25519 parity rejects a non-canonical y coordinate", () => {
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const nonCanonicalY = Buffer.from(
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "hex",
  );
  const publicKey = Buffer.concat([spkiPrefix, nonCanonicalY]).toString("base64");
  assert.equal(
    verifyEd25519(
      publicKey,
      Buffer.from("NOA side-artifact strict verifier parity", "utf8"),
      Buffer.alloc(64, 7).toString("base64"),
    ),
    false,
  );
});

test("Decision verifier rejects the OpenSSL small-order universal forgery", () => {
  const loaded = vectors.find(({ slug, vec }) => slug === "decision" && vec.expect === "ACCEPT");
  assert.ok(loaded, "valid Decision vector must exist");

  const artifact = structuredClone(loaded.vec.artifact) as {
    sig: { kid: string; value: string };
  };
  const forgedKeyring = structuredClone(keyring);
  artifact.sig.value = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
  forgedKeyring[artifact.sig.kid]!.publicKey =
    "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

  const result = verifyArtifact(artifact, {
    ...loaded.vec.context,
    schemas,
    keyring: forgedKeyring,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /invalid signature/);
});

test("live authorization evaluates revocation at verifier time, not signer-controlled decidedAt", () => {
  const loaded = vectors.find(({ slug, vec }) => slug === "decision" && vec.expect === "ACCEPT");
  assert.ok(loaded, "valid Decision vector must exist");
  const historicalKeyring = structuredClone(keyring);
  const artifact = structuredClone(loaded.vec.artifact) as { sig: { kid: string } };
  historicalKeyring[artifact.sig.kid]!.revokedAt = "2026-07-14T11:58:00.000Z";

  const historical = verifyArtifact(artifact, {
    ...loaded.vec.context,
    schemas,
    keyring: historicalKeyring,
  });
  assert.equal(historical.ok, true, historical.reason);

  const liveAuthorization = verifyArtifact(artifact, {
    ...loaded.vec.context,
    schemas,
    keyring: historicalKeyring,
    authorizationTime: "2026-07-14T12:00:00.000Z",
  });
  assert.equal(liveAuthorization.ok, false);
  assert.match(liveAuthorization.reason ?? "", /revoked/);
});

test("an invalid verifier-controlled authorization time fails closed", () => {
  const loaded = vectors.find(({ slug, vec }) => slug === "decision" && vec.expect === "ACCEPT");
  assert.ok(loaded, "valid Decision vector must exist");
  const result = verifyArtifact(loaded.vec.artifact, {
    ...loaded.vec.context,
    schemas,
    keyring,
    authorizationTime: "not-a-time",
  });
  assert.equal(result.ok, false);
  assert.match(result.reason ?? "", /authorizationTime/);
});
