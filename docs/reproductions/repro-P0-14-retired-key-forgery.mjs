/**
 * P0-14 class regression: every repository JavaScript/TypeScript keyring verifier gets a current
 * control and a retired-key attack. The attack always uses a signer-chosen timestamp from before
 * retirement; a pass would therefore reproduce the backdated retired-key forgery.
 *
 * Flat maps remain the compatibility contract for genuinely static, non-rotating trust roots. This
 * probe never manufactures a flat map from lifecycle data: the downgrade helpers are tested below.
 */
import { spawn, spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  SIGNING_KEY_LIFECYCLE_SPEC,
  buildCheckpoint,
  buildReceipt,
  complianceCommit,
  coseSign1Verify,
  generateKeyPair,
  receiptFromCose,
  receiptToCose,
  resolveVerificationKey,
  sha256Prefixed,
  verifyChain,
  verifyChainText,
  verifyChainWitnessed,
  verifyCheckpoint,
  verifyReceiptCompliance,
} from "../../dist/src/index.js";
import {
  ARTIFACTS,
  verifyArtifact,
} from "../../packages/approval-artifacts/dist/src/index.js";
import {
  asStringKeyring,
  buildReceiptKeyring,
  loadSchemas as loadEvidenceSchemas,
  verifyEvidence,
} from "../../packages/evidence/dist/src/index.js";
import {
  buildApprovalReceipt,
  verifyApprovalReceipt,
} from "../../packages/adapter-core/src/index.mjs";
import {
  buildOutcomeReceipt,
  verifyOutcomeReceipt,
} from "../../packages/mcp-proxy/src/outcome-receipt.mjs";
import { createRotatableSigner } from "../../packages/mcp-proxy/src/rotatable-signer.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const enc = new TextEncoder();
const b = (value) => enc.encode(JSON.stringify(value));
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const RETIRED_AT = "2026-08-01T08:36:12.643Z";
const BEFORE = "2020-01-01T00:00:00.000Z";
const AFTER = "2026-08-01T08:36:12.644Z";

const rows = [];
function probe(surface, controlOk, attackRefused, controlDetail, attackDetail) {
  rows.push({ surface, controlOk, attackRefused, controlDetail, attackDetail });
  console.log(`CONTROL ${surface.padEnd(34)} -> ${controlOk ? "PASS" : "FAIL"}  ${controlDetail}`);
  console.log(`ATTACK  ${surface.padEnd(34)} -> ${attackRefused ? "REFUSED" : "ACCEPTED"}  ${attackDetail}`);
}

function receipt(signer, id, ts, compliance = undefined) {
  return buildReceipt({
    id,
    ts,
    scope: { chain: `chain-${id}`, tenant: "tenant-p0-14" },
    agent: { id: "agent-p0-14", model: null, principal: "SERVICE" },
    action: {
      id: "wire.transfer",
      canonical: "wire.transfer",
      riskClass: "HIGH",
      paramsHash: sha256Prefixed(id),
      reversible: false,
      rollbackRef: null,
    },
    governance: {
      mode: "on",
      verdict: "EXECUTED",
      ruleId: null,
      approval: null,
      sandboxed: false,
      ...(compliance === undefined ? {} : { compliance }),
    },
  }, null, signer);
}

function lifecycle(retiredKey, currentKey, retiredAt = RETIRED_AT) {
  return {
    spec: SIGNING_KEY_LIFECYCLE_SPEC,
    keys: {
      [retiredKey.kid]: { publicKey: retiredKey.publicKey, retiredAt },
      [currentKey.kid]: { publicKey: currentKey.publicKey, retiredAt: null },
    },
  };
}

function cliVerify(chain, keyring) {
  const dir = mkdtempSync(join(tmpdir(), "noa-p0-14-cli-"));
  try {
    const chainPath = join(dir, "chain.json");
    const keyringPath = join(dir, "keyring.json");
    writeFileSync(chainPath, JSON.stringify(chain));
    writeFileSync(keyringPath, JSON.stringify(keyring));
    const run = spawnSync(process.execPath, [join(ROOT, "dist/src/cli.js"), "verify", chainPath, "--keyring", keyringPath], {
      cwd: ROOT,
      encoding: "utf8",
    });
    return { status: run.status, output: `${run.stdout}${run.stderr}`.trim() };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function evidenceCliVerify(fixture, checkpointKeyring) {
  const dir = mkdtempSync(join(tmpdir(), "noa-p0-14-evidence-cli-"));
  try {
    const bundlePath = join(dir, "bundle.json");
    const rootPath = join(dir, "tenant-root.json");
    const ringPath = join(dir, "checkpoint-keyring.json");
    writeFileSync(bundlePath, JSON.stringify(fixture.bundle));
    writeFileSync(rootPath, JSON.stringify(fixture.tenantRoot));
    writeFileSync(ringPath, JSON.stringify(checkpointKeyring));
    const run = spawnSync(process.execPath, [
      join(ROOT, "packages/evidence/dist/src/cli.js"),
      bundlePath,
      "--tenant-root", rootPath,
      "--checkpoint-keyring", ringPath,
      "--now", fixture.now,
      "--max-age-hours", String(fixture.maxAgeHours),
    ], { cwd: ROOT, encoding: "utf8" });
    return { status: run.status, output: `${run.stdout}${run.stderr}`.trim() };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function wireRequest(id, chain, keyring) {
  const doc = Buffer.from(JSON.stringify(chain));
  const ring = Buffer.from(JSON.stringify(keyring));
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64BE(BigInt(id));
  const nonce = Buffer.alloc(32, id);
  const tlv = (tag, value) => {
    const head = Buffer.alloc(5);
    head[0] = tag;
    head.writeUInt32BE(value.length, 1);
    return Buffer.concat([head, value]);
  };
  const payload = Buffer.concat([
    Buffer.from([1, 2]),
    idBuf,
    nonce,
    Buffer.from([1]),
    tlv(1, doc),
    tlv(2, ring),
  ]);
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length);
  payload.copy(frame, 4);
  return frame;
}

function frames(buffer) {
  const out = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    if (offset + 4 + length > buffer.length) break;
    out.push(buffer.subarray(offset + 4, offset + 4 + length));
    offset += 4 + length;
  }
  return out;
}

async function serveVerify(id, chain, keyring) {
  const child = spawn(process.execPath, [join(ROOT, "dist/src/cli.js"), "--serve", "--frame-timeout-ms", "5000"], {
    cwd: ROOT,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  child.stdin.end(wireRequest(id, chain, keyring));
  const exit = await new Promise((resolveExit) => child.on("close", resolveExit));
  const parsedFrames = frames(Buffer.concat(stdout));
  const response = parsedFrames.find((frame) => frame[1] === 3);
  if (!response) return { exit, status: "NO_RESPONSE", stderr: Buffer.concat(stderr).toString("utf8") };
  const verdictLength = response.readUInt32BE(74);
  const verdict = JSON.parse(response.subarray(78, 78 + verdictLength).toString("utf8"));
  return { exit, status: verdict.status, reason: verdict.reason };
}

const retired = generateKeyPair("p0-14-retired");
const current = generateKeyPair("p0-14-current");
const otherCurrent = generateKeyPair("p0-14-other-current");
const staticKey = generateKeyPair("p0-14-static");
const retiredSigner = { kid: retired.kid, privateKey: retired.privateKey };
const currentSigner = { kid: current.kid, privateKey: current.privateKey };
const retiredReceipt = receipt(retiredSigner, "retired-backdated", BEFORE);
const currentReceipt = receipt(currentSigner, "current", AFTER);
const lifecycleDoc = lifecycle(retired, current);
const currentLifecycle = lifecycle(retired, current, null);
const staticMap = { [staticKey.kid]: staticKey.publicKey };
const staticReceipt = receipt({ kid: staticKey.kid, privateKey: staticKey.privateKey }, "static", AFTER);

// Shared resolver: this is exported so downstream packages have one decision, not copied parsers.
const resolverControl = resolveVerificationKey(b(currentLifecycle), retired.kid);
const resolverAttack = resolveVerificationKey(b(lifecycleDoc), retired.kid);
probe(
  "resolveVerificationKey",
  resolverControl.ok,
  !resolverAttack.ok && /retired/i.test(resolverAttack.reason),
  resolverControl.ok ? "current key resolved" : resolverControl.reason,
  resolverAttack.ok ? "retired key resolved" : resolverAttack.reason,
);

// Root chain, text alias, and standalone checkpoint.
const chainControl = verifyChain(b([currentReceipt]), { keyring: b(lifecycleDoc) });
const chainAttack = verifyChain(b([retiredReceipt]), { keyring: b(lifecycleDoc) });
probe("verifyChain", chainControl.status === "VALID", chainAttack.status === "TAMPERED" && /retired/i.test(chainAttack.reason ?? ""), chainControl.status, `${chainAttack.status}: ${chainAttack.reason}`);

const textControl = verifyChainText(JSON.stringify([currentReceipt]), { keyring: JSON.stringify(lifecycleDoc) });
const textAttack = verifyChainText(JSON.stringify([retiredReceipt]), { keyring: JSON.stringify(lifecycleDoc) });
probe("verifyChainText", textControl.status === "VALID", textAttack.status === "TAMPERED" && /retired/i.test(textAttack.reason ?? ""), textControl.status, `${textAttack.status}: ${textAttack.reason}`);

const currentCheckpoint = buildCheckpoint(currentReceipt, AFTER, currentSigner);
const retiredCheckpoint = buildCheckpoint(currentReceipt, BEFORE, retiredSigner);
const checkpointControl = verifyCheckpoint(b(currentCheckpoint), b(lifecycleDoc));
const checkpointAttack = verifyCheckpoint(b(retiredCheckpoint), b(lifecycleDoc));
probe("verifyCheckpoint", checkpointControl === "ok", checkpointAttack === "retired signing key", checkpointControl, checkpointAttack);

const witnessOpts = { anchors: b([]), trustSet: b({ witnesses: [], quorum: 0 }) };
const witnessedControl = verifyChainWitnessed(b([currentReceipt]), b(lifecycleDoc), witnessOpts);
const witnessedAttack = verifyChainWitnessed(b([retiredReceipt]), b(lifecycleDoc), witnessOpts);
probe("verifyChainWitnessed", witnessedControl.chain.status === "VALID", witnessedAttack.chain.status === "TAMPERED" && /retired/i.test(witnessedAttack.chain.reason ?? ""), witnessedControl.chain.status, `${witnessedAttack.chain.status}: ${witnessedAttack.chain.reason}`);

const cliControl = cliVerify([currentReceipt], lifecycleDoc);
const cliAttack = cliVerify([retiredReceipt], lifecycleDoc);
probe("root noa verify CLI", cliControl.status === 0, cliAttack.status === 2 && /retired/i.test(cliAttack.output), `exit=${cliControl.status}`, `exit=${cliAttack.status}: ${cliAttack.output}`);

const serveControl = await serveVerify(1, [currentReceipt], lifecycleDoc);
const serveAttack = await serveVerify(1, [retiredReceipt], lifecycleDoc);
probe("root noa --serve IPC", serveControl.status === "VALID", serveAttack.status === "TAMPERED" && /retired/i.test(serveAttack.reason ?? ""), `${serveControl.status} exit=${serveControl.exit}`, `${serveAttack.status}: ${serveAttack.reason}`);

// COSE direct and receipt composition.
const currentCose = receiptToCose(currentReceipt, currentSigner);
const retiredCose = receiptToCose(retiredReceipt, retiredSigner);
const coseControl = coseSign1Verify(currentCose, b(lifecycleDoc));
const coseAttack = coseSign1Verify(retiredCose, b(lifecycleDoc));
probe("coseSign1Verify", coseControl.ok, !coseAttack.ok && /retired/i.test(coseAttack.reason ?? ""), coseControl.ok ? "ok" : coseControl.reason, coseAttack.reason);

const receiptCoseControl = receiptFromCose(currentCose, b(lifecycleDoc));
const receiptCoseAttack = receiptFromCose(retiredCose, b(lifecycleDoc));
probe("receiptFromCose", receiptCoseControl.ok, !receiptCoseAttack.ok && /retired/i.test(receiptCoseAttack.reason ?? ""), receiptCoseControl.ok ? "ok" : receiptCoseControl.reason, receiptCoseAttack.reason);

// Compliance carrier authentication.
const policy = {
  spec: "noa.policy/0.2",
  id: "p0-14-policy",
  requiredPaths: ["action"],
  rules: [{ id: "allow-transfer", when: { op: "eq", path: "action", value: "wire.transfer" }, then: "ALLOW" }],
};
const inputs = { action: "wire.transfer" };
const commitment = complianceCommit(policy, inputs);
const complianceCurrent = receipt(currentSigner, "compliance-current", AFTER, commitment);
const complianceRetired = receipt(retiredSigner, "compliance-retired", BEFORE, commitment);
const complianceControl = verifyReceiptCompliance(b(complianceCurrent), b(policy), b(inputs), { keyring: b(lifecycleDoc) });
const complianceAttack = verifyReceiptCompliance(b(complianceRetired), b(policy), b(inputs), { keyring: b(lifecycleDoc) });
probe("verifyReceiptCompliance", complianceControl.ok, !complianceAttack.ok && /retired/i.test(complianceAttack.reason ?? ""), complianceControl.ok ? "ok" : complianceControl.reason, complianceAttack.reason);

// Generic side-artifact verification over the committed valid Decision vector.
const artifactVector = readJson(join(ROOT, "packages/approval-artifacts/conformance/decision/valid.json"));
const artifactKeyring = readJson(join(ROOT, "packages/approval-artifacts/conformance/keyring.json"));
const artifactSchemas = {};
for (const meta of Object.values(ARTIFACTS)) {
  artifactSchemas[meta.spec] = readJson(join(ROOT, "packages/approval-artifacts/schema", meta.schemaId));
}
const artifactKid = artifactVector.artifact.sig.kid;
const artifactCurrentCtx = { ...artifactVector.context, schemas: artifactSchemas, keyring: structuredClone(artifactKeyring) };
artifactCurrentCtx.keyring[artifactKid].revokedAt = null;
const artifactRetiredCtx = structuredClone(artifactCurrentCtx);
artifactRetiredCtx.keyring[artifactKid].revokedAt = RETIRED_AT;
const artifactControl = verifyArtifact(b(artifactVector.artifact), b(artifactCurrentCtx));
const artifactAttack = verifyArtifact(b(artifactVector.artifact), b(artifactRetiredCtx));
probe("verifyArtifact", artifactControl.ok, !artifactAttack.ok && /revoked/i.test(artifactAttack.reason ?? ""), artifactControl.ok ? "ok" : artifactControl.reason, artifactAttack.reason);

// Approval receipt verification, including the legitimate multi-current lifecycle regression.
const deferred = buildReceipt({
  id: "approval-deferred",
  ts: BEFORE,
  scope: { chain: "approval-chain", tenant: "tenant-p0-14" },
  agent: { id: "agent-p0-14", model: null, principal: "SERVICE" },
  action: { id: "wire.transfer", canonical: "wire.transfer", riskClass: "HIGH", paramsHash: sha256Prefixed("approval"), reversible: false, rollbackRef: null },
  governance: { mode: "on", verdict: "DEFERRED", ruleId: "human", approval: null, sandboxed: false, compliance: commitment },
}, null, currentSigner);
const approval = buildApprovalReceipt({
  deferredReceipt: deferred,
  by: `HUMAN:hmac-sha256:${"a".repeat(64)}`,
  ts: BEFORE,
  signer: retiredSigner,
}).receipt;
const approvalCurrent = {
  spec: SIGNING_KEY_LIFECYCLE_SPEC,
  keys: {
    [retired.kid]: { publicKey: retired.publicKey, retiredAt: null },
    [otherCurrent.kid]: { publicKey: otherCurrent.publicKey, retiredAt: null },
  },
};
const approvalControl = verifyApprovalReceipt(approval, { approverKeyring: approvalCurrent });
const approvalAttack = verifyApprovalReceipt(approval, { approverKeyring: lifecycleDoc });
probe("verifyApprovalReceipt", approvalControl.ok, !approvalAttack.ok && /retired/i.test(approvalAttack.reason ?? ""), approvalControl.ok ? "ok (two current keys)" : approvalControl.reason, approvalAttack.reason);

// Outcome verifier plus stale cached-handle and downgrade-API regression.
const rotatable = createRotatableSigner(retired, { now: () => Date.parse(RETIRED_AT) });
const cachedLifecycle = rotatable.verificationLifecycle();
const oldOutcome = buildOutcomeReceipt({ decisionReceipt: currentReceipt, tool: "wire.transfer", outcome: "success", ts: BEFORE }, rotatable);
rotatable.rotate(current);
const newOutcome = buildOutcomeReceipt({ decisionReceipt: currentReceipt, tool: "wire.transfer", outcome: "success", ts: AFTER }, rotatable);
const outcomeControl = verifyOutcomeReceipt(newOutcome, { verification: cachedLifecycle });
const outcomeAttack = verifyOutcomeReceipt(oldOutcome, { verification: cachedLifecycle });
probe("verifyOutcomeReceipt", outcomeControl.ok, !outcomeAttack.ok && /retired/i.test(outcomeAttack.reason ?? "") && rotatable.historicalKeyring === undefined, outcomeControl.ok ? "cached handle resolved new key" : outcomeControl.reason, `${outcomeAttack.reason}; historicalKeyring=${typeof rotatable.historicalKeyring}`);

const originalMapIterator = Map.prototype[Symbol.iterator];
let poisonedOutcomeAttack;
Map.prototype[Symbol.iterator] = function* forgedRetirementIterator() {
  yield [retired.kid, { publicKey: retired.publicKey, retiredAt: null }];
};
try {
  poisonedOutcomeAttack = verifyOutcomeReceipt(oldOutcome, { verification: cachedLifecycle });
} finally {
  Map.prototype[Symbol.iterator] = originalMapIterator;
}
probe(
  "verifyOutcomeReceipt Map poison",
  outcomeControl.ok,
  !poisonedOutcomeAttack.ok && /retired/i.test(poisonedOutcomeAttack.reason ?? ""),
  "current key verified before poison",
  poisonedOutcomeAttack.reason,
);

// Narrowing APIs: exact static conversion remains; lifecycle/security-field loss throws. The
// manifest receipt resolver emits lifecycle state and the chain verifier consumes it.
const narrowControl = asStringKeyring(b({ [staticKey.kid]: { publicKey: staticKey.publicKey } }));
let narrowAttack;
try {
  asStringKeyring(b(lifecycleDoc));
  narrowAttack = "accepted";
} catch (error) {
  narrowAttack = String(error?.message ?? error);
}
probe("asStringKeyring", narrowControl[staticKey.kid] === staticKey.publicKey, /refusing|discard|static public key/i.test(narrowAttack), "exact {publicKey} flattened", narrowAttack);

const manifestBase = {
  spec: "noa.key-manifest/0.1",
  tenant: "tenant-p0-14",
  version: 1,
  issuedAt: BEFORE,
  expiresAt: AFTER,
  previousManifestHash: null,
  keys: [],
  sig: { alg: "ed25519", kid: "manifest", value: "x" },
};
const manifestEntry = (kid, publicKey, revokedAt) => JSON.parse(
  `{"kid":${JSON.stringify(kid)},"type":"GATE","roles":[],"publicKey":${JSON.stringify(publicKey)},"validFrom":${JSON.stringify(BEFORE)},"revokedAt":${JSON.stringify(revokedAt)}}`,
);
const manifestCurrent = {
  ...manifestBase,
  keys: [manifestEntry(current.kid, current.publicKey, null)],
};
const manifestRetired = {
  ...manifestBase,
  keys: [manifestEntry(retired.kid, retired.publicKey, RETIRED_AT)],
};
const builtCurrent = verifyChain(b([currentReceipt]), { keyring: b(buildReceiptKeyring(manifestCurrent)) });
const builtRetired = verifyChain(b([retiredReceipt]), { keyring: b(buildReceiptKeyring(manifestRetired)) });
probe("buildReceiptKeyring", builtCurrent.status === "VALID", builtRetired.status === "TAMPERED" && /retired/i.test(builtRetired.reason ?? ""), builtCurrent.status, `${builtRetired.status}: ${builtRetired.reason}`);

// Full evidence pipeline: use its valid EXECUTED bundle and change only the EXTERNAL checkpoint
// trust root from current to retired. This reaches evidence step 17 without narrowing.
const evidenceFixture = readJson(join(ROOT, "packages/evidence/conformance/valid/executed.json"));
const evidenceSchemas = loadEvidenceSchemas();
const checkpointKid = evidenceFixture.bundle.checkpoint.sig.kid;
const checkpointPub = evidenceFixture.checkpointKeyring[checkpointKid];
const evidenceCurrentRing = {
  spec: SIGNING_KEY_LIFECYCLE_SPEC,
  keys: { [checkpointKid]: { publicKey: checkpointPub, retiredAt: null } },
};
const evidenceRetiredRing = {
  spec: SIGNING_KEY_LIFECYCLE_SPEC,
  keys: { [checkpointKid]: { publicKey: checkpointPub, retiredAt: RETIRED_AT } },
};
const evidenceOptions = {
  tenantRoot: b(evidenceFixture.tenantRoot),
  now: evidenceFixture.now,
  maxAgeMs: evidenceFixture.maxAgeHours * 60 * 60 * 1000,
  schemas: evidenceSchemas,
};
const evidenceControl = verifyEvidence(b(evidenceFixture.bundle), { ...evidenceOptions, checkpointKeyring: b(evidenceCurrentRing) });
const evidenceAttack = verifyEvidence(b(evidenceFixture.bundle), { ...evidenceOptions, checkpointKeyring: b(evidenceRetiredRing) });
probe("verifyEvidence", evidenceControl.verdict === "VALID_FULL_CHAIN", evidenceAttack.verdict !== "VALID_FULL_CHAIN" && /retired/i.test(evidenceAttack.reason ?? ""), evidenceControl.verdict, `${evidenceAttack.verdict}: ${evidenceAttack.reason}`);

const evidenceCliControl = evidenceCliVerify(evidenceFixture, evidenceCurrentRing);
const evidenceCliAttack = evidenceCliVerify(evidenceFixture, evidenceRetiredRing);
probe(
  "verify-evidence CLI",
  evidenceCliControl.status === 0 && /VALID_FULL_CHAIN/.test(evidenceCliControl.output),
  evidenceCliAttack.status === 2 && /retired/i.test(evidenceCliAttack.output),
  `exit=${evidenceCliControl.status}`,
  `exit=${evidenceCliAttack.status}: ${evidenceCliAttack.output}`,
);

// Static compatibility controls are explicit and are not derived from lifecycle data.
const staticChain = verifyChain(b([staticReceipt]), { keyring: b(staticMap) });
const staticOutcome = buildOutcomeReceipt({ decisionReceipt: staticReceipt, tool: "wire.transfer", outcome: "success", ts: AFTER }, { kid: staticKey.kid, privateKey: staticKey.privateKey });
const multiStaticOutcome = verifyOutcomeReceipt(staticOutcome, { verification: { ...staticMap, [current.kid]: current.publicKey } });
probe("static map compatibility", staticChain.status === "VALID" && multiStaticOutcome.ok, true, `${staticChain.status}; multi-key outcome=${multiStaticOutcome.ok}`, "structurally carries no lifecycle field; no in-repo lifecycle-to-flat conversion used");

const failed = rows.filter((row) => !row.controlOk || !row.attackRefused);
console.log(`\nP0-14 surface matrix: ${rows.length - failed.length}/${rows.length} PASS`);
if (failed.length > 0) {
  console.log("BROKEN:", failed.map((row) => row.surface).join(", "));
  process.exitCode = 1;
}
