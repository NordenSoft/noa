#!/usr/bin/env node
/**
 * DISPATCH-SURFACE ENUMERATION — the C-04 / H-02 class, enforced at the source.
 *
 * THE INVARIANT THIS PROTECTS:
 *
 *     Once an external operation has been INVOKED, no self-report by the executing party may
 *     establish that no side effect occurred. A determinate negative is emitted only where a party
 *     OTHER than the executed one observed the non-dispatch.
 *
 * WHY A SOURCE-LEVEL REGISTRY AND NOT A TEST. C-04 and H-02 were four separate sites implementing
 * the same rule four times, three of them wrongly, and each fix closed one MECHANISM. A behavioural
 * test can only assert the invariant at surfaces someone remembered to write a test for; the next
 * dispatch surface is by definition the one nobody remembered. This enumerates the surfaces from
 * the SOURCE and fails when the set changes — so a new one cannot be added silently, and a
 * dispositioned one cannot vanish without the disposition being revisited.
 *
 * BIDIRECTIONAL RECONCILIATION. Both directions are errors:
 *   • a matched site that is NOT in the registry  → a new dispatch surface bypassed review;
 *   • a registry entry that matches NOTHING       → the registry is describing code that is gone,
 *                                                   which is how a hand-maintained matrix rots into
 *                                                   the poison-catalogue pathology (H-03).
 *
 * Run:  node scripts/lint-dispatch-surfaces.mjs [--warn]
 *       --warn  report findings and exit 0 (the P2 ratchet's warn-first stage)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WARN_ONLY = process.argv.includes("--warn");

/**
 * A dispatch surface is a call that hands control to code the kernel does not own and that may
 * commit a side effect. The patterns are deliberately narrow and literal — a broad regex would
 * match half the repository and train everyone to ignore this gate.
 */
const DISPATCH_PATTERNS = [
  { id: "gate-wrapper-execute", re: /await\s+input\.execute\(\)/ },
  { id: "framework-adapter-fn", re: /result\s*=\s*await\s+fn\(args\)/ },
  { id: "mcp-proxy-calltool", re: /await\s+downstream\.callTool\(/ },
  // ADR-0005 Slice 1 rotted the previous literal (`report(grantId: string, input: unknown`) when the
  // entry point moved to bytes. The gate CAUGHT it as a STALE REGISTRY ENTRY, which is the behaviour
  // this layer exists for; the pattern is re-pinned to the new signature rather than broadened, because
  // a loose regex here would match a renamed method and quietly stop measuring the surface.
  // The trailing `agent: AgentRecord` is what distinguishes the ENGINE's dispatch surface from the two
  // TRANSPORT clients in wrapper.ts. Slice 1 unified their signatures on `Uint8Array`, so a pattern
  // keyed on the body type alone matched all three and the gate reported REGISTRY DRIFT three times —
  // correctly. `agent` is the engine's authorization parameter, so keying on it is narrower AND more
  // meaningful than the pre-Slice-1 `input: unknown`, which distinguished them only by accident.
  { id: "gate-engine-report", re: /\breport\(grantId: string, body: Uint8Array, agent: AgentRecord/ },
];

/**
 * THE REGISTRY. Every dispatch surface in the repository, with the mechanism that discharges the
 * invariant for it. `evidence` names the test that fails if the mechanism is removed — an entry
 * whose evidence is "none" is a disposition, not a control, and must say why in `note`.
 */
const REGISTRY = [
  {
    id: "gate-wrapper-execute",
    file: "packages/gate/src/wrapper.ts",
    disposition: "CLOSED",
    mechanism:
      "the tool's entire self-report is read BEFORE any reducer transition, so the catch block is " +
      "reachable only from DISPATCHED; plus a belt that converts any residual throw into " +
      "ToolOutcomeNotRecorded (executionHappened: true).",
    evidence: "packages/gate/test/no-tool-claim-is-retry-safe.test.ts",
  },
  {
    id: "gate-engine-report",
    file: "packages/gate/src/engine.ts",
    disposition: "CLOSED",
    mechanism:
      "C-04. A determinate FAILED_BEFORE_DISPATCH is signed ONLY when the gate's own grant status " +
      "is UNUSED (the F8a CAS never ran). After RESERVED the same claim is recorded as an " +
      "attributed claim and routed through the existing uncertainty mechanism (202).",
    evidence: "packages/gate/test/grant-atomic.test.ts",
  },
  {
    id: "framework-adapter-fn",
    file: "packages/framework-adapters/src/wrap-tool.mjs",
    disposition: "CLOSED",
    mechanism:
      "H-02a. The terminal outcome is the adapter-core reducer's, not a local `threw ? FAILED : " +
      "EXECUTED`. A post-invocation throw is SIDE_EFFECT_UNCONFIRMED, which has no member in the " +
      "frozen noa.receipt/0.1 verdict enum, so NO terminal receipt is signed and the caller gets " +
      "ToolOutcomeNotRecorded carrying the original value by identity.",
    evidence: "packages/framework-adapters/test/no-premature-executed.test.mjs",
  },
  {
    id: "mcp-proxy-calltool",
    file: "packages/mcp-proxy/src/create-proxy-server.mjs",
    disposition: "MITIGATED",
    mechanism:
      "H-02b. The host-visible McpError carries the reducer's state as machine-readable `data` " +
      "(executionHappened / safeToRetry / sideEffectState / evidenceOutcome).",
    note:
      "NOT fully closed, and deliberately so: the signed noa.mcp.outcome/0.1 receipt still records " +
      'outcome:"error". That field is a record of the PROXY\'s own observation (the forwarded call ' +
      "raised), never the downstream tool's self-report, and noa.mcp.outcome/0.1 is a published " +
      "wire artifact whose enum is not widened to invent an 'unconfirmed' member. The residual risk " +
      "— a consumer reading outcome:\"error\" as proof the side effect did not occur — is a " +
      "documented non-claim, not a mechanical control. See NON-CLAIMS.md.",
    evidence: "packages/mcp-proxy/test/no-retry-safe-after-forward.test.mjs",
  },
];

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === "dist" || e.name === ".git") continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(ts|mjs|js)$/.test(e.name) && !/\.d\.ts$/.test(e.name)) out.push(p);
  }
  return out;
}

const found = [];
for (const file of walk(path.join(ROOT, "packages"))) {
  if (/[/\\](test|dist)[/\\]/.test(file)) continue;
  const src = fs.readFileSync(file, "utf8");
  const lines = src.split("\n");
  for (const { id, re } of DISPATCH_PATTERNS) {
    lines.forEach((line, i) => {
      if (re.test(line)) found.push({ id, file: path.relative(ROOT, file), line: i + 1 });
    });
  }
}

const errors = [];
const registryById = new Map(REGISTRY.map((r) => [r.id, r]));
const seen = new Set();

for (const f of found) {
  seen.add(f.id);
  const entry = registryById.get(f.id);
  if (!entry) {
    errors.push(
      `UNREGISTERED DISPATCH SURFACE  ${f.file}:${f.line} (${f.id})\n` +
        `    A call that hands control to code we do not own must carry an explicit disposition.\n` +
        `    Add it to REGISTRY in scripts/lint-dispatch-surfaces.mjs with its mechanism and evidence.`,
    );
    continue;
  }
  if (entry.file !== f.file) {
    errors.push(`REGISTRY DRIFT  "${f.id}" is registered at ${entry.file} but was found at ${f.file}:${f.line}`);
  }
}

for (const entry of REGISTRY) {
  if (!seen.has(entry.id)) {
    errors.push(
      `STALE REGISTRY ENTRY  "${entry.id}" (${entry.file}) matches nothing in the tree.\n` +
        `    Either the surface was removed (delete the entry) or the pattern rotted (fix it).\n` +
        `    A registry that describes code which no longer exists measures nothing — H-03.`,
    );
  }
  if (!entry.evidence) {
    errors.push(`REGISTRY ENTRY WITHOUT EVIDENCE  "${entry.id}" — a disposition with no failing test is an opinion.`);
  }
}

const closed = REGISTRY.filter((r) => r.disposition === "CLOSED").length;
const mitigated = REGISTRY.filter((r) => r.disposition === "MITIGATED").length;

console.log(`dispatch surfaces: ${found.length} matched, ${REGISTRY.length} registered (${closed} CLOSED, ${mitigated} MITIGATED)`);
for (const r of REGISTRY) console.log(`  ${r.disposition.padEnd(9)} ${r.id.padEnd(24)} ${r.file}`);

if (errors.length) {
  console.error(`\n${errors.length} finding(s):\n`);
  for (const e of errors) console.error(`  ${e}\n`);
  if (!WARN_ONLY) process.exit(1);
  console.error("(--warn: reported, not blocking)");
}
