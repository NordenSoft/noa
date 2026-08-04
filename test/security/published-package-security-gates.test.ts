import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  cpSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

type Finding = { lint: string; file: string; line: number; msg: string };
type GateResult = {
  exit: number;
  summary: Array<{ id: string; mode: string; count: number | null; budget: number | null }>;
  findings: Finding[];
};

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const SKIP_PARTS = new Set([".git", ".venv", "node_modules", "dist", "target", "scratchpad"]);

function sha256(file: string): string {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function copyFixture(): string {
  const fixture = mkdtempSync(path.join(tmpdir(), "noa-published-gates-"));
  cpSync(ROOT, fixture, {
    recursive: true,
    filter(source) {
      if (source === ROOT) return true;
      const parts = path.relative(ROOT, source).split(path.sep);
      return !parts.some((part) => SKIP_PARTS.has(part));
    },
  });
  symlinkSync(path.join(ROOT, "node_modules"), path.join(fixture, "node_modules"), "dir");
  return fixture;
}

function runGate(fixture: string): GateResult {
  // lint-security-gates calls process.exit immediately after printing. With stdout connected to a
  // pipe, Node may exit before the large finding JSON has flushed; a real file descriptor makes the
  // write synchronous and gives the test the complete document.
  const outputFile = path.join(fixture, ".published-gate-test-output.json");
  const outputFd = openSync(outputFile, "w");
  let run;
  try {
    run = spawnSync(process.execPath, [path.join(fixture, "scripts/lint-security-gates.mjs"), "--json"], {
      cwd: fixture,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      stdio: ["ignore", outputFd, "pipe"],
    });
  } finally {
    closeSync(outputFd);
  }
  // codeql[js/file-system-race] — `outputFile` is a path this test created under its own
  // `mkdtempSync` directory and handed to a child process it just awaited. No other writer exists,
  // and the alternative (a descriptor held across the spawn) would not survive the child's own open.
  // Suppressed with the reason rather than restructured: a race needs a second party, and there is
  // none. If that ever stops being true, this comment is the thing that is wrong.
  const stdout = readFileSync(outputFile, "utf8");
  rmSync(outputFile, { force: true });
  if (run.error) throw run.error;
  assert.equal(run.signal, null, `security gate was terminated by ${run.signal ?? "an unknown signal"}: ${run.stderr}`);
  assert.notEqual(run.status, null, `security gate produced no exit status: ${run.stderr}`);
  let parsed: Omit<GateResult, "exit">;
  try {
    parsed = JSON.parse(stdout) as Omit<GateResult, "exit">;
  } catch (err) {
    assert.fail(
      `security gate did not emit JSON (exit ${run.status}, ${String(err)}, ${stdout.length} chars):\n` +
        `stdout head=${stdout.slice(0, 300)}\nstdout tail=${stdout.slice(-300)}\nstderr=${run.stderr}`,
    );
  }
  return { exit: run.status!, ...parsed! };
}

function hasFinding(result: GateResult, lint: string, file: string, afterLine = -1): boolean {
  return result.findings.some((finding) => finding.lint === lint && finding.file === file && finding.line > afterLine);
}

test("published-package L2/L3/L8 coverage and reconciliation bite through the real gate", () => {
  const fixture = copyFixture();
  try {
    const baseline = runGate(fixture);
    assert.equal(baseline.exit, 0, "the clean fixture must pass before a mutation can prove anything");

    const gateFile = path.join(fixture, "scripts/lint-security-gates.mjs");
    const originalGate = readFileSync(gateFile, "utf8");
    const originalGateHash = sha256(gateFile);
    try {
      const tcbAnchor = "const ADAPTER_CORE_TCB = [\n";
      const reason = '"re-export surface only; declares no rule and makes no runtime decision"';
      let mutantGate = originalGate.replace(tcbAnchor, `${tcbAnchor}  "packages/adapter-core/src/index.mjs",\n`);
      mutantGate = mutantGate.replace(reason, '""');
      assert.notEqual(mutantGate, originalGate, "the classification-table mutation did not apply");
      writeFileSync(gateFile, mutantGate, "utf8");
      const classification = runGate(fixture);
      const indexFindings = classification.findings.filter(
        (finding) => finding.lint === "adapter-core-reconcile" && finding.file === "packages/adapter-core/src/index.mjs",
      );
      assert.equal(classification.exit, 1);
      assert.equal(indexFindings.some((finding) => finding.msg.includes("EMPTY reason")), true, "an empty exclusion reason did not block");
      assert.equal(indexFindings.some((finding) => finding.msg.includes("in BOTH")), true, "classification in both inventories did not block");
    } finally {
      writeFileSync(gateFile, originalGate, "utf8");
    }
    assert.equal(sha256(gateFile), originalGateHash, "the gate script was not restored after classification-table probes");

    for (const subject of [
      {
        label: "adapter-core",
        rel: "packages/adapter-core/src/approval-decision.mjs",
        lints: ["L2-adapter-core", "L3-adapter-core", "L8-adapter-core"],
      },
      {
        label: "mcp-proxy",
        rel: "packages/mcp-proxy/src/outcome-receipt.mjs",
        lints: ["L2-mcp-proxy", "L3-mcp-proxy", "L8-mcp-proxy"],
      },
    ]) {
      const abs = path.join(fixture, subject.rel);
      const original = readFileSync(abs, "utf8");
      const originalHash = sha256(abs);
      try {
        appendFileSync(
          abs,
          `\nconst __${subject.label.replace("-", "_")}L3Probe = {};\n` +
            `function __publishedL2Probe(value) { return value.includes("probe"); }\n` +
            `function __publishedL8Probe(value) { return JSON.stringify(value); }\n`,
          "utf8",
        );
        const mutant = runGate(fixture);
        const plantedLines = readFileSync(abs, "utf8").split("\n");
        const l2Line = plantedLines.findIndex((line) => line.includes("function __publishedL2Probe")) + 1;
        const l3Line = plantedLines.findIndex((line) => line.includes(`const __${subject.label.replace("-", "_")}L3Probe`)) + 1;
        const l8Line = plantedLines.findIndex((line) => line.includes("function __publishedL8Probe")) + 1;
        assert.equal(mutant.exit, 1, `${subject.label}: the planted constructs must exceed the measured ratchets`);
        assert.equal(
          mutant.findings.some(
            (finding) => finding.lint === subject.lints[0] && finding.file === subject.rel && finding.line === l2Line,
          ),
          true,
          `${subject.label}: L2 did not name the planted .includes line`,
        );
        assert.equal(
          mutant.findings.some(
            (finding) => finding.lint === subject.lints[1] && finding.file === subject.rel && finding.line === l3Line,
          ),
          true,
          `${subject.label}: L3 did not name the planted mutable-table line`,
        );
        assert.equal(
          mutant.findings.some(
            (finding) =>
              finding.lint === subject.lints[2] &&
              finding.file === subject.rel &&
              finding.line === l8Line &&
              finding.msg.includes("[live-builtin-member: `JSON.stringify`]"),
          ),
          true,
          `${subject.label}: L8 did not name the planted JSON.stringify line and rule`,
        );
      } finally {
        writeFileSync(abs, original, "utf8");
      }
      assert.equal(sha256(abs), originalHash, `${subject.label}: the classified source was not restored byte-for-byte`);
    }

    const newAdapterRel = "packages/adapter-core/src/__unclassified_gate_test.mjs";
    const newMcpRel = "packages/mcp-proxy/src/__unclassified_gate_test.mjs";
    const newAdapter = path.join(fixture, newAdapterRel);
    const newMcp = path.join(fixture, newMcpRel);
    try {
      writeFileSync(newAdapter, "export {};\n", "utf8");
      writeFileSync(newMcp, "export {};\n", "utf8");
      const unclassified = runGate(fixture);
      assert.equal(unclassified.exit, 1);
      assert.equal(hasFinding(unclassified, "adapter-core-reconcile", newAdapterRel), true);
      assert.equal(hasFinding(unclassified, "mcp-proxy-reconcile", newMcpRel), true);
    } finally {
      rmSync(newAdapter, { force: true });
      rmSync(newMcp, { force: true });
    }

    const moves = [
      ["adapter-core-reconcile", "packages/adapter-core/src/approval-decision.mjs", "packages/adapter-core/src/approval-decision.__moved_test.mjs"],
      ["mcp-proxy-reconcile", "packages/mcp-proxy/src/outcome-receipt.mjs", "packages/mcp-proxy/src/outcome-receipt.__moved_test.mjs"],
    ] as const;
    const hashes = moves.map(([, from]) => sha256(path.join(fixture, from)));
    try {
      for (const [, from, to] of moves) renameSync(path.join(fixture, from), path.join(fixture, to));
      const moved = runGate(fixture);
      assert.equal(moved.exit, 1);
      for (const [lint, from, to] of moves) {
        assert.equal(hasFinding(moved, lint, to), true, `${to}: relocated file was not reported as unclassified`);
        assert.equal(moved.findings.some((finding) => finding.lint === lint && finding.file === from && finding.msg.startsWith("a file classified")), true, `${from}: stale classified path was not reported`);
      }
    } finally {
      for (const [, from, to] of moves) renameSync(path.join(fixture, to), path.join(fixture, from));
    }
    for (let i = 0; i < moves.length; i++) {
      assert.equal(sha256(path.join(fixture, moves[i]![1])), hashes[i], `${moves[i]![1]} was not restored after relocation`);
    }
  } finally {
    // The target is the unique mkdtemp directory created above, never a caller-supplied path.
    rmSync(fixture, { recursive: true, force: true });
  }
});
