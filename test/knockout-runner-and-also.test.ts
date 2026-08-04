import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

type Suite = [string, string, string[]];
type Entry = {
  id: string;
  control: string;
  file: string;
  find: string;
  replace: string;
  also?: Array<{ find: string; replace: string }>;
  andAlso?: string;
  kind: "tests";
  suite: Suite;
};
type Observation = {
  exit: number | null;
  failing: Set<string>;
  findings: number;
  ms: number;
  timedOut: boolean;
  out: string;
};
type Evidence = {
  verdict: string;
  detail?: string;
  andAlso?: string;
  hashBefore: Record<string, string>;
  hashAfter: Record<string, string>;
  restored: boolean;
};

// This test is compiled to dist/test. Resolve back to the source runner so `npm test` exercises the
// exact instrument used by lint-control-knockout, not a copied fixture or stale build artefact.
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const runner = await import(pathToFileURL(path.join(repoRoot, "scripts/lib/knockout-runner.mjs")).href) as {
  runKnockout: (options: {
    root: string;
    entry: Entry;
    registry: Entry[];
    baseline: Observation;
    timeoutMs: number;
  }) => Evidence;
  observeSuite: (root: string, suite: Suite, timeoutMs?: number) => Observation;
  validateKnockoutRegistry: (registry: object[]) => Map<string, object>;
  VERDICT: Record<string, string>;
};
const { runKnockout, observeSuite, validateKnockoutRegistry, VERDICT } = runner;

const PRIMARY = "const primary = REAL_PRIMARY;";
const COMPANION = "const companion = REAL_COMPANION;";
const EXTRA = "const extra = REAL_EXTRA;";

function fixture(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ko-and-also-"));
  fs.writeFileSync(path.join(root, "primary.js"), `${PRIMARY}\n`);
  fs.writeFileSync(path.join(root, "companion.js"), `${COMPANION}\n${EXTRA}\n`);
  fs.writeFileSync(path.join(root, "suite.mjs"), [
    'import fs from "node:fs";',
    'const primary = fs.readFileSync(new URL("./primary.js", import.meta.url), "utf8");',
    'const companion = fs.readFileSync(new URL("./companion.js", import.meta.url), "utf8");',
    'const broken = !primary.includes("REAL_PRIMARY") && !companion.includes("REAL_COMPANION") && !companion.includes("REAL_EXTRA");',
    'if (broken) console.log("✖ paired guard is load-bearing (1.0ms)");',
    'console.log("ℹ tests 1");',
    'console.log("ℹ pass " + (broken ? 0 : 1));',
    'console.log("ℹ fail " + (broken ? 1 : 0));',
    'process.exit(broken ? 1 : 0);',
  ].join("\n"));
  return root;
}

function registry(): [Entry, Entry] {
  const suite: Suite = [".", process.execPath, ["suite.mjs"]];
  return [
    {
      id: "primary",
      control: "primary half",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      andAlso: "companion",
      kind: "tests",
      suite,
    },
    {
      id: "companion",
      control: "companion half",
      file: "companion.js",
      find: COMPANION,
      replace: "const companion = false;",
      also: [{ find: EXTRA, replace: "const extra = false;" }],
      kind: "tests",
      suite,
    },
  ];
}

function baseline(root: string, suite: Suite): Observation {
  return observeSuite(root, suite, 60_000);
}

test("an unknown registry key errors loudly with the entry id and key", () => {
  const [entry] = registry();
  assert.throws(
    () => validateKnockoutRegistry([{ ...entry, andAlso: undefined, silentlyIgnored: true }]),
    /invalid knockout entry "primary": unknown key "silentlyIgnored"/,
  );
});

test("a missing andAlso id errors loudly before a suite can run", () => {
  const [entry] = registry();
  assert.throws(
    () => validateKnockoutRegistry([{ ...entry, andAlso: "does-not-exist" }]),
    /invalid knockout entry "primary": andAlso references missing entry id "does-not-exist"/,
  );
});

test("required values and nested also edits use closed schemas too", () => {
  const [entry, companion] = registry();
  assert.throws(
    () => validateKnockoutRegistry([{ ...entry, replace: undefined }]),
    /invalid knockout entry "primary": replace must be a string/,
  );
  assert.throws(
    () => validateKnockoutRegistry([
      { ...entry, andAlso: undefined },
      { ...companion, also: [{ find: EXTRA, replace: "const extra = false;", typo: true }] },
    ]),
    /invalid knockout entry "companion": unknown also\[0\] key "typo"/,
  );
});

test("andAlso applies both mutations and hash-verifies restoration of both files", () => {
  const root = fixture();
  try {
    const entries = registry();
    const ev = runKnockout({
      root,
      entry: entries[0],
      registry: entries,
      baseline: baseline(root, entries[0].suite),
      timeoutMs: 60_000,
    });

    assert.equal(ev.verdict, VERDICT.DETECTOR_TRIGGERED, ev.detail);
    assert.equal(ev.andAlso, "companion");
    assert.deepEqual(Object.keys(ev.hashBefore).sort(), ["companion.js", "primary.js"]);
    assert.deepEqual(Object.keys(ev.hashAfter).sort(), ["companion.js", "primary.js"]);
    assert.equal(ev.restored, true);
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), `${PRIMARY}\n`);
    assert.equal(
      fs.readFileSync(path.join(root, "companion.js"), "utf8"),
      `${COMPANION}\n${EXTRA}\n`,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the primary mutation alone stays green in the same fixture", () => {
  const root = fixture();
  try {
    const [entry] = registry();
    const lone = { ...entry };
    delete lone.andAlso;
    const ev = runKnockout({
      root,
      entry: lone,
      registry: [lone],
      baseline: baseline(root, lone.suite),
      timeoutMs: 60_000,
    });
    assert.equal(ev.verdict, VERDICT.DETECTOR_DID_NOT_TRIGGER, ev.detail);
    assert.equal(ev.restored, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("same-file paired mutations that cancel to pristine never run as a mutant", () => {
  const root = fixture();
  try {
    const suite: Suite = [".", process.execPath, ["suite.mjs"]];
    const first: Entry = {
      id: "first",
      control: "first half",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = INTERMEDIATE;",
      andAlso: "second",
      kind: "tests",
      suite,
    };
    const second: Entry = {
      id: "second",
      control: "second half",
      file: "primary.js",
      find: "const primary = INTERMEDIATE;",
      replace: PRIMARY,
      kind: "tests",
      suite,
    };
    const ev = runKnockout({
      root,
      entry: first,
      registry: [first, second],
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
    });
    assert.equal(ev.verdict, VERDICT.MUTATION_NOT_APPLIED, ev.detail);
    assert.match(ev.detail ?? "", /pair cancelled itself/);
    assert.equal(ev.restored, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("restoration refuses to erase an unexpected edit made while the suite runs", () => {
  const root = fixture();
  try {
    fs.writeFileSync(path.join(root, "concurrent-suite.mjs"), [
      'import fs from "node:fs";',
      'const target = new URL("./primary.js", import.meta.url);',
      'const source = fs.readFileSync(target, "utf8");',
      'if (source.includes("const primary = false;")) fs.writeFileSync(target, "concurrent edit\\n");',
      'console.log("ℹ tests 1");',
      'console.log("ℹ pass 1");',
      'console.log("ℹ fail 0");',
    ].join("\n"));
    const suite: Suite = [".", process.execPath, ["concurrent-suite.mjs"]];
    const entry: Entry = {
      id: "concurrent",
      control: "concurrent edit preservation",
      file: "primary.js",
      find: PRIMARY,
      replace: "const primary = false;",
      kind: "tests",
      suite,
    };
    const ev = runKnockout({
      root,
      entry,
      registry: [entry],
      baseline: baseline(root, suite),
      timeoutMs: 60_000,
    });
    assert.equal(ev.verdict, VERDICT.RESTORATION_FAILED, ev.detail);
    assert.equal(ev.restored, false);
    assert.match(ev.detail ?? "", /refusing to overwrite a concurrent edit/);
    assert.equal(fs.readFileSync(path.join(root, "primary.js"), "utf8"), "concurrent edit\n");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
