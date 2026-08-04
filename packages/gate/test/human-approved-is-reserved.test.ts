/**
 * `HUMAN_APPROVED` IS RESERVED, AND NOTHING MAY EMIT IT UNTIL THE THIRD LEG HAS A SOURCE.
 *
 * ─── THE RULE IS THE OWNER'S, NOT AN ADR'S ──────────────────────────────────────────────────────
 *
 * `NON-CLAIMS.md` (amended by the owner 2026-07-29, with the surrounding consequences marked
 * owner-ratified and binding):
 *
 *     approval_intent_digest == grant_intent_digest == execution_intent_digest
 *     No component may claim `HUMAN_APPROVED` unless that equality has been independently
 *     established.
 *
 * TWO of the three legs are established at the gate: the boundary derives the display, the action
 * binding holds, the approver's identity and timing window are checked, the decision is bound to
 * THIS hold, and the grant is taken from `hold.action.paramsHash`. The THIRD — that the target ran
 * those params — has no admissible source. Stages 9-10 accept no input a gate can verify, `NC-6.8`
 * declined credential custody, and no cooperating third party exists.
 *
 * So until an execution witness exists, emitting `HUMAN_APPROVED` is claiming an equality nobody
 * established. The ENFORCED path now emits `HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND`, which says
 * less and is true.
 *
 * ─── WHY A SEPARATE FILE RATHER THAN AN ASSERTION INSIDE THE FLOW TESTS ────────────────────────
 *
 * The flow tests assert what the honest path PRODUCES. This one asserts what NOTHING may produce,
 * which is a different question and survives a rewrite of the flow. The token is a single string:
 * the cheapest possible regression is someone "restoring" it in a merge, and a test keyed to one
 * scenario would not see it. This scans the SOURCE — every emission site in both packages at once.
 *
 * ⚠ It is a source scan, and that limit is stated rather than implied: it proves no code SAYS the
 * token, not that no code could compute it. A computed `"HUMAN_" + "APPROVED"` would pass. That is
 * accepted — the realistic regression is a literal, and a lint claiming more would be the kind of
 * overclaim this repository audits for.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
/**
 * Walk UP to the repo root instead of counting `..`.
 *
 * This file executes from `dist/test`, not from `test`, so any fixed depth is wrong in one of the
 * two locations — and it fails as ENOENT on a path with `packages/packages` in it, which reads
 * like a broken repo rather than a broken test. Searching for the marker cannot be wrong in
 * either.
 */
function repoRoot(from: string): string {
  let dir = from;
  for (let i = 0; i < 10; i++) {
    if (statSyncSafe(join(dir, "packages"))) return dir;
    dir = dirname(dir);
  }
  throw new Error(`could not find the repo root above ${from}`);
}
function statSyncSafe(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}
const REPO = repoRoot(HERE);

/** Every `.ts` under a package's `src/`, walked by index (no `for…of` on a decision path). */
function sources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    if (statSync(abs).isDirectory()) sources(abs, out);
    else if (entry.endsWith(".ts")) out[out.length] = abs;
  }
  return out;
}

/** Lines that ASSIGN the token — a type union member or a doc comment is not an emission. */
function emissionLines(file: string): string[] {
  const hits: string[] = [];
  const lines = readFileSync(file, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const trimmed = line.trim();
    if (trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("|")) continue;
    // An assignment or an object property carrying the literal.
    if (/"HUMAN_APPROVED"/.test(line) && /(reasonCode\s*[:=])|(=\s*"HUMAN_APPROVED")/.test(line)) {
      hits[hits.length] = `${file.slice(REPO.length + 1)}:${i + 1}  ${trimmed.slice(0, 100)}`;
    }
  }
  return hits;
}

test("CONTROL — the scanner CAN see an emission (it is not green by construction)", () => {
  // A scanner that matched nothing would pass the real test forever. This proves it fires on the
  // exact shape it is meant to catch, using a synthetic line rather than a planted file.
  const probe = ["const x = {", '  reasonCode: "HUMAN_APPROVED",', "};"].join("\n");
  const tmp = join(HERE, "__probe-human-approved.ts");
  writeFileSync(tmp, probe);
  try {
    assert.equal(emissionLines(tmp).length, 1,
      "the scanner cannot see a plain `reasonCode: \"HUMAN_APPROVED\"` — every assertion below is vacuous");
  } finally {
    rmSync(tmp, { force: true });
  }
});

test("HUMAN_APPROVED is emitted by NOTHING in gate/src or relay/src", () => {
  const files = [
    ...sources(join(REPO, "packages", "gate", "src")),
    ...sources(join(REPO, "packages", "relay", "src")),
  ];
  assert.ok(files.length > 10, `fixture: only ${files.length} sources found — the walk is broken`);

  const hits: string[] = [];
  for (let i = 0; i < files.length; i++) {
    const found = emissionLines(files[i] as string);
    for (let k = 0; k < found.length; k++) hits[hits.length] = found[k] as string;
  }

  assert.deepEqual(hits, [],
    "something emits `HUMAN_APPROVED`, and the owner's invariant forbids it while the execution " +
      "intent digest has no source (NON-CLAIMS.md, amended 2026-07-29). If an execution witness now " +
      "EXISTS, this test is the thing to change — and changing it means saying where the third leg " +
      "comes from. Sites:\n  " + hits.join("\n  "));
});

test("the token stays in the union — it is reserved, not deleted", () => {
  // Deleting it would lose the destination: when an execution witness exists, the ENFORCED path
  // moves back to this token. A union without it would make that a redesign rather than one line.
  const types = readFileSync(join(REPO, "packages", "gate", "src", "types.ts"), "utf8");
  assert.ok(/\|\s*"HUMAN_APPROVED"/.test(types), "the reserved token was removed from the union");
  assert.ok(/\|\s*"HUMAN_APPROVED_INTENT_NOT_EXECUTION_BOUND"/.test(types),
    "the honest token is missing from the union");
});
