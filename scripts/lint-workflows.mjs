#!/usr/bin/env node
/**
 * Structural lint for `.github/workflows/*.yml` — the check that a generic YAML parser cannot make.
 *
 * ─── WHY THIS EXISTS, MEASURED ───────────────────────────────────────────────────────────────────
 *
 * On 2026-08-03 a step was inserted BETWEEN another step's `name:` and its `run:`:
 *
 *     - name: approval-artifacts tests            <- left with NO `run:` at all
 *     - name: Install adapter-core FIRST
 *       run: cd packages/adapter-core && npm ci
 *
 *       run: cd packages/approval-artifacts …     <- orphaned; a SECOND `run:` in the same mapping
 *
 * GitHub refused the whole workflow: `startup_failure`, **0 jobs**, on every push, and it also
 * suppressed the `pull_request` runs — so the required checks on the open PR stopped being produced
 * at all. Nine CI runs were consumed before anyone looked at the job COUNT rather than the verdict.
 *
 * The reason it was not caught locally is the point of this file: **`yaml.safe_load` reported the
 * file as VALID.** Duplicate mapping keys are legal YAML — last one wins — so a parser answers
 * "well-formed?" when the question was "is this a valid workflow?". A green from the wrong question
 * is indistinguishable from a green.
 *
 * That is the third broken instrument in a single day on this branch: a `sed` pipe that replaced a
 * gate's exit code with its own, a full-string grep that structurally could not see an elided hash,
 * and this. **Absence of a finding and absence of checking are the same value in code and opposite
 * facts in reality.**
 *
 * ─── WHAT IT CHECKS ──────────────────────────────────────────────────────────────────────────────
 *
 *   1. No DUPLICATE KEY inside one step mapping — the defect above, and invisible to a YAML parser.
 *   2. Every step has EXACTLY ONE of `run:` / `uses:` — never zero (the orphaned `name:`), never both.
 *   3. Every job declares `runs-on` and `steps`.
 *
 * Deliberately line-structural rather than parser-based: the failure is precisely that the parser
 * NORMALISES the defect away. A checker built on the tool that could not see it would inherit the
 * blindness. Multi-line `run: |` bodies are safe — their content is indented deeper than the step's
 * key column, and only the key column is inspected.
 *
 * Exit 1 on any finding. Exit 1 ALSO when no workflow file is found: "the check could not run" and
 * "the check passed" must never share an exit code.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const DIR = ".github/workflows";
const findings = [];

let files;
try {
  files = readdirSync(DIR).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));
} catch (e) {
  console.error(`lint-workflows: cannot read ${DIR}: ${e.message}`);
  process.exit(1);
}
if (files.length === 0) {
  console.error(`lint-workflows: no workflow files in ${DIR} — refusing to report success`);
  process.exit(1);
}

const indentOf = (line) => line.length - line.trimStart().length;
const isBlank = (line) => line.trim() === "" || line.trim().startsWith("#");

for (const file of files) {
  const path = join(DIR, file);
  const lines = readFileSync(path, "utf8").split("\n");

  // ── steps ──────────────────────────────────────────────────────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)-\s+(\w[\w-]*):/.exec(lines[i]);
    if (!m) continue;
    const dashIndent = m[1].length;
    const keyCol = dashIndent + 2;
    // Only sequence items that look like STEPS. A step names at least one of these.
    const first = m[2];
    if (!["name", "uses", "run", "id", "if"].includes(first)) continue;

    const keys = [{ key: first, line: i + 1 }];
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j];
      if (isBlank(l)) continue;
      const ind = indentOf(l);
      if (ind <= dashIndent) break;          // left the sequence item
      if (ind !== keyCol) continue;          // inside a block scalar or a nested mapping
      const km = /^\s*([\w-]+):/.exec(l);
      if (km) keys.push({ key: km[1], line: j + 1 });
    }

    const seen = new Map();
    for (const { key, line } of keys) {
      if (seen.has(key)) {
        findings.push(
          `${path}:${line}  DUPLICATE KEY \`${key}\` in one step (first seen at :${seen.get(key)}). ` +
            `Legal YAML — last one wins — so a parser will NOT report this, and GitHub will refuse ` +
            `the whole workflow with 0 jobs.`,
        );
      } else seen.set(key, line);
    }

    const hasRun = seen.has("run"), hasUses = seen.has("uses");
    if (!hasRun && !hasUses) {
      findings.push(
        `${path}:${i + 1}  step has NEITHER \`run\` nor \`uses\`. Usually a new step was inserted ` +
          `between this one's \`name:\` and its body.`,
      );
    } else if (hasRun && hasUses) {
      findings.push(`${path}:${i + 1}  step has BOTH \`run\` and \`uses\`; GitHub accepts only one.`);
    }
  }

  // ── jobs ───────────────────────────────────────────────────────────────────────────────────────
  const jobsAt = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  if (jobsAt === -1) {
    findings.push(`${path}:1  no top-level \`jobs:\` block.`);
    continue;
  }
  for (let i = jobsAt + 1; i < lines.length; i++) {
    const jm = /^ {2}([\w-]+):\s*$/.exec(lines[i]);
    if (!jm) continue;
    let hasRunsOn = false, hasSteps = false, usesReusable = false;
    for (let j = i + 1; j < lines.length; j++) {
      if (/^ {2}[\w-]+:\s*$/.test(lines[j]) || /^\S/.test(lines[j])) break;
      if (/^ {4}runs-on:/.test(lines[j])) hasRunsOn = true;
      if (/^ {4}steps:/.test(lines[j])) hasSteps = true;
      if (/^ {4}uses:/.test(lines[j])) usesReusable = true;
    }
    if (usesReusable) continue; // a reusable-workflow call declares neither
    if (!hasRunsOn) findings.push(`${path}:${i + 1}  job \`${jm[1]}\` has no \`runs-on\`.`);
    if (!hasSteps) findings.push(`${path}:${i + 1}  job \`${jm[1]}\` has no \`steps\`.`);
  }
}

if (findings.length > 0) {
  console.error(`\nlint-workflows: ${findings.length} finding(s) — GitHub would refuse these files.\n`);
  for (const f of findings) console.error(`  ${f}`);
  console.error("");
  process.exit(1);
}
console.error(`lint-workflows: ${files.length} workflow file(s) structurally valid.`);
