/**
 * THE VERDICT RECORD — a gate that inspected nothing may not report GREEN.
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────────────────────────────────
 * Round 8 measured four separate gates reporting success while examining zero subjects:
 *
 *   R8-23  `lint-security-gates.mjs:515` reads `ci.yml` as `existsSync(…) ? read(…) : ""`, and all
 *          seven CI assertions are `if (ci && …)`. DELETE `ci.yml` and L7 reports `BLOCKING 0`,
 *          exit 0. The gate that checks CI is green precisely when there is no CI.
 *   R8-25  `run-r7-exploits.mjs` derived a disposition from the EXIT CODE and used the printed
 *          `RESULT:` line only as a liveness token, never comparing the two.
 *   R8-26  `lint-control-knockout.mjs` calls any non-green run KILLED, with no baseline. Six of its
 *          34 entries target a suite whose baseline is already red, so they report KILLED for any
 *          mutation — including a semantic no-op.
 *   R8-36  the composite `security-gates` depends on build artifacts; on a clean tracked tree it
 *          exits 2 at step one, so "security-gates exit 0" described a pre-built worktree.
 *
 * Four instances, one shape: **absence of findings and absence of checking produce the same output.**
 * This repository has now rediscovered that shape at six layers, and `run-r7-exploits.mjs:26-41`
 * already wrote the principle down for its own corpus — *"a verdict is now earned, not inferred:
 * exit codes are evidence of what a process decided; they are not evidence that it ran."*
 * It was never generalised. This module is that generalisation.
 *
 * ── THE RULE ────────────────────────────────────────────────────────────────────────────────────
 * A gate emits a VERDICT RECORD naming what it examined. `summarize()` refuses a green summary when
 * any gate reports `examined === 0` for a subject class it claims to cover, or declares an
 * anti-vacuity control that was never observed to fail. Green becomes a statement about work done,
 * not about findings absent.
 *
 * NOT A REPLACEMENT for the gates' own exit codes — it is a second, independent question. A gate can
 * legitimately find nothing; it cannot legitimately examine nothing while claiming to cover
 * something.
 *
 * ── ZERO IS SOMETIMES HONEST ────────────────────────────────────────────────────────────────────
 * A subject class that is genuinely empty (a package with no TypeScript, an exemption table with no
 * entries) is not a defect. So `examined: 0` is permitted ONLY with an explicit
 * `emptyReason` — a sentence saying why zero is the true count. An unexplained zero is a finding.
 * That is the same discipline the relay's exemption table already applies to blank reasons.
 */

/** @typedef {{ gate: string, subject: string, examined: number, emptyReason?: string, findings?: number, antiVacuity?: { control: string, observedRed: boolean } }} VerdictRecord */

const RECORDS = [];

/**
 * Record what a gate examined. Call once per SUBJECT CLASS, not once per gate — a gate that walks
 * files and also checks a config emits two records, so a zero in either is visible.
 *
 * @param {VerdictRecord} rec
 */
export function emit(rec) {
  if (typeof rec !== "object" || rec === null) throw new TypeError("verdict.emit: record must be an object");
  for (const k of ["gate", "subject"]) {
    if (typeof rec[k] !== "string" || rec[k].trim() === "") {
      throw new TypeError(`verdict.emit: "${k}" must be a non-empty string`);
    }
  }
  if (!Number.isInteger(rec.examined) || rec.examined < 0) {
    throw new TypeError(`verdict.emit: "examined" must be a non-negative integer (${rec.gate}/${rec.subject})`);
  }
  RECORDS[RECORDS.length] = rec;
  return rec;
}

/** Every record emitted so far, in order. */
export function records() {
  return RECORDS.slice();
}

/** Test-only: forget everything emitted. Never called by a gate. */
export function reset() {
  RECORDS.length = 0;
}

/**
 * Decide whether the emitted records permit a GREEN summary.
 *
 * @returns {{ ok: boolean, findings: string[], examinedTotal: number }}
 */
export function summarize(recs = RECORDS) {
  const findings = [];
  let examinedTotal = 0;

  if (recs.length === 0) {
    findings[findings.length] =
      "NO GATE EMITTED A VERDICT RECORD. A run that recorded nothing cannot be green — it is " +
      "indistinguishable from a run in which no gate executed.";
    return { ok: false, findings, examinedTotal: 0 };
  }

  for (const r of recs) {
    examinedTotal += r.examined;
    const id = `${r.gate}/${r.subject}`;

    if (r.examined === 0) {
      const why = typeof r.emptyReason === "string" ? r.emptyReason.trim() : "";
      if (why === "") {
        findings[findings.length] =
          `${id} examined ZERO subjects and gave no reason. Either the subject class is genuinely ` +
          `empty — say so in \`emptyReason\` — or this gate reported success without looking at ` +
          `anything, which is the R8-23 shape.`;
      }
    }

    // A declared control that was never observed failing is a claim, not a control.
    if (r.antiVacuity !== undefined) {
      if (typeof r.antiVacuity !== "object" || r.antiVacuity === null || typeof r.antiVacuity.control !== "string") {
        findings[findings.length] = `${id} declared an antiVacuity block with no \`control\` string.`;
      } else if (r.antiVacuity.observedRed !== true) {
        findings[findings.length] =
          `${id} declares the anti-vacuity control "${r.antiVacuity.control}" but did not observe it ` +
          `fail. A control nobody has seen fail is not known to be a control.`;
      }
    }
  }

  return { ok: findings.length === 0, findings, examinedTotal };
}

/**
 * Print the summary and return the exit code a runner should use. Deliberately returns rather than
 * calling `process.exit`, so a caller can combine it with its own findings.
 */
export function report(recs = RECORDS, { json = false } = {}) {
  const s = summarize(recs);
  if (json) {
    console.log(JSON.stringify({ ok: s.ok, examinedTotal: s.examinedTotal, findings: s.findings, records: recs }, null, 2));
    return s.ok ? 0 : 1;
  }
  console.log(`\nverdict records: ${recs.length} · subjects examined: ${s.examinedTotal}`);
  for (const r of recs) {
    const zero = r.examined === 0 ? (r.emptyReason ? "  (empty, explained)" : "  ← ZERO, UNEXPLAINED") : "";
    console.log(`  ${String(r.examined).padStart(6)}  ${r.gate}/${r.subject}${zero}`);
  }
  if (!s.ok) {
    console.error(`\n${s.findings.length} verdict finding(s) — a green summary is REFUSED:\n`);
    for (const f of s.findings) console.error(`  ${f}\n`);
  }
  return s.ok ? 0 : 1;
}
