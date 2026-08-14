#!/usr/bin/env node
/**
 * `noa verify-evidence <bundle.json> --tenant-root <f> --checkpoint-keyring <f> [--now <ts>]
 *  [--max-age-hours <n>]`
 *
 * Offline, network-free. Prints the tiered verdict + the ordered per-step audit trail as JSON and
 * exits with a code derived from `(verdict, enrolment, dimensions.settlement)`:
 *   0  VALID_FULL_CHAIN | VALID_SEGMENT_ONLY | VALID_FROM_TRUSTED_ANCHOR  (verified)
 *   2  INVALID                                  (a hard, fail-closed rejection at a named step)
 *   3  INCONCLUSIVE                             (a non-executed outcome with no fresh trusted checkpoint)
 *   4  UNVERIFIED                               (no external trust root / checkpoint keyring supplied, F7a)
 *   5  usage / IO error
 *   6  INCONCLUSIVE                             (the settlement question was asked and not answered)
 *      DEFINED, and NOT REACHABLE from this build — no rule here assigns a settlement value that
 *      produces it. The first rule that can is the one admitting a settlement artifact with no
 *      verified params preimage. Documented now so the number is reserved and a consumer can wire
 *      it; not claimed to fire.
 *   7  internal invariant violation — a (verdict, enrolment, settlement) tuple the rules cannot
 *      produce reached the exit mapper. A statement about THIS VERIFIER, never about the evidence.
 *
 * The JSON result carries two fields beyond the pre-settlement shape, both always present:
 * `enrolment` (was the enrolment question asked at all) and `dimensions.settlement`.
 *
 * The mapping itself lives in `exit-codes.ts`, not here, and it is DERIVED from the dimension rules
 * rather than authored beside them — see that file for why an exit table written separately from the
 * rules that feed it produced a branch nothing could reach.
 */
import { readFileSync } from "node:fs";
import { verifyEvidence } from "./verify-evidence.js";
import { exitCodeFor, USAGE_EXIT_CODE, INTERNAL_INVARIANT_EXIT_CODE, INADMISSIBLE_TUPLE_ERROR_NAME, type EvidenceExitCode } from "./exit-codes.js";
import type { VerificationPurpose } from "./types.js";

function usage(msg?: string): never {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa-verify-evidence <bundle.json> --tenant-root <root.json> --checkpoint-keyring <cp.json> "
      + "[--enrolment-registry <reg.json> ...] [--audience <relying-party-id>] "
      + "[--now <rfc3339>] [--max-age-hours <n>] [--purpose audit|authorize]\n",
  );
  process.exit(USAGE_EXIT_CODE);
}

/**
 * BYTES-IN: the CLI no longer parses anything. A bundle, a trust root and a checkpoint keyring are
 * DOCUMENTS; the verifier takes them as bytes and the kernel's own strict parser is the single
 * place they become data. `JSON.parse` here was a SECOND, weaker parser in front of the strict one
 * — it accepts duplicate keys (last wins), floats, and `__proto__` — so a document the verifier
 * would have rejected could have been silently normalised before it ever got there.
 */
function readBytes(path: string): Uint8Array {
  try {
    return readFileSync(path);
  } catch (e) {
    usage(`cannot read ${path}: ${(e as Error).message}`);
  }
}

function main(argv: string[]): void {
  const args = argv.slice(2);
  let bundlePath: string | undefined;
  let tenantRootPath: string | undefined;
  let checkpointKeyringPath: string | undefined;
  let now: string | undefined;
  let maxAgeHours: number | undefined;
  let purpose: VerificationPurpose | undefined;
  // REPEATABLE, because a relying party legitimately holds several registries — one per tenant it
  // transacts with, and successive windows for the same tenant across a rotation. The flag appends
  // rather than replaces so a second `--enrolment-registry` cannot silently discard the first.
  const enrolmentRegistryPaths: string[] = [];
  let audience: string | undefined;

  /**
   * SINGLETON FLAGS: a MISSING value and a SECOND occurrence are both usage errors.
   *
   * ⚠ WHY THIS IS A HELPER RATHER THAN SIX HAND-WRITTEN BRANCHES, MEASURED. Every singleton used to
   * be `x = args[++i]`, which is wrong twice over:
   *
   *   • A BARE TRAILING FLAG consumed `undefined` and the run CONTINUED. An invocation ending in
   *     `--audience` verified with no reader identity and exited 0 — the operator typed a flag, got a
   *     verdict, and nothing said the flag did nothing.
   *   • A REPEATED FLAG was LAST-WINS, silently. Measured: `--audience hostile --audience good`
   *     exited 6 and `--audience good --audience hostile` exited 4, so whoever appends to the command
   *     line last decides the answer. That is the shape a wrapper script, a CI template or an
   *     injected argument exploits, and it applies to `--tenant-root` exactly as much as to
   *     `--audience`: appending a second trust root would silently replace the first.
   *
   * `--enrolment-registry` is deliberately NOT a singleton — a reader legitimately holds several —
   * and it APPENDS, so a second one can never discard the first. That is the whole distinction: a
   * repeatable flag accumulates, a singleton refuses.
   */
  const seen = new Set<string>();
  const singleton = (flag: string, i: number): string => {
    if (seen.has(flag)) {
      usage(`${flag} was given more than once — it names ONE value, and silently taking the last would let whoever appends to the command line last decide the answer`);
    }
    seen.add(flag);
    const v = args[i];
    if (v === undefined || v.startsWith("--")) {
      usage(`${flag} needs a value${v === undefined ? "" : ` (got the next flag ${v})`}`);
    }
    return v;
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--tenant-root") tenantRootPath = singleton(a, ++i);
    else if (a === "--checkpoint-keyring") checkpointKeyringPath = singleton(a, ++i);
    else if (a === "--enrolment-registry") {
      // REPEATABLE: appends rather than replaces, so a second one cannot discard the first.
      const p = args[++i];
      if (p === undefined || p.startsWith("--")) usage("--enrolment-registry needs a file path");
      enrolmentRegistryPaths.push(p);
    } else if (a === "--audience") audience = singleton(a, ++i);
    else if (a === "--now") now = singleton(a, ++i);
    else if (a === "--max-age-hours") maxAgeHours = Number(singleton(a, ++i));
    else if (a === "--purpose") {
      // Both purposes require authority at verifier-controlled `now`; `authorize` identifies the
      // result as a current authorization decision. Any other value is a usage error here —
      // verifyEvidence ALSO fail-closes on it, but rejecting at the CLI gives the operator a clear
      // message instead of an UNVERIFIED verdict.
      const p = singleton(a, ++i);
      if (p !== "audit" && p !== "authorize") usage(`--purpose must be "audit" or "authorize" (got ${JSON.stringify(p)})`);
      purpose = p;
    } else if (a === "-h" || a === "--help") usage();
    else if (a.startsWith("--")) usage(`unknown flag ${a}`);
    else if (!bundlePath) bundlePath = a;
    else usage(`unexpected argument ${a}`);
  }

  if (!bundlePath) usage("missing <bundle.json>");
  if (!tenantRootPath) usage("missing --tenant-root (F7a: external trust root is REQUIRED)");
  if (!checkpointKeyringPath) usage("missing --checkpoint-keyring (F7a: external checkpoint keyring is REQUIRED)");

  const bundle = readBytes(bundlePath);
  const tenantRoot = readBytes(tenantRootPath);
  const checkpointKeyring = readBytes(checkpointKeyringPath);
  const enrolmentRegistries = enrolmentRegistryPaths.map(readBytes);

  // A REGISTRY WITH NO READER IS A USAGE ERROR HERE, and a fail-closed verdict in the verifier.
  // Both, deliberately: the verifier must never depend on a caller having checked, and an operator
  // who forgot the flag deserves the sentence that says so rather than an UNVERIFIED they will read
  // as a statement about the evidence. NOT the reverse — `--audience` with no registry is fine and
  // means nothing was asked, which is exactly what the result will say.
  if (enrolmentRegistries.length > 0 && (audience === undefined || audience === "")) {
    usage("--enrolment-registry requires --audience (this verifier's own relying-party identity): a registry that does not know who is reading it cannot be scoped");
  }

  const res = verifyEvidence(bundle, {
    tenantRoot,
    checkpointKeyring,
    ...(enrolmentRegistries.length > 0 ? { enrolmentRegistries } : {}),
    ...(audience !== undefined ? { audience } : {}),
    ...(now !== undefined ? { now } : {}),
    ...(maxAgeHours !== undefined && Number.isFinite(maxAgeHours) ? { maxAgeMs: maxAgeHours * 60 * 60 * 1000 } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
  });

  process.stdout.write(JSON.stringify(res, null, 2) + "\n");

  // The mapper REFUSES a tuple the assignment rules cannot produce, rather than answering 0 for it.
  //
  // The catch binds NOTHING. Reading a thrown value's fields runs code the failing party controls,
  // and a handler whose whole job is to report a failure is the worst place to hand over a turn. The
  // consequence is that this block cannot inspect WHAT was thrown — so it does not diagnose. It
  // reports the two things it knows for certain: the mapper did not return, and this is the tuple it
  // was given. `INADMISSIBLE_TUPLE_ERROR_NAME` is named as the expected cause, not asserted as the
  // observed one. Every value printed is one this process built from its own constants; none of it
  // comes from the bundle, so there is nothing here an author of hostile bytes can steer.
  let code: EvidenceExitCode;
  try {
    code = exitCodeFor(res.verdict, res.enrolment, res.dimensions.settlement);
  } catch {
    process.stderr.write(
      `error: the exit mapper refused this result instead of returning a code. Expected cause: ` +
        `${INADMISSIBLE_TUPLE_ERROR_NAME} — (verdict, enrolment, settlement) = ` +
        `(${res.verdict}, ${res.enrolment}, ${res.dimensions.settlement}) is a tuple no assignment rule ` +
        `produces. This is a defect in this verifier, not a statement about the evidence.\n`,
    );
    process.exit(INTERNAL_INVARIANT_EXIT_CODE);
  }
  process.exit(code);
}

main(process.argv);
