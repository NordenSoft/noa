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
 *      LIVE. This entry said "DEFINED, and NOT REACHABLE from this build" long after it became
 *      reachable: the rule it named as the first that could produce it — a settlement artifact with
 *      no verifiable params preimage — shipped in slice I2, and 11 conformance fixtures now exit 6
 *      at the process boundary (`test/cli-wire.test.ts` starts a real node and reads the real
 *      status). An integrator reading the shipped source was being told NOT to expect a status this
 *      binary really returns, which is the one direction a reserved-code note must never be wrong in.
 *      It is MANY-TO-ONE by design — an enrolled class with no witness, a self-witnessed one, a
 *      witness missing its coordinates, and an unverifiable-bounds settlement all land here — so the
 *      caller that needs to know WHICH reads `failedStep`, `code` and `reason` from the JSON.
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

  /**
   * A NUMERIC flag's value is VALIDATED HERE, at the moment it is read — never converted and
   * inspected later.
   *
   * ⚠ THE DEFECT THIS REPLACES, MEASURED, AND IT CROSSED THE USAGE/VERDICT BOUNDARY. The value was
   * `Number(...)`, which answers `NaN` for a malformed string and `Infinity` for `"1e400"`. Nothing
   * refused either: the call site further down carried a `Number.isFinite` guard that SILENTLY
   * OMITTED `maxAgeMs` when the conversion failed — restoring the PERMISSIVE 24-hour default. So on
   * one DENIED fixture:
   *
   *     --max-age-hours 0                        -> exit 3   (the freshness rule fires)
   *     --max-age-hours definitely-not-a-number  -> exit 0   (the rule is gone)
   *
   * A mistyped SAFETY option produced a positive verdict. `Number.isFinite` reading as a defence is
   * exactly the shape that hides one: it was true of the guard and false of the outcome, because
   * "the value is not finite" was answered by dropping the option rather than by refusing the run.
   *
   * The raw string is checked, not just the converted number, because `Number("")` is `0` and
   * `Number(" ")` is `0` — an empty value would otherwise become the STRICTEST setting by accident,
   * which is the same class of silent substitution in the other direction.
   */
  const finiteNumber = (flag: string, raw: string): number => {
    const n = Number(raw);
    if (raw.trim() === "" || !Number.isFinite(n)) {
      usage(`${flag} must be a finite number (got ${JSON.stringify(raw)}) — a malformed safety option is refused, never dropped: silently falling back to the default turns a typo into a more permissive run`);
    }
    if (n < 0) {
      usage(`${flag} must not be negative (got ${JSON.stringify(raw)})`);
    }
    return n;
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
    // The ONLY numeric flag this CLI takes. If a second one is ever added it goes through
    // `finiteNumber` as well — that is why the validation is a named helper rather than two lines
    // inlined here, where the next flag would be written beside it and not through it.
    else if (a === "--max-age-hours") maxAgeHours = finiteNumber(a, singleton(a, ++i));
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
    // NO `Number.isFinite` GUARD HERE, deliberately. A non-finite value cannot reach this line —
    // `finiteNumber` refuses it with exit 5 at parse time. The guard that used to stand here read as
    // a defence and acted as a silent DOWNGRADE: it dropped the option and restored the permissive
    // default. A conditional that quietly discards a safety setting is worse than no conditional.
    ...(maxAgeHours !== undefined ? { maxAgeMs: maxAgeHours * 60 * 60 * 1000 } : {}),
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
