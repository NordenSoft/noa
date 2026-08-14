#!/usr/bin/env node
/**
 * `noa verify-evidence <bundle.json> --tenant-root <f> --checkpoint-keyring <f> [--now <ts>]
 *  [--max-age-hours <n>]`
 *
 * Offline, network-free. Prints the tiered verdict + the ordered per-step audit trail as JSON and
 * exits with a code derived from `(verdict, dimensions.settlement)`:
 *   0  VALID_FULL_CHAIN | VALID_SEGMENT_ONLY   (verified — full or segment-only)
 *   2  INVALID                                  (a hard, fail-closed rejection at a named step)
 *   3  INCONCLUSIVE                             (a non-executed outcome with no fresh trusted checkpoint)
 *   4  UNVERIFIED                               (no external trust root / checkpoint keyring supplied, F7a)
 *   5  usage / IO error
 *   6  INCONCLUSIVE                             (the settlement question was asked and not answered)
 *
 * The mapping itself lives in `exit-codes.ts`, not here, and it is DERIVED from the dimension rules
 * rather than authored beside them — see that file for why an exit table written separately from the
 * rules that feed it produced a branch nothing could reach.
 */
import { readFileSync } from "node:fs";
import { verifyEvidence } from "./verify-evidence.js";
import { exitCodeFor, USAGE_EXIT_CODE } from "./exit-codes.js";
import type { VerificationPurpose } from "./types.js";

function usage(msg?: string): never {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa-verify-evidence <bundle.json> --tenant-root <root.json> --checkpoint-keyring <cp.json> [--now <rfc3339>] [--max-age-hours <n>] [--purpose audit|authorize]\n",
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

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--tenant-root") tenantRootPath = args[++i];
    else if (a === "--checkpoint-keyring") checkpointKeyringPath = args[++i];
    else if (a === "--now") now = args[++i];
    else if (a === "--max-age-hours") maxAgeHours = Number(args[++i]);
    else if (a === "--purpose") {
      // Both purposes require authority at verifier-controlled `now`; `authorize` identifies the
      // result as a current authorization decision. Any other value is a usage error here —
      // verifyEvidence ALSO fail-closes on it, but rejecting at the CLI gives the operator a clear
      // message instead of an UNVERIFIED verdict.
      const p = args[++i];
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

  const res = verifyEvidence(bundle, {
    tenantRoot,
    checkpointKeyring,
    ...(now !== undefined ? { now } : {}),
    ...(maxAgeHours !== undefined && Number.isFinite(maxAgeHours) ? { maxAgeMs: maxAgeHours * 60 * 60 * 1000 } : {}),
    ...(purpose !== undefined ? { purpose } : {}),
  });

  process.stdout.write(JSON.stringify(res, null, 2) + "\n");

  process.exit(exitCodeFor(res.verdict, res.dimensions.settlement));
}

main(process.argv);
