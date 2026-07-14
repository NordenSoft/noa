#!/usr/bin/env node
/**
 * `noa verify-evidence <bundle.json> --tenant-root <f> --checkpoint-keyring <f> [--now <ts>]
 *  [--max-age-hours <n>]`
 *
 * Offline, network-free. Prints the tiered verdict + the ordered per-step audit trail as JSON and
 * exits with a verdict-specific code:
 *   0  VALID_FULL_CHAIN | VALID_SEGMENT_ONLY   (verified — full or segment-only)
 *   2  INVALID                                  (a hard, fail-closed rejection at a named step)
 *   3  INCONCLUSIVE                             (a non-executed outcome with no fresh trusted checkpoint)
 *   4  UNVERIFIED                               (no external trust root / checkpoint keyring supplied, F7a)
 *   5  usage / IO error
 */
import { readFileSync } from "node:fs";
import { verifyEvidence } from "./verify-evidence.js";

function usage(msg?: string): never {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa-verify-evidence <bundle.json> --tenant-root <root.json> --checkpoint-keyring <cp.json> [--now <rfc3339>] [--max-age-hours <n>]\n",
  );
  process.exit(5);
}

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    usage(`cannot read/parse ${path}: ${(e as Error).message}`);
  }
}

function main(argv: string[]): void {
  const args = argv.slice(2);
  let bundlePath: string | undefined;
  let tenantRootPath: string | undefined;
  let checkpointKeyringPath: string | undefined;
  let now: string | undefined;
  let maxAgeHours: number | undefined;

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--tenant-root") tenantRootPath = args[++i];
    else if (a === "--checkpoint-keyring") checkpointKeyringPath = args[++i];
    else if (a === "--now") now = args[++i];
    else if (a === "--max-age-hours") maxAgeHours = Number(args[++i]);
    else if (a === "-h" || a === "--help") usage();
    else if (a.startsWith("--")) usage(`unknown flag ${a}`);
    else if (!bundlePath) bundlePath = a;
    else usage(`unexpected argument ${a}`);
  }

  if (!bundlePath) usage("missing <bundle.json>");
  if (!tenantRootPath) usage("missing --tenant-root (F7a: external trust root is REQUIRED)");
  if (!checkpointKeyringPath) usage("missing --checkpoint-keyring (F7a: external checkpoint keyring is REQUIRED)");

  const bundle = readJson(bundlePath);
  const tenantRoot = readJson(tenantRootPath) as Record<string, unknown>;
  const checkpointKeyring = readJson(checkpointKeyringPath) as Record<string, unknown>;

  const res = verifyEvidence(bundle, {
    tenantRoot: tenantRoot as never,
    checkpointKeyring: checkpointKeyring as never,
    ...(now !== undefined ? { now } : {}),
    ...(maxAgeHours !== undefined && Number.isFinite(maxAgeHours) ? { maxAgeMs: maxAgeHours * 60 * 60 * 1000 } : {}),
  });

  process.stdout.write(JSON.stringify(res, null, 2) + "\n");

  const code =
    res.verdict === "VALID_FULL_CHAIN" || res.verdict === "VALID_SEGMENT_ONLY" || res.verdict === "VALID_FROM_TRUSTED_ANCHOR"
      ? 0
      : res.verdict === "INVALID"
        ? 2
        : res.verdict === "INCONCLUSIVE"
          ? 3
          : 4; // UNVERIFIED
  process.exit(code);
}

main(process.argv);
