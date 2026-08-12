#!/usr/bin/env node
/**
 * `noa verify <receipts.json> [--keyring <keyring.json>] [--checkpoint <cp.json>] [--identity <manifest.json>]`
 *
 * OPT-IN witness federation (all disjoint from the default flow — federation-spec §4/§10):
 *   [--anchors <anchors.json>] [--trust-set <trust.json>] [--max-anchor-age-ms <n>]
 *
 * Offline receipt-chain verifier. No network, no NOA cloud. Deterministic exit codes so it
 * drops straight into CI:
 *   0  VALID        (structure + chain + signatures verified against the keyring)
 *   1  UNVERIFIED   (chain ok, but NO keyring supplied so signatures were not authenticated)
 *   2  TAMPERED     (an integrity check failed)
 *   3  MALFORMED    (not a well-formed receipt chain / bad input)
 *   4  USAGE        (bad arguments / unreadable file)
 *   5  UNTRUSTED    (signature ok, but (agent.id, sig.kid) not authorized by the identity manifest)
 *   6  WITNESS_INCOMPLETE (chain VALID, but the §4 witness-acceptance over the supplied anchor snapshot
 *                          did NOT reach QUORUM_CONFIRMED — TRUNCATED / FORK / NOT_ESTABLISHED / STALE /
 *                          INVALID_INPUT; only emitted in the opt-in --anchors/--trust-set mode)
 *
 * CI rule: treat ANY non-zero exit as failure. Do not special-case "==2".
 *
 * Witness mode (opt-in): supply BOTH --anchors and --trust-set (one without the other is a usage error).
 * The chain is verified offline exactly as without the flags, THEN the §4 acceptance rule is applied to the
 * caller-supplied anchor snapshot over the chain's head. A QUORUM_CONFIRMED result plus a VALID chain exits
 * 0; any witness failure exits 6 (or the chain's own non-zero code if the chain itself did not verify).
 * `--max-anchor-age-ms` enforces §4/§6 currency (now = wall clock; a confirm older than n ms is STALE).
 * Omitting the witness flags leaves behavior byte-for-byte identical to the pre-witness CLI.
 *
 * Hostile-input hardened: input is read with a size cap and parsed by the strict safeParse
 * (duplicate-key reject, depth bound, prototype-pollution guard, float reject).
 */

import { readSync, openSync, fstatSync, closeSync, constants as fsConstants } from "node:fs";
import { verifyChain, type VerifyOptions, type VerifyStatus } from "./verify.js";
import { verifyChainWitnessed, type WitnessedOptions } from "./federation/verify-witnessed.js";

const MAX_FILE_BYTES = 64 * 1024 * 1024; // 64 MiB hard cap

const EXIT = {
  VALID: 0,
  UNVERIFIED: 1,
  TAMPERED: 2,
  MALFORMED: 3,
  USAGE: 4,
  UNTRUSTED: 5,
  WITNESS_INCOMPLETE: 6,
} as const;

function usage(msg?: string): never {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa verify <receipts.json> [--keyring <keyring.json>] [--checkpoint <checkpoint.json>] " +
      "[--identity <manifest.json>] [--anchors <anchors.json> --trust-set <trust.json> [--max-anchor-age-ms <n>]]\n" +
      "       noa --serve [--frame-timeout-ms <n>]   (PROTOCOL REHEARSAL, ADR-0002 Stage 0.5 — NOT a security\n" +
      "                                               boundary, NOT the isolated kernel; docs/kernel-wire-protocol.md)\n",
  );
  process.exit(EXIT.USAGE);
}

/**
 * Read a document's TEXT and hand it to the kernel unparsed.
 *
 * It used to `safeParse` here and pass the resulting object into `verifyChain`. That made the CLI
 * the odd one out among five implementations: `impl-go`, `impl-rust`, `impl-csharp` and the
 * `impl-py` CLI each read file bytes and let their own strict parser own the parse. Now this one
 * does too — the parse happens exactly once, inside the boundary, in the module that is normative
 * for it. The size cap stays here because it is a property of reading a FILE, not of the document.
 */
function readDocumentText(path: string): string {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch {
    usage(`cannot open file: ${path}`);
  }
  let text: string;
  try {
    let st: ReturnType<typeof fstatSync>;
    try {
      st = fstatSync(fd);
    } catch {
      usage(`cannot inspect file: ${path}`);
    }
    if (!st.isFile()) usage(`not a regular file: ${path}`);
    if (st.size > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
    try {
      const chunks: Buffer[] = [];
      const chunk = Buffer.allocUnsafe(64 * 1024);
      let total = 0;
      for (;;) {
        const remaining = MAX_FILE_BYTES + 1 - total;
        const n = readSync(fd, chunk, 0, Math.min(chunk.length, remaining), null);
        if (n === 0) break;
        total += n;
        if (total > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
        chunks.push(Buffer.from(chunk.subarray(0, n)));
      }
      text = Buffer.concat(chunks, total).toString("utf8");
    } catch {
      usage(`cannot read file: ${path}`);
    }
  } finally {
    closeSync(fd);
  }
  return text;
}

/** Map a receipt-chain verdict to its exit code (shared by the default and witness paths). */
function statusToExit(status: VerifyStatus): number {
  switch (status) {
    case "VALID":
      return EXIT.VALID;
    case "UNVERIFIED":
      return EXIT.UNVERIFIED;
    case "UNTRUSTED":
      return EXIT.UNTRUSTED;
    case "TAMPERED":
      return EXIT.TAMPERED;
    default:
      return EXIT.MALFORMED;
  }
}

function main(argv: string[]): number {
  const args = argv.slice(2);
  if (args.length === 0) usage();
  const cmd = args[0];
  if (cmd !== "verify") usage(`unknown command: ${cmd}`);

  let receiptsPath: string | undefined;
  let keyringPath: string | undefined;
  let checkpointPath: string | undefined;
  let identityPath: string | undefined;
  let anchorsPath: string | undefined;
  let trustSetPath: string | undefined;
  let maxAnchorAgeMs: number | undefined;

  for (let i = 1; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--keyring") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--keyring requires a path");
      keyringPath = v;
    } else if (a === "--checkpoint") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--checkpoint requires a path");
      checkpointPath = v;
    } else if (a === "--identity") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--identity requires a path");
      identityPath = v;
    } else if (a === "--anchors") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--anchors requires a path");
      anchorsPath = v;
    } else if (a === "--trust-set") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--trust-set requires a path");
      trustSetPath = v;
    } else if (a === "--max-anchor-age-ms") {
      const v = args[++i];
      if (v === undefined || v.startsWith("--")) usage("--max-anchor-age-ms requires a value");
      const n = Number(v);
      if (!Number.isSafeInteger(n) || n < 0) usage("--max-anchor-age-ms must be a non-negative integer");
      maxAnchorAgeMs = n;
    } else if (a.startsWith("--")) usage(`unknown flag: ${a}`);
    else if (!receiptsPath) receiptsPath = a;
    else usage(`unexpected argument: ${a}`);
  }
  if (!receiptsPath) usage("missing <receipts.json>");

  // Witness mode requires BOTH --anchors and --trust-set together; a lone one (or a stray
  // --max-anchor-age-ms) is a usage error (mirrors the paired-flag discipline of the existing flags).
  const witnessMode = anchorsPath !== undefined || trustSetPath !== undefined;
  if (witnessMode && (anchorsPath === undefined || trustSetPath === undefined)) {
    usage("--anchors and --trust-set must be supplied together");
  }
  if (maxAnchorAgeMs !== undefined && !witnessMode) {
    usage("--max-anchor-age-ms requires --anchors and --trust-set");
  }

  let receipts: string;
  const opts: VerifyOptions = {};
  let anchors: string | undefined;
  let trustSet: string | undefined;
  try {
    receipts = readDocumentText(receiptsPath);
    if (keyringPath) opts.keyring = readDocumentText(keyringPath);
    if (checkpointPath) opts.checkpoint = readDocumentText(checkpointPath);
    if (identityPath) opts.identityManifest = readDocumentText(identityPath);
    if (anchorsPath) anchors = readDocumentText(anchorsPath);
    if (trustSetPath) trustSet = readDocumentText(trustSetPath);
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return EXIT.MALFORMED;
  }

  if (witnessMode) {
    const wopts: WitnessedOptions = {
      anchors: anchors as string,
      trustSet: trustSet as string,
    };
    if (opts.checkpoint !== undefined) wopts.checkpoint = opts.checkpoint;
    if (opts.identityManifest !== undefined) wopts.identityManifest = opts.identityManifest;
    if (maxAnchorAgeMs !== undefined) wopts.freshness = { now: Date.now(), maxAgeMs: maxAnchorAgeMs };

    const result = verifyChainWitnessed(receipts, opts.keyring, wopts);
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");

    const chainExit = statusToExit(result.chain.status);
    if (chainExit !== EXIT.VALID) {
      process.stderr.write(`chain did not verify (${result.chain.status}): witness acceptance is moot\n`);
      return chainExit;
    }
    if (result.witness.classification === "QUORUM_CONFIRMED") return EXIT.VALID;
    process.stderr.write(`witness acceptance failed (${result.witness.classification}): ${result.witness.reason}\n`);
    return EXIT.WITNESS_INCOMPLETE;
  }

  const result = verifyChain(receipts, opts);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  return statusToExit(result.status);
}

// `--serve` — Stage 0.5 PROTOCOL REHEARSAL (docs/kernel-wire-protocol.md): length-framed requests
// on stdin, length-framed signed responses on stdout, long-lived. NOT a security boundary and NOT
// the isolated Go kernel — same-realm TypeScript behind a process boundary is still poisonable
// inside the process. Dynamic import so the one-shot path evaluates exactly the modules it always did.
if (process.argv[2] === "--serve") {
  const { runServe } = await import("./serve.js");
  process.exit(await runServe(process.argv.slice(3)));
}
process.exit(main(process.argv));
