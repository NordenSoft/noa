#!/usr/bin/env node
/**
 * noa-tsa — independent anchoring for noa-receipt witness anchors (opt-in, offline).
 *
 *   noa-tsa stamp       --anchors <anchors.json> --tsa-url <url> [--out <path>] [--no-cert-req] [--no-nonce]
 *   noa-tsa verify      --anchors <anchors.json> --tsr <tsr.json>
 *   noa-tsa fork-scan   --anchors <pool.json> --trust-set <trust-set.json> [--chain <receipts.json>] [--tsr <tsr.json>]
 *   noa-tsa corroborate --checkpoint <cp.json> --anchors <pool.json> --trust-set <trust-set.json>
 *                       [--now <rfc3339> --max-age-ms <n>] [--tsr <tsr.json>]
 *
 * `stamp` requests ONE RFC 3161 timestamp per DISTINCT anchor in <anchors.json> (keyed by the
 * anchor's own hash — see anchor-hash.mjs — so two anchors over the same frontier from different
 * witnesses get separate stamps) and writes a {anchorHash -> stamp record} sidecar map; it NEVER
 * modifies <anchors.json>. `verify` structurally checks every anchor against its stamp (verify.mjs)
 * and exits non-zero if ANY anchor is unstamped or mismatched.
 *
 * `fork-scan` is the MONITOR (equivocation.mjs): it reads a pool of PUBLISHED anchors and reports
 * signed contradictions — one identity, two histories. It needs no presented head and no private
 * state. `--chain` additionally compares the pool against the chain the prover presented, which is
 * what catches a retroactive edit that also extended the chain. `corroborate` asks whether a v0.1
 * checkpoint's endorsed head was independently observed by a quorum of pinned witnesses.
 *
 * Hostile-input hardened: input files are read with a size cap and parsed by noa-receipt's own
 * hardened safeParse.
 *
 * Exit codes: 0 OK · 1 MISMATCH (verify: >=1 anchor unstamped/mismatched; corroborate: quorum not
 * met) · 2 TRANSPORT (stamp: TSA request failed) · 3 MALFORMED (bad JSON/DER input) · 4 USAGE ·
 * 5 EQUIVOCATION (a signed contradiction was found).
 */
import { readSync, writeFileSync, openSync, fstatSync, closeSync, constants as fsConstants } from "node:fs";
import { safeParse, frozenTable, verifyChain, intrinsics } from "noa-receipt";
import { stampAnchor } from "./client.mjs";
import { verifyStamp } from "./verify.mjs";
import { anchorHash } from "./anchor-hash.mjs";
import { scanForEquivocation, checkpointCorroboration, historyFromReceipts, receiptCount, rfc3339ToMs } from "./equivocation.mjs";

const MAX_FILE_BYTES = 64 * 1024 * 1024;
// Captured at load, and the exit table frozen + null-rooted (ADR §5.6). The exit code IS the
// verdict as a pipeline consumes it, so a rewritable EXIT.EQUIVOCATION would turn a detected
// fork into a silent success for every caller at once.
const { setHas, newSet, arrayLength, arraySlice, isArray, strStartsWith, toNumber, isFiniteNumber, jsonStringify } = intrinsics;
const EXIT = frozenTable({ OK: 0, MISMATCH: 1, TRANSPORT: 2, MALFORMED: 3, USAGE: 4, EQUIVOCATION: 5 });

function usage(msg) {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: noa-tsa stamp --anchors <anchors.json> --tsa-url <url> [--out <path>] [--no-cert-req] [--no-nonce]\n" +
      "       noa-tsa verify --anchors <anchors.json> --tsr <tsr.json>\n" +
      "       noa-tsa fork-scan --anchors <pool.json> --trust-set <trust-set.json> [--chain <receipts.json>] [--tsr <tsr.json>]\n" +
      "       noa-tsa corroborate --checkpoint <cp.json> --anchors <pool.json> --trust-set <trust-set.json>\n" +
      "                           [--now <rfc3339> --max-age-ms <n>] [--tsr <tsr.json>]\n",
  );
  process.exit(EXIT.USAGE);
}

/**
 * ONE fatal-exit path, rather than a `process.stderr.write` + `process.exit` pair at each site.
 * Centralising it keeps the exit-code table honest (every fatal route goes through a single place
 * that takes the code as an argument) and keeps the number of raw `process.*` dispatch sites in
 * this decision-path file to the few that genuinely need them.
 */
function fail(code, msg) {
  process.stderr.write(`error: ${msg}\n`);
  process.exit(code);
}

function readJsonFile(path) {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = openSync(path, flags);
  } catch {
    usage(`cannot open file: ${path}`);
  }
  let text;
  try {
    let st;
    try {
      st = fstatSync(fd);
    } catch {
      usage(`cannot inspect file: ${path}`);
    }
    if (!st.isFile()) usage(`not a regular file: ${path}`);
    if (st.size > MAX_FILE_BYTES) usage(`file too large (>${MAX_FILE_BYTES} bytes): ${path}`);
    try {
      const chunks = [];
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
  try {
    return safeParse(text, { maxLength: MAX_FILE_BYTES });
  } catch (e) {
    // Malformed JSON is EXIT.MALFORMED (3) with a clean one-line message — never an uncaught
    // safeParse throw dumping a raw stack and exiting 1 (which contradicts the header's exit table).
    fail(EXIT.MALFORMED, `malformed JSON in ${path}: ${e.message}`);
  }
}

function parseFlags(args, spec) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (setHas(spec.valued, a)) {
      const v = args[++i];
      if (v === undefined || strStartsWith(v, "--")) usage(`${a} requires a value`);
      out[a] = v;
    } else if (setHas(spec.flags, a)) {
      out[a] = true;
    } else {
      usage(`unknown flag: ${a}`);
    }
  }
  return out;
}

async function cmdStamp(args) {
  const flags = parseFlags(args, { valued: new Set(["--anchors", "--tsa-url", "--out"]), flags: new Set(["--no-cert-req", "--no-nonce"]) });
  if (!flags["--anchors"]) usage("stamp requires --anchors <path>");
  if (!flags["--tsa-url"]) usage("stamp requires --tsa-url <url>");
  const anchors = readJsonFile(flags["--anchors"]);
  if (!Array.isArray(anchors)) usage("--anchors file must contain a JSON array of anchors");
  // "Did nothing" is not "succeeded". Exiting 0 over an empty array reported success for a run that
  // did no work at all - reproduced for `stamp` against an UNREACHABLE TSA, where exit 0 said
  // nothing about whether the TSA had ever been contacted.
  if (arrayLength(anchors) === 0) usage("--anchors file contains an empty array - refusing to report success for stamping nothing");
  const out = flags["--out"] ?? `${flags["--anchors"]}.tsr.json`;

  const sidecar = {};
  // Index walk, not `for…of`: the iterator protocol is rewritable and a substituting iterator
  // could hand the stamper a different anchor from the one the caller supplied.
  for (let ai = 0; ai < arrayLength(anchors); ai++) {
    const a = anchors[ai];
    let key;
    try {
      key = anchorHash(a);
    } catch (e) {
      fail(EXIT.MALFORMED, `malformed anchor entry: ${e.message}`);
      return EXIT.MALFORMED;
    }
    if (sidecar[key]) continue; // distinct-anchor dedup (same witness re-listed twice in the file)
    try {
      sidecar[key] = await stampAnchor(a, {
        tsaUrl: flags["--tsa-url"],
        certReq: !flags["--no-cert-req"],
        includeNonce: !flags["--no-nonce"],
      });
    } catch (e) {
      fail(EXIT.TRANSPORT, `stamping anchor ${key} (kid=${a?.sig?.kid}): ${e.message}`);
      return EXIT.TRANSPORT;
    }
  }
  writeFileSync(out, JSON.stringify(sidecar, null, 2) + "\n", "utf8");
  process.stdout.write(`wrote ${Object.keys(sidecar).length} stamp(s) to ${out}\n`);
  return EXIT.OK;
}

function cmdVerify(args) {
  const flags = parseFlags(args, { valued: new Set(["--anchors", "--tsr"]), flags: new Set() });
  if (!flags["--anchors"]) usage("verify requires --anchors <path>");
  if (!flags["--tsr"]) usage("verify requires --tsr <path>");
  const anchors = readJsonFile(flags["--anchors"]);
  const sidecar = readJsonFile(flags["--tsr"]);
  if (!Array.isArray(anchors)) usage("--anchors file must contain a JSON array of anchors");
  if (arrayLength(anchors) === 0) usage("--anchors file contains an empty array - refusing to report success for verifying nothing");
  if (typeof sidecar !== "object" || sidecar === null || Array.isArray(sidecar)) usage("--tsr file must contain a JSON object (anchorHash -> stamp record)");

  let mismatches = 0;
  let malformed = 0;
  const results = [];
  for (let ai = 0; ai < arrayLength(anchors); ai++) {
    const a = anchors[ai];
    let key;
    try {
      key = anchorHash(a);
    } catch (e) {
      results.push({ ok: false, code: "MALFORMED", reason: `malformed anchor entry: ${e.message}` });
      mismatches++;
      malformed++;
      continue;
    }
    const record = sidecar[key];
    const res = record ? verifyStamp(a, record) : { ok: false, reason: "no stamp for this anchor in the .tsr file" };
    results.push({ anchorHash: key, chain: a?.chain, highestSeq: a?.highestSeq, ...res });
    if (!res.ok) {
      mismatches++;
      if (res.code === "MALFORMED") malformed++;
    }
  }
  process.stdout.write(JSON.stringify({ results, mismatches }, null, 2) + "\n");
  // A bad-DER/bad-base64 (or malformed anchor) input is EXIT.MALFORMED (3) per the header table —
  // distinct from a well-formed-but-non-matching stamp, which is EXIT.MISMATCH (1).
  if (malformed > 0) return EXIT.MALFORMED;
  return mismatches === 0 ? EXIT.OK : EXIT.MISMATCH;
}

/** Shared loader for the monitor commands: the anchor pool, the pinned trust-set, optional stamps. */
function loadMonitorInputs(flags) {
  const anchors = readJsonFile(flags["--anchors"]);
  const trustSet = readJsonFile(flags["--trust-set"]);
  if (!isArray(anchors)) usage("--anchors file must contain a JSON array of anchors (the published pool)");
  if (arrayLength(anchors) === 0) usage("--anchors file contains an empty array - an empty pool is not a clean pool");
  const opts = {};
  if (flags["--chain"]) {
    const receipts = readJsonFile(flags["--chain"]);
    if (!isArray(receipts)) usage("--chain file must contain a JSON array of receipts");
    if (arrayLength(receipts) === 0) usage("--chain file contains an empty array - there is no presented history to compare against");
    // THE PRESENTED CHAIN IS VERIFIED, NOT TRUSTED. `historyFromReceipts` reads each receipt's OWN
    // `chain.hash` and skips whatever it cannot read; on its own that let `--chain '[{}]'` exit 0
    // while reporting `historyChecked:true` over a history containing nothing at all. Two checks
    // close it: the kernel's unchanged offline verifier must accept the document (no keyring needed
    // - this is the structural and hash-linkage check, so the hashes the history is built from are
    // the chain's own real ones), and the derivation must be TOTAL, not partial.
    const chainResult = verifyChain(jsonStringify(receipts));
    if (chainResult.status === "MALFORMED" || chainResult.status === "TAMPERED") {
      fail(EXIT.MALFORMED, `--chain does not verify (${chainResult.status}: ${chainResult.reason}) - refusing to compare anchors against a chain that is not internally consistent`);
    }
    const history = historyFromReceipts(receipts);
    if (arrayLength(history) !== receiptCount(receipts)) {
      fail(EXIT.MALFORMED, `--chain: only ${arrayLength(history)} of ${receiptCount(receipts)} receipt(s) yielded a usable (chain, seq, hash) entry - a partially-read history would silently narrow the comparison`);
    }
    opts.history = history;
  }
  if (flags["--tsr"]) {
    const sidecar = readJsonFile(flags["--tsr"]);
    if (typeof sidecar !== "object" || sidecar === null || isArray(sidecar)) {
      usage("--tsr file must contain a JSON object (anchorHash -> stamp record)");
    }
    opts.stamps = sidecar;
  }
  return { anchors, trustSet, opts };
}

function cmdForkScan(args) {
  const flags = parseFlags(args, { valued: newSet(["--anchors", "--trust-set", "--chain", "--tsr"]), flags: newSet() });
  if (!flags["--anchors"]) usage("fork-scan requires --anchors <path>");
  if (!flags["--trust-set"]) usage("fork-scan requires --trust-set <path>");
  const { anchors, trustSet, opts } = loadMonitorInputs(flags);

  const res = scanForEquivocation(anchors, trustSet, opts);
  process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  // EXIT 0 MEANS "CLEAN", AND NOTHING ELSE. It used to also cover "I admitted nothing" and "the
  // pool was full of forgeries", so a pipeline could not tell a clean bill from a scan that never
  // examined anything. `clean` is the single fail-closed field, and the exit code now follows it.
  if (res.verdict === "INVALID_INPUT") return EXIT.MALFORMED;
  if (res.equivocationFound) return EXIT.EQUIVOCATION;
  return res.clean ? EXIT.OK : EXIT.MISMATCH;
}

function cmdCorroborate(args) {
  const flags = parseFlags(args, {
    valued: newSet(["--checkpoint", "--anchors", "--trust-set", "--chain", "--tsr", "--now", "--max-age-ms"]),
    flags: newSet(),
  });
  if (!flags["--checkpoint"]) usage("corroborate requires --checkpoint <path>");
  if (!flags["--anchors"]) usage("corroborate requires --anchors <path>");
  if (!flags["--trust-set"]) usage("corroborate requires --trust-set <path>");
  const checkpoint = readJsonFile(flags["--checkpoint"]);
  const { anchors, trustSet, opts } = loadMonitorInputs(flags);

  // Freshness is all-or-nothing: half a policy is an operator error, and silently treating it as "no
  // freshness" would re-open the replay gap the flag exists to close.
  const hasNow = flags["--now"] !== undefined;
  const hasAge = flags["--max-age-ms"] !== undefined;
  if (hasNow !== hasAge) usage("--now and --max-age-ms must be supplied together (a freshness policy is not half a policy)");
  if (hasNow) {
    // STRICT RFC 3339, because that is what the flag claims. `Date.parse` accepted "2026" and
    // silently anchored the whole freshness window to the first instant of that year. The strict
    // scanner already existed in equivocation.mjs and simply was not being used here.
    const now = rfc3339ToMs(flags["--now"]);
    const maxAgeMs = toNumber(flags["--max-age-ms"]);
    if (now === null) usage(`--now must be a full RFC 3339 timestamp such as 2026-06-23T10:30:00Z (got: ${flags["--now"]})`);
    if (!isFiniteNumber(maxAgeMs) || maxAgeMs < 0) usage(`--max-age-ms must be a non-negative number: ${flags["--max-age-ms"]}`);
    opts.freshness = { now, maxAgeMs };
  }

  const res = checkpointCorroboration(checkpoint, anchors, trustSet, opts);
  process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  if (res.verdict === "INVALID_INPUT") return EXIT.MALFORMED;
  if (res.equivocationFound) return EXIT.EQUIVOCATION;
  return res.corroborated ? EXIT.OK : EXIT.MISMATCH;
}

async function main(argv) {
  // Captured slicing: the argv walk selects WHICH verdict runs, so it does not go through a
  // rewritable `Array.prototype.slice`.
  const args = arraySlice(argv, 2);
  if (arrayLength(args) === 0) usage();
  const cmd = args[0];
  const rest = arraySlice(args, 1);
  if (cmd === "stamp") return cmdStamp(rest);
  if (cmd === "verify") return cmdVerify(rest);
  if (cmd === "fork-scan") return cmdForkScan(rest);
  if (cmd === "corroborate") return cmdCorroborate(rest);
  usage(`unknown command: ${cmd}`);
}

main(process.argv).then((code) => process.exit(code));
