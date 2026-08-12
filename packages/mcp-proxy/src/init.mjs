#!/usr/bin/env node
/**
 * init.mjs — `noa-mcp-proxy init`: scaffolds the artifacts the R4 human-approval gate needs to
 * START, into a target directory.
 *
 * THIS IS SCAFFOLDING, NOT ACTIVATION. Do not read a clean exit from this command as "the gate is
 * now protecting anything" — it is not, until every one of the following is also true:
 *   1. an MCP host's config actually launches `proxy.mjs` wrapping your real downstream, pointed at
 *      the files this command writes (see this package's README, "Human-approval gate (R4)" and
 *      "Run it yourself");
 *   2. the generated `approval-rules.json` actually matches YOUR tool/action ids — the starter rule
 *      below matches ONLY the bundled demo tool, and a rule that matches nothing you own holds
 *      nothing of yours; and
 *   3. a real HUMAN runs `noa-approve` out-of-band for every held call, from a separate terminal,
 *      holding the approver private key this command mints — that human's judgment is the control;
 *      this package only proves, cryptographically, what they decided, after the fact; and
 *   4. the agent RETRIES the identical held call once approved — approval does not itself re-execute
 *      anything.
 * "One command and you're done" is a claim this project's own review explicitly rejected; do not
 * reintroduce it in help text, a commit message, or documentation that wraps this command. Nothing
 * generated here is described as "unforgeable" or "cannot be bypassed" — see NON-CLAIMS.md and
 * THREAT-MODEL.md before relying on any of it.
 *
 * Generates, under --dir (default "."):
 *   approval-rules.json     A starter rule set: this package's OWN demo transfer-guard fixture
 *                            (src/policy.mjs's `APPROVAL_RULES` — the exact array Scenario R in
 *                            test/smoke.mjs exercises). It holds `transfer_funds` calls of >= 5000
 *                            minor units from the BUNDLED demo-downstream.mjs. A real integration
 *                            MUST replace `match.action` (and, if used, `threshold.path`) with its
 *                            own tool/action ids before this protects anything of the operator's own.
 *   pending-store.jsonl      The empty JSONL operational index --pending-store points at. Empty and
 *                            "does not exist yet" fold to the identical state (see adapter-core's
 *                            pending-store.mjs) — creating it here is a real, inspectable starting
 *                            point, not a magic trick.
 *   approver-key.json        A FRESH Ed25519 signing identity for the human-approver seat, written
 *                            mode 0600 through noa-mcp-adapter-core's `loadOrCreateKeyFile` — the
 *                            SAME CWE-367/TOCTOU-hardened helper packages/signer-sidecar's sidecar
 *                            uses, never a hand-rolled `writeFileSync`. Hand this path to
 *                            `noa-approve --key-file` and NOWHERE else — whoever holds it IS the
 *                            approval seat, in full.
 *   approver-keyring.json    The PUBLIC `{ kid: publicKey }` derived from approver-key.json — what
 *                            `--approver-keyring` feeds the proxy so it can authenticate that seat's
 *                            signature. Sharing this file is fine; sharing approver-key.json is the
 *                            same as handing over the approval seat itself.
 *
 * Refuses to silently overwrite: the pre-flight check runs as ONE BATCH, over all four paths,
 * BEFORE any write begins — so a directory where NONE of the four is occupied gets all four
 * written, and a directory where ANY of the four is already occupied (a regular file, a
 * directory, or a symlink — dangling or not; see the CWE-367 note below) refuses the run before
 * touching anything, unless --force is given, in which case all four are regenerated fresh
 * (including a BRAND NEW approver identity — any approval-in-flight signed under the old one
 * stops verifying against the new keyring).
 *
 * Honest limit on that guarantee: the pre-flight check is atomic as a CHECK, not as a WRITE. Once
 * writing begins, the four files are still created one at a time; a failure partway through
 * (a disk error, or a file appearing at one of the four paths in the window between the
 * pre-flight check and that specific write — the same TOCTOU class CWE-367 names) can leave
 * earlier files in this run on disk and later ones missing. On any write failure this prints
 * exactly which of the four were confirmed written before the failure, rather than claiming
 * either "all four" or "none" by default.
 *
 * CWE-367 (symlink / TOCTOU): every one of the four writes below uses the SAME
 * `O_CREAT|O_EXCL|O_NOFOLLOW` guard, applied uniformly rather than only on the one file that
 * happens to hold key material. `O_EXCL` alone already makes the OS refuse to create through a
 * PRE-EXISTING symlink at the target path — dangling or not, per POSIX open(2) — independently of
 * where the link points; `O_NOFOLLOW` is belt-and-suspenders on platforms that support it. For
 * approver-key.json specifically, the actual write still goes through
 * noa-mcp-adapter-core's `loadOrCreateKeyFile` (mode 0600, the same helper packages/signer-sidecar
 * uses) rather than the local helper below — that helper carries its own, independently-audited
 * version of this exact guard; the local helper here exists because no equivalent is exported from
 * noa-mcp-adapter-core for non-key files (checked: index.mjs exports nothing narrower than the
 * key-file loader for a single-file exclusive create).
 */
import { mkdirSync, lstatSync, openSync, writeFileSync, closeSync, unlinkSync, constants as fsConstants } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { loadOrCreateKeyFile, generateKeyPair, validateApprovalRules, describeThrown, thrownCode, intrinsics } from "noa-mcp-adapter-core";
import { APPROVAL_RULES } from "./policy.mjs";

// Builtins taken from the kernel's module-load capture rather than read live, matching every other
// file in this TCB (see proxy.mjs's own REDTEAM 2026-08-03 note): a decision path — and refusing to
// write through a symlink onto the gate's own trust anchor IS one — must not resolve `.filter`,
// `.push`, `JSON.stringify` etc. through a prototype slot an attacker in this realm could replace.
const { jsonStringify, arrayPush } = intrinsics;

// Captured ONCE at module load — every `process.std*.write` inside a function called later reads
// this local binding, never the live global. `process` itself has no wrapper in the shared
// intrinsics bundle (it is a host object, not a JS-spec builtin the kernel wraps), so it is
// captured locally here, the same way, for the same reason: a value read before this module
// finishes evaluating can no longer be repointed by anything that runs after.
const PROCESS = process;

const GENERATED = Object.freeze(["approval-rules.json", "pending-store.jsonl", "approver-key.json", "approver-keyring.json"]);

const HELP = `usage: noa-mcp-proxy init [--dir <path>] [--force]

Scaffolds approval-rules.json, pending-store.jsonl, approver-key.json, and approver-keyring.json
into --dir (default: the current directory) — the four inputs the human-approval gate
(--approval-rules / --pending-store / --approver-keyring) needs to start. This is scaffolding, not
activation: it does not wire an MCP host, does not adapt the starter rule to your own tools, and
does not run any approval — see this package's README, "Human-approval gate (R4)".

  --dir <path>   target directory (created if missing; default ".")
  --force        overwrite existing generated files instead of refusing (regenerates the approver
                 identity too — anything approved under the old one stops verifying)
  --help, -h     print this message
`;

/**
 * True if ANYTHING sits at `path` — a regular file, a directory, or a symlink (dangling or not).
 * Deliberately `lstatSync`, never `existsSync`/`statSync`: both of those FOLLOW a symlink and
 * report "nothing here" for a DANGLING one (the target doesn't exist, so the query about the
 * target says false) — which is exactly backwards for a pre-flight occupancy check: the pathname
 * itself is occupied by the link regardless of what, if anything, it points at. `lstatSync` looks
 * at the link itself and never follows it.
 */
function pathOccupied(path) {
  try {
    lstatSync(path);
    return true;
  } catch (err) {
    if (thrownCode(err) === "ENOENT") return false;
    throw err; // anything else (EACCES, ...) is a real problem, not "free to write here"
  }
}

/**
 * Creates a BRAND-NEW file at `path` and writes `content` to it, refusing outright if anything
 * already sits there (see the module doc-comment's CWE-367 note for why `O_CREAT|O_EXCL` is the
 * control, not just this function's own existence). Throws with a clear, greppable message on
 * EEXIST/ELOOP; any other open/write failure propagates as-is (converted to a description by the
 * caller via `describeThrown`, per this package's thrown-value-handling boundary).
 */
function createFileExclusive(path, content) {
  const flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = openSync(path, flags, 0o644);
  } catch (err) {
    const code = thrownCode(err);
    if (code === "EEXIST" || code === "ELOOP") {
      throw new Error(`"${path}" already exists or is a symlink -- refusing to write through it (CWE-367 symlink-attack guard)`);
    }
    throw err;
  }
  try {
    writeFileSync(fd, content, "utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Renders `items` as one indented line per entry — replaces the `.map(...).join("")` shape used
 * throughout this file's messages. `.map`/`.join` are BOTH prototype dispatches an attacker could
 * rewrite (L2/L8's own DISPATCH_METHODS list), and an index loop needs no wrapper import at all for
 * a use this small and local.
 */
function joinLines(items) {
  let out = "";
  for (let i = 0; i < items.length; i++) out += `  ${items[i]}\n`;
  return out;
}

function parseArgs(argv) {
  const opts = { dir: ".", force: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--dir") {
      const value = argv[++i];
      if (value === undefined) throw new Error('noa-mcp-proxy init: "--dir" requires a value');
      opts.dir = value;
    } else if (flag === "--force") {
      opts.force = true;
    } else if (flag === "--help" || flag === "-h") {
      opts.help = true;
    } else {
      throw new Error(`noa-mcp-proxy init: unknown flag "${flag}" (see --help)`);
    }
  }
  return opts;
}

function nextStepsMessage({ dir, rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath }) {
  return `noa-mcp-proxy init: wrote 4 files to "${dir}":
  ${rulesPath}
      starter approval rule (matches the BUNDLED demo transfer_funds tool only — edit
      match.action to your own tool/action id before this holds anything of yours)
  ${pendingStorePath}
      empty operational index for outstanding approvals
  ${approverKeyPath}
      PRIVATE key (mode 0600) for the human-approver seat — pass to \`noa-approve --key-file\` ONLY
  ${approverKeyringPath}
      PUBLIC key derived from the file above — this is what --approver-keyring feeds the proxy

This is SCAFFOLDING, not activation. Nothing is protected yet. To actually see the gate hold and
release one call:

  1. Point an MCP host (or this package's own demo) at the proxy with the gate on, e.g.:
       node <path-to-proxy.mjs> \\
         --approval-rules ${rulesPath} \\
         --pending-store ${pendingStorePath} \\
         --approver-keyring ${approverKeyringPath} \\
         -- node <path-to-your-downstream-server>
  2. A call matching the starter rule (transfer_funds, amountMinor >= 5000, against the bundled
     demo downstream) is HELD — the proxy returns an MCP error carrying the DEFERRED receipt id;
     the downstream is never invoked.
  3. From a SEPARATE terminal, a human holding approver-key.json resolves it out-of-band:
       noa-approve approve --id <receiptId> --by you@example.com \\
         --pending-store ${pendingStorePath} --key-file ${approverKeyPath}
  4. The agent retries the IDENTICAL call. Only then does the proxy adopt the signed approval and
     forward it — approving does not itself re-execute anything.

No claim here is "unforgeable" or "cannot be bypassed". Read NON-CLAIMS.md and THREAT-MODEL.md
(https://github.com/NordenSoft/noa) before relying on this for anything that matters.
`;
}

/**
 * Runs one `init` invocation. Returns an exit code (0/1) — NEVER throws, NEVER calls
 * `process.exit` — mirroring adapter-core's `runApproveCli` so this is directly unit-testable
 * in-process (see test/init.test.mjs).
 */
export function runInitCli(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    PROCESS.stderr.write(`${describeThrown(err)}\n`);
    return 1;
  }
  if (opts.help) {
    PROCESS.stdout.write(HELP);
    return 0;
  }

  const dir = opts.dir;
  const rulesPath = join(dir, "approval-rules.json");
  const pendingStorePath = join(dir, "pending-store.jsonl");
  const approverKeyPath = join(dir, "approver-key.json");
  const approverKeyringPath = join(dir, "approver-keyring.json");
  const targets = { rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath };

  try {
    mkdirSync(dir, { recursive: true });
  } catch (err) {
    PROCESS.stderr.write(`noa-mcp-proxy init: could not create "${dir}" (${describeThrown(err)})\n`);
    return 1;
  }

  // Refuse the WHOLE run before writing anything if any target already exists, unless --force.
  // Checked as a batch (not "refuse the first one hit and leave the rest half-written") — a
  // partial scaffold silently mixed with pre-existing files is worse than a clean refusal.
  // `pathOccupied` (lstat-based) catches a symlink here too, dangling or not — see the module
  // doc-comment's CWE-367 note; `existsSync` would miss a dangling one. `pathOccupied` can itself
  // throw on a non-ENOENT lstat failure (e.g. EACCES on a parent directory) — caught HERE so that
  // failure reaches the caller as a normal exit-1 report, honoring this function's own "never
  // throws" contract, rather than escaping uncaught. An index loop (not `.filter`) over a plain
  // array (not `for…of`) — both are prototype/iterator dispatches on this decision path.
  const allTargets = [rulesPath, pendingStorePath, approverKeyPath, approverKeyringPath];
  const preexisting = [];
  try {
    for (let i = 0; i < allTargets.length; i++) {
      if (pathOccupied(allTargets[i])) arrayPush(preexisting, allTargets[i]);
    }
  } catch (err) {
    PROCESS.stderr.write(`noa-mcp-proxy init: could not check "${dir}" for existing files (${describeThrown(err)})\n`);
    return 1;
  }
  if (preexisting.length > 0 && !opts.force) {
    PROCESS.stderr.write(
      `noa-mcp-proxy init: refusing to overwrite ${preexisting.length} existing file(s) in "${dir}":\n` +
        joinLines(preexisting) +
        `Pass --force to regenerate all four files (this MINTS A NEW approver identity — anything\n` +
        `approved under the old one stops verifying against the new keyring), or move them aside first.\n`,
    );
    return 1;
  }
  if (opts.force) {
    for (let i = 0; i < preexisting.length; i++) {
      const p = preexisting[i];
      try {
        unlinkSync(p);
      } catch (err) {
        PROCESS.stderr.write(`noa-mcp-proxy init: --force could not remove existing "${p}" (${describeThrown(err)})\n`);
        return 1;
      }
    }
  }

  // Self-check the starter rules against the SAME validator the gate itself runs at load time —
  // belt-and-suspenders: APPROVAL_RULES is an existing, already-tested fixture, but a generator
  // that ships a rule set it has never validated is exactly the kind of "trust me" this package
  // exists to replace.
  const validation = validateApprovalRules(APPROVAL_RULES);
  if (!validation.ok) {
    PROCESS.stderr.write(
      `noa-mcp-proxy init: internal error — this package's own starter approval rules failed validation:\n${joinLines(validation.errors)}`,
    );
    return 1;
  }

  // Written one at a time (this is where the "checked as one batch, written sequentially" honest
  // limit from the module doc-comment applies) — `confirmed` tracks exactly which of the four
  // landed before any failure, so a partial-write report never has to guess or overclaim.
  const confirmed = [];
  try {
    createFileExclusive(rulesPath, jsonStringify(APPROVAL_RULES, null, 2) + "\n");
    arrayPush(confirmed, rulesPath);
    createFileExclusive(pendingStorePath, "");
    arrayPush(confirmed, pendingStorePath);
    const approverKp = loadOrCreateKeyFile({
      keyFile: approverKeyPath,
      mintKeyPair: () => generateKeyPair(`noa-mcp-proxy-init:approver:${randomUUID()}`),
      callerLabel: "noa-mcp-proxy init",
    });
    arrayPush(confirmed, approverKeyPath);
    createFileExclusive(approverKeyringPath, jsonStringify({ [approverKp.kid]: approverKp.publicKey }, null, 2) + "\n");
    arrayPush(confirmed, approverKeyringPath);
  } catch (err) {
    PROCESS.stderr.write(
      `noa-mcp-proxy init: could not write generated files (${describeThrown(err)})\n` +
        (confirmed.length > 0
          ? `${confirmed.length} of 4 file(s) WERE written before this failure (not all-or-nothing once writing starts — see init.mjs's doc-comment):\n${joinLines(confirmed)}`
          : "0 of 4 files were written.\n"),
    );
    return 1;
  }

  // Only reached once EVERY one of the four literal paths below was freshly created (never
  // followed through a symlink — createFileExclusive would have thrown first) — so this message
  // is never printed for a run that actually wrote somewhere else.
  PROCESS.stdout.write(nextStepsMessage({ dir, ...targets }));
  return 0;
}

export const GENERATED_FILE_NAMES = GENERATED;

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(runInitCli(process.argv.slice(2)));
}
