/**
 * config-artifact.mjs — the ONE hardened open/read/append/write path for a SECURITY-BEARING
 * CONFIG FILE: an artifact whose CONTENT decides whether a human has to approve an action, and
 * whose signature is allowed to stand in for that human.
 *
 * ── THE BUG THIS MODULE EXISTS TO CLOSE (reproduced 2026-08-12, not theoretical) ────────────────
 * `packages/mcp-proxy/src/proxy.mjs` read `--approval-rules`, `--approver-keyring` and
 * `--approver-identity` with a path-based `readFileSync(path, "utf8")`, and
 * `packages/adapter-core/src/pending-store.mjs` read/appended `--pending-store` the same way. A
 * path-based read FOLLOWS A SYMLINK. Two attacks were measured against the shipped CLI:
 *
 *   1. Replace `approval-rules.json` with a symlink to a file containing `[]`. The human-approval
 *      gate is then OFF, and a `transfer_funds` of 7000 minor units — well above the configured
 *      5000 threshold — was FORWARDED AND EXECUTED with no human approval at any point. The
 *      downstream answered "transferred 7000 (minor units) to attacker-account".
 *   2. Replace `approver-keyring.json` with a symlink to an attacker-controlled keyring. The
 *      attacker then signs the approval with their OWN key, and the identical retry EXECUTED.
 *
 * WHY THAT IS IN SCOPE AND NOT AN OPERATOR PROBLEM. This product exists to stop an AI agent from
 * taking a consequential action without a named human's approval. In most real deployments the
 * agent process CAN WRITE ITS OWN WORKING DIRECTORY. So "the attacker can create a file in the
 * config directory" is not an exotic precondition — it is the ordinary state of the thing being
 * constrained. An enforcement boundary that a file swap turns off is not a boundary.
 *
 * ── WHAT THIS MODULE DOES ───────────────────────────────────────────────────────────────────────
 * Every access goes through ONE descriptor that cannot be redirected by a later path swap:
 *
 *   - `openSync(path, ... | O_NOFOLLOW)` — the open ITSELF fails (ELOOP) when the final path
 *     component is a symlink, whether it resolves or dangles. There is no separate "check the
 *     path, then open the path" gap for a race to land in, because the check IS the open.
 *   - `fstatSync(fd)` — on the DESCRIPTOR, never a second `statSync` on the PATH (which would
 *     reopen the very TOCTOU window this closes). It must be a REGULAR FILE: a FIFO, a device or a
 *     directory can hand a different answer to every read, which is the same bug with a longer fuse.
 *   - OWNER: the file must belong to this process's effective uid, or to root. A file planted by a
 *     DIFFERENT uid never becomes a verdict here.
 *   - MODE: group/other WRITE bits are refused. A world-writable rule set is not a rule set.
 *   - The bytes are then read from THAT SAME DESCRIPTOR — the path is never re-opened.
 *
 * ── WHAT THIS MODULE DOES NOT DO, STATED PLAINLY ────────────────────────────────────────────────
 * It does NOT defend against an attacker who can rewrite the file's CONTENT IN PLACE as the same
 * uid. Same-uid in-place content rewriting is indistinguishable, at the filesystem layer, from the
 * operator editing their own config, and no `open` flag can tell those apart. It does NOT defend
 * against an attacker who controls this process (they need no file at all), nor against one who
 * owns the directory AND runs as the trusted uid. Defending the CONTENT needs the content to be
 * signed and the signature checked against a key that does not live beside it — see
 * NON-CLAIMS.md NC-7.0. What is closed here is the REDIRECTION class: the path the operator
 * configured no longer decides which BYTES the process reads.
 */
import { openSync, fstatSync, readSync, writeFileSync, ftruncateSync, closeSync, constants as fsConstants } from "node:fs";
import { describeThrown, thrownCode } from "./safe-throw.mjs";

import { intrinsics } from "noa-receipt";

// REDTEAM 2026-08-03 — the builtins come from the kernel's module-load capture on every published
// decision path, whether or not each individual site is reachable today (see key-file.mjs's own
// note). Reachability is a property of the surrounding code, and the surrounding code changes.
const { jsonParse, numToString, arrayPush, bufferAlloc, bufferConcat, bufSubarray, bufToString } = intrinsics;

// Captured at MODULE-EVALUATION time, before any caller-supplied value has been read: the effective
// uid this process is allowed to trust a security artifact from. `null` on a platform with no POSIX
// uid model (Windows), where the ownership test is skipped and DOCUMENTED as skipped rather than
// silently reported as passed — O_NOFOLLOW and the regular-file test still apply there.
const PROCESS_EUID = typeof process.geteuid === "function" ? process.geteuid() : null;

// O_NOFOLLOW is POSIX-only; `0` on a platform lacking it, where this degrades to a plain open — no
// worse than the pre-fix behavior there, and the regular-file/owner/mode tests still run.
const NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
// O_NONBLOCK so a FIFO planted at the config path cannot HANG the open: `open(fifo, O_RDONLY)`
// blocks until a writer arrives, which would let an attacker stall the proxy at startup instead of
// being refused by the regular-file test two lines later. On a regular file it has no effect.
const NONBLOCK = fsConstants.O_NONBLOCK ?? 0;
const READ_FLAGS = fsConstants.O_RDONLY | NOFOLLOW | NONBLOCK;
const APPEND_FLAGS = fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | NOFOLLOW | NONBLOCK;
// ── WHY THESE TWO, AND WHY NEITHER OF THEM CARRIES O_TRUNC (fixed 2026-08-12) ────────────────────
// The replace path used to be ONE open with `O_CREAT|O_TRUNC`, and the truncation therefore happened
// INSIDE the `open` — before the fstat, before the owner test, before the mode test. MEASURED: a
// write refused for a group-writable target had ALREADY EMPTIED that target to zero bytes. The guard
// destroyed the very file it then declined to write. The order is now open (no truncation) → verify
// the descriptor → truncate THROUGH the descriptor that was verified, so a refusal leaves the file
// byte-for-byte as it was found.
//
// Creation is `O_CREAT|O_EXCL`: an EXCLusive create cannot adopt a file that somebody else planted
// between "it was not there" and "create it", which is the window a plain O_CREAT hands over.
const REPLACE_EXISTING_FLAGS = fsConstants.O_WRONLY | NOFOLLOW | NONBLOCK;
const CREATE_EXCLUSIVE_FLAGS = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NOFOLLOW | NONBLOCK;

// A config artifact this package will hold entirely in memory. The cap is not a policy statement —
// it is a bound on how much an attacker who can grow the file can make this process allocate.
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;

// Read granularity for the bounded reader below. Not a limit on anything — only how often the
// running total is compared against the cap.
const READ_CHUNK_BYTES = 64 * 1024;

/** The ONE typed error every guard in this module raises, so a caller can catch the whole class. */
export class ConfigArtifactError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigArtifactError";
  }
}

/**
 * The descriptor-level verdict. Returns a human-readable REASON to refuse, or `null` to accept.
 * Every test here reads the FSTAT OF AN ALREADY-OPEN DESCRIPTOR — nothing re-resolves the path.
 */
function refusalReason(st, pathname, label, singleLink) {
  if (!st.isFile()) {
    return `${label} "${pathname}" is not a regular file — a FIFO, device or directory can answer differently on every read, so it can never be a governance input`;
  }
  // HARD LINKS, on the paths that WRITE (fixed 2026-08-12). O_NOFOLLOW refuses a symLINK; a hard
  // link is not a link at all at the filesystem layer, it is a second NAME for the same inode, and
  // an `fstat` of it is indistinguishable from an fstat of the operator's own file — same uid, same
  // mode, same everything. MEASURED: a hard link planted at the configured output, pointing at
  // another 0600 file owned by this same uid, passed every check and had that victim's content
  // replaced. `nlink` is the one field that can tell: a file this process is entitled to overwrite
  // wholesale should have exactly ONE name. Reads are deliberately NOT subject to this — a second
  // name does not change which bytes a read returns, so refusing there would cost operators a
  // legitimate layout for no security gain.
  if (singleLink && st.nlink > 1) {
    return `${label} "${pathname}" has ${numToString(st.nlink, 10)} hard links — these bytes have another name, so replacing them here would also replace the contents of a file this path does not describe; refusing (point ${label} at a path with a single link)`;
  }
  if (PROCESS_EUID !== null && st.uid !== PROCESS_EUID && st.uid !== 0) {
    return `${label} "${pathname}" is owned by uid ${numToString(st.uid, 10)}, not by this process (uid ${numToString(PROCESS_EUID, 10)}) or root — refusing to take an enforcement decision from a file this process does not own`;
  }
  if ((st.mode & 0o022) !== 0) {
    return `${label} "${pathname}" is writable by group or others (mode 0${numToString(st.mode & 0o777, 8)}) — anyone in that set could turn the gate off; run \`chmod g-w,o-w\` on it first`;
  }
  return null;
}

/**
 * Opens `pathname` with `flags`, then verifies the DESCRIPTOR. Returns `{ fd, size }`, or `null`
 * when the file genuinely does not exist and `flags` did not ask to create it. Throws
 * ConfigArtifactError on a symlink, a non-regular file, a foreign owner or loose write bits — and
 * closes the descriptor before it does, so a refusal never leaks an fd.
 *
 * `singleLink` additionally refuses a hard-linked file (see refusalReason) — set by the paths that
 * WRITE. `existsIsSoft` turns an `EEXIST` from an O_EXCL create into `null` instead of an error, so
 * the caller can re-try the "it exists" branch rather than fail a benign creation race.
 */
function openVerified(pathname, label, flags, mode, { singleLink = false, existsIsSoft = false } = {}) {
  let fd;
  try {
    // The descriptor-level O_NOFOLLOW / regular-file / owner / mode checks below are precisely the
    // controls this generic query models as absent; callers legitimately point these flags at a
    // caller-owned temporary directory in tests.
    // codeql[js/insecure-temporary-file]
    fd = openSync(pathname, flags, mode);
  } catch (err) {
    const code = thrownCode(err);
    if (code === "ELOOP") {
      throw new ConfigArtifactError(
        `${label} "${pathname}" is a symlink — refusing to follow it (CWE-59/CWE-367 symlink-redirect guard: a swapped link would silently change which bytes decide this gate). Point ${label} directly at the intended regular file.`,
      );
    }
    if (code === "ENOENT") return null;
    if (code === "EEXIST" && existsIsSoft) return null;
    throw new ConfigArtifactError(`${label} "${pathname}" could not be opened (${describeThrown(err)})`);
  }

  let st;
  try {
    st = fstatSync(fd);
  } catch (err) {
    closeSync(fd);
    throw new ConfigArtifactError(`${label} "${pathname}" could not be inspected after opening (${describeThrown(err)})`);
  }

  const reason = refusalReason(st, pathname, label, singleLink);
  if (reason !== null) {
    closeSync(fd);
    throw new ConfigArtifactError(reason);
  }
  return { fd, size: st.size };
}

/**
 * Reads a whole descriptor in bounded steps, refusing the moment the ACTUAL byte count passes
 * `maxBytes`.
 *
 * THE BUG THIS REPLACES (reproduced 2026-08-12): the cap was compared against the size reported by
 * the `fstat` and the descriptor was then read in ONE call with no further bound. `fstat` describes
 * the file at the instant it was taken, and a writer that grows the file between that instant and
 * the read is exactly the party this module exists to constrain. Measured with a 1 MB cap and a
 * concurrent appender: the function returned a **1.2 MB** buffer — the cap reported "within limit"
 * about a number that was already stale. A limit that is only ever checked against a remembered
 * value is not a limit on what this process actually allocates.
 */
function readAllBounded(fd, pathname, label, maxBytes) {
  const chunks = [];
  let total = 0;
  for (;;) {
    // A FRESH buffer per chunk: a reused scratch buffer would have to be copied before being
    // retained anyway, and a missed copy is a silent content corruption rather than a loud failure.
    const chunk = bufferAlloc(READ_CHUNK_BYTES);
    const n = readSync(fd, chunk, 0, READ_CHUNK_BYTES, null);
    if (n === 0) break;
    total += n;
    if (total > maxBytes) {
      throw new ConfigArtifactError(
        `${label} "${pathname}" is larger than the ${numToString(maxBytes, 10)}-byte cap (already read ${numToString(total, 10)} bytes) — refusing to load it. A file that grew while it was being read is a file something else is writing right now.`,
      );
    }
    arrayPush(chunks, n === READ_CHUNK_BYTES ? chunk : bufSubarray(chunk, 0, n));
  }
  // Decoded AFTER concatenation, never per chunk: a multi-byte UTF-8 sequence straddling a chunk
  // boundary would otherwise decode as two replacement characters.
  return bufToString(bufferConcat(chunks), "utf8");
}

/**
 * Reads a security-bearing config artifact as UTF-8 text THROUGH a verified descriptor.
 *
 * Returns `null` when the file does not exist and `required` is false (the pending store's very
 * first `recordDeferred` legitimately targets a not-yet-existing path). Every other disqualifying
 * condition is a ConfigArtifactError — never a silent fallback, never a partial read.
 *
 * @param {string} pathname
 * @param {{ label?: string, maxBytes?: number, required?: boolean }} [options]
 */
export function readConfigArtifact(pathname, { label = "config file", maxBytes = DEFAULT_MAX_BYTES, required = false } = {}) {
  const opened = openVerified(pathname, label, READ_FLAGS, undefined);
  if (opened === null) {
    if (required) throw new ConfigArtifactError(`${label} "${pathname}" does not exist`);
    return null;
  }
  try {
    // The fstat size is an EARLY refusal — it costs one comparison and rejects an oversized file
    // without reading a byte of it. It is NOT the enforcement: readAllBounded below re-checks the
    // count of bytes THIS PROCESS ACTUALLY READ, which is the only number that bounds the allocation.
    if (opened.size > maxBytes) {
      throw new ConfigArtifactError(`${label} "${pathname}" is ${numToString(opened.size, 10)} bytes, over the ${numToString(maxBytes, 10)}-byte cap — refusing to load it`);
    }
    // From the DESCRIPTOR. Re-opening by path here is the whole bug: it would hand the final read
    // back to whatever the pathname resolves to at that instant.
    return readAllBounded(opened.fd, pathname, label, maxBytes);
  } finally {
    closeSync(opened.fd);
  }
}

/**
 * `readConfigArtifact` + the kernel's captured `JSON.parse`. The file is REQUIRED: every caller of
 * this helper was given an explicit path by the operator, so a missing file is a misconfiguration
 * that must stop the process, not a reason to run with the control absent.
 *
 * @param {string} pathname
 * @param {{ label?: string, maxBytes?: number }} [options]
 */
export function readConfigJson(pathname, { label = "config file", maxBytes = DEFAULT_MAX_BYTES } = {}) {
  const text = readConfigArtifact(pathname, { label, maxBytes, required: true });
  try {
    return jsonParse(text);
  } catch (err) {
    throw new ConfigArtifactError(`${label} "${pathname}" is not valid JSON (${describeThrown(err)})`);
  }
}

/**
 * Appends to a security-bearing artifact THROUGH a verified descriptor, creating it 0600 if it is
 * not there yet. O_APPEND makes each write land at the end even with a second writer (the approval
 * CLI) on the same file; O_NOFOLLOW means a planted symlink can never turn this into an
 * arbitrary-file append primitive.
 *
 * @param {string} pathname
 * @param {string} text
 * @param {{ label?: string }} [options]
 */
export function appendConfigArtifact(pathname, text, { label = "config file" } = {}) {
  // `singleLink`: an append through a hard link is the same arbitrary-file-write primitive the
  // symlink guard closes, wearing the one disguise O_NOFOLLOW cannot see through.
  const opened = openVerified(pathname, label, APPEND_FLAGS, 0o600, { singleLink: true });
  try {
    // writeFileSync on an EXISTING descriptor writes at the current position (O_APPEND: the end)
    // and loops over short writes itself; it does not close the fd and does not truncate.
    writeFileSync(opened.fd, text, "utf8");
  } finally {
    closeSync(opened.fd);
  }
}

/**
 * Replaces a file this process OWNS, through a verified descriptor. Used for artifacts the proxy
 * publishes (the `--keyring-file` public keyring): without O_NOFOLLOW a planted symlink turns a
 * routine startup write into "clobber any file this process can write" — the same primitive
 * loadOrCreateKeyFile already refuses for `--key-file`.
 *
 * ORDER OF OPERATIONS, AND WHY IT IS THE WHOLE POINT (fixed 2026-08-12): open WITHOUT truncating →
 * verify the descriptor → truncate THROUGH the descriptor that was verified → write. The previous
 * single `O_CREAT|O_TRUNC` open truncated inside the `open` itself, so every refusal below used to
 * fire on a file this function had already emptied. Now a refused write leaves the target byte-for-
 * byte as it was found, and a hard-linked target is refused outright rather than replacing the
 * content of whatever else shares that inode.
 *
 * @param {string} pathname
 * @param {string} text
 * @param {{ label?: string, mode?: number }} [options]
 */
export function writeConfigArtifact(pathname, text, { label = "config file", mode = 0o600 } = {}) {
  // Two attempts, not a loop: the only way BOTH branches decline is that the file existed for one
  // open and did not exist for the other, i.e. something is creating and removing it right now. One
  // retry absorbs a single benign race; a second identical outcome is a state this function refuses
  // to keep guessing at.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const existing = openVerified(pathname, label, REPLACE_EXISTING_FLAGS, undefined, { singleLink: true });
    if (existing !== null) {
      try {
        // Through the ALREADY-VERIFIED descriptor. The file position is still 0, so the write below
        // starts at the beginning; `ftruncate` is what stops a shorter replacement from leaving the
        // tail of the previous content behind.
        ftruncateSync(existing.fd, 0);
        writeFileSync(existing.fd, text, "utf8");
      } finally {
        closeSync(existing.fd);
      }
      return;
    }
    const created = openVerified(pathname, label, CREATE_EXCLUSIVE_FLAGS, mode, { singleLink: true, existsIsSoft: true });
    if (created !== null) {
      try {
        writeFileSync(created.fd, text, "utf8");
      } finally {
        closeSync(created.fd);
      }
      return;
    }
  }
  throw new ConfigArtifactError(
    `${label} "${pathname}" is being created and removed by something else while this process is writing it — refusing to keep re-trying (fail-closed: a governance artifact whose existence flickers is not one this process can publish safely)`,
  );
}
