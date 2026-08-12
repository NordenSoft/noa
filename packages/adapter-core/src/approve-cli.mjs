#!/usr/bin/env node
/**
 * approve-cli.mjs — `noa-approve`: the v1 human-approval interface for a DEFERRED receipt.
 *
 *   noa-approve approve --id <deferredReceiptId> --by <email> --pending-store <path> --key-file <path> [--receipt-log <path>] [--ttl-ms <n>]
 *   noa-approve deny    --id <deferredReceiptId> --by <email> --reason <text> --pending-store <path> --key-file <path> [--receipt-log <path>]
 *
 * Signs with its OWN approver identity (never the agent's key) and records only a signed decision
 * plus a single-use ticket — it never itself re-executes the held action (that happens later, when
 * the agent retries and the proxy consumes the ticket).
 *
 * D8 / GDPR-CCPA: the raw `--by` email is pseudonymized to an opaque `hmac-sha256:` approver id
 * (opaque-id.mjs) before it enters the SIGNED receipt, and the free-text `--reason` is NEVER signed
 * (kept only in the local pending-store index). No raw PII rests in the signed, hash-chained bytes.
 * Deterministic exit codes: 0 success, 1 usage/runtime error (never a raw uncaught throw).
 */
import { appendFileSync, statSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { generateKeyPair } from "noa-receipt";
import { loadPendingIndex, recordApproved, recordDenied, PendingStoreError } from "./pending-store.mjs";
import { buildApprovalReceipt, buildDenialReceipt, DEFAULT_APPROVAL_TICKET_TTL_MS } from "./approval-decision.mjs";
import { opaqueApproverId } from "./opaque-id.mjs";
import { loadOrCreateKeyFile } from "./key-file.mjs";
import { describeThrown } from "./safe-throw.mjs";

import { intrinsics } from "noa-receipt";

// REDTEAM 2026-08-03 — bulk hardening of the published decision paths. Four CRITICALs came out of
// this package in two days, every one of them a LIVE builtin read that an attacker could replace
// after module load: an approval seat bound by `Array.prototype.includes`, a signature verified over
// bytes from `Buffer.concat`, a policy weakening hidden by `JSON.stringify`, an approval rule made
// invisible by `Array.isArray`. Auditing the remaining ~300 flagged reads one at a time is not a
// control — it is a race against the next person who adds one.
//
// So the builtins are taken from the kernel's module-load capture here too, whether or not each
// individual site is reachable today. Reachability is a property of the surrounding code, and the
// surrounding code changes.
const { jsonStringify } = intrinsics;


function loadOrCreateApproverSigner(keyFile) {
  return loadOrCreateKeyFile({
    keyFile,
    mintKeyPair: () => generateKeyPair(`noa-approve:${randomUUID()}`),
    callerLabel: "noa-approve",
  });
}

function parseArgs(argv) {
  if (argv.length === 0) throw new Error("usage: noa-approve <approve|deny> --id <id> --by <email> --pending-store <path> --key-file <path> [--reason <text>] [--receipt-log <path>] [--ttl-ms <n>]");
  const command = argv[0];
  if (command !== "approve" && command !== "deny") throw new Error(`noa-approve: unknown command "${command}" (expected "approve" or "deny")`);
  const opts = { id: null, by: null, reason: null, pendingStorePath: null, keyFile: null, receiptLogPath: null, ttlMs: DEFAULT_APPROVAL_TICKET_TTL_MS };
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[++i];
    if (flag === "--id") opts.id = value;
    else if (flag === "--by") opts.by = value;
    else if (flag === "--reason") opts.reason = value;
    else if (flag === "--pending-store") opts.pendingStorePath = value;
    else if (flag === "--key-file") opts.keyFile = value;
    else if (flag === "--receipt-log") opts.receiptLogPath = value;
    else if (flag === "--ttl-ms") opts.ttlMs = Number(value);
    else throw new Error(`noa-approve: unknown flag "${flag}"`);
  }
  if (!opts.id) throw new Error("noa-approve: --id is required");
  if (!opts.by) throw new Error("noa-approve: --by is required");
  if (!opts.pendingStorePath) throw new Error("noa-approve: --pending-store is required");
  if (!opts.keyFile) throw new Error("noa-approve: --key-file is required");
  refuseAliasedPaths(opts);
  return { command, opts };
}

/**
 * Refuses `--receipt-log` and `--pending-store` naming the SAME file. Appending signed receipts
 * into the pending store makes the store unloadable — `loadPendingIndex` refuses every line that
 * is not a known event, so the whole approval gate fails closed and every later call is refused
 * until an operator repairs the file. That is the safe direction, but it is a self-inflicted
 * outage the CLI can simply decline: the check costs two stats and runs before any durable act.
 *
 * String equality is not enough — a symlink, a hardlink, `./` prefixes or a trailing slash all
 * name one file under two spellings — so identical (dev, ino) is refused too. A stat that fails
 * means at least one path does not exist yet, which is the ordinary first-run case and no alias.
 */
function refuseAliasedPaths(opts) {
  if (!opts.receiptLogPath) return;
  const sameFile = `noa-approve: --receipt-log and --pending-store name the same file ("${opts.receiptLogPath}") — appending signed receipts into the pending store makes the store unloadable and refuses every later approval. Point them at two different files.`;
  if (opts.receiptLogPath === opts.pendingStorePath) throw new Error(sameFile);
  let store;
  let log;
  try {
    store = statSync(opts.pendingStorePath);
    log = statSync(opts.receiptLogPath);
  } catch {
    return; // one of them does not exist yet — the ordinary first-run case, not an alias
  }
  if (store.dev === log.dev && store.ino === log.ino) throw new Error(sameFile);
}

/**
 * `mode: 0o600` applies ONLY when this call CREATES the file, so it changes nothing for an
 * existing log and cannot break a log shared with another writer. It matters because the receipt
 * log holds validly-signed ALLOWED receipts, which are bearer material (see the ORDERING note
 * below), and the umask default would otherwise create that file world-readable.
 *
 * HONEST LIMIT, unchanged by this: unlike the pending store (config-artifact.mjs) this write is
 * NOT descriptor-hardened — no `O_NOFOLLOW`, no owner/mode check on an existing file. Routing it
 * through `appendConfigArtifact` would add all three, and is the obvious next step; it is not
 * taken here because that loader's owner test would newly refuse a receipt log legitimately shared
 * with a proxy running as a different uid (proxy.mjs documents that shared-log case), and that
 * compatibility question deserves its own change rather than riding along with this one.
 */
function appendReceiptLog(path, receipt) {
  if (path) appendFileSync(path, jsonStringify(receipt) + "\n", { encoding: "utf8", mode: 0o600 });
}

/**
 * The stderr line for the one failure this ordering deliberately leaves possible: the receipt log
 * write SUCCEEDED and the pending-store write then failed, so a signed decision receipt is sitting
 * in the log for a decision the store never recorded. Returns "" when there is nothing to say, so
 * the caller keeps exactly one stderr write.
 */
function orphanedLogWarning(receiptLogPath, kind) {
  if (kind === null) return "";
  return (
    `noa-approve: WARNING — the signed ${kind} receipt was ALREADY appended to "${receiptLogPath}" ` +
    `before this failure, and nothing was recorded in the pending store. No decision path in this ` +
    `repo reads a receipt log, so that line authorizes nothing on its own — but it is valid signed ` +
    `bearer material with no expiry of its own (the ticket TTL lives only in the store event), so ` +
    `anyone who can WRITE the pending store could replay it there later. Treat the log line as live ` +
    `until the decision is resolved.\n`
  );
}

/**
 * Runs one approve/deny invocation. Returns an exit code (0/1) — NEVER throws, NEVER calls
 * `process.exit` — so this is directly unit-testable in-process. Only the bottom of this file
 * touches real `process.argv`/`process.exit`.
 */
export function runApproveCli(argv) {
  let command, opts;
  try {
    ({ command, opts } = parseArgs(argv));
  } catch (err) {
    process.stderr.write(`${describeThrown(err)}\n`);
    return 1;
  }

  let record;
  try {
    // Records are keyed by (sessionId, id) — a receipt id alone (e.g. "rcpt_0") is not globally
    // unique — so look the human's --id up by scanning for its receipt id rather than a bare
    // Map.get(). In the normal one-session-per-file case there is exactly one match; a store shared
    // by several sessions that each minted the same receipt id is genuinely ambiguous and refused
    // (fail-closed: approve the WRONG session's request is worse than asking the operator to split).
    const matches = [...loadPendingIndex(opts.pendingStorePath).values()].filter((r) => r.id === opts.id);
    if (matches.length === 0) throw new PendingStoreError(`no pending record for id "${opts.id}"`);
    if (matches.length > 1) throw new PendingStoreError(`id "${opts.id}" is ambiguous across ${matches.length} sessions in this pending store — this file is shared by more than one session; resolve them in separate pending stores`);
    record = matches[0];
    if (record.status !== "pending") throw new PendingStoreError(`id "${opts.id}" is not awaiting a decision (status "${record.status}")`);
  } catch (err) {
    process.stderr.write(`noa-approve: ${describeThrown(err)}\n`);
    return 1;
  }

  let signer;
  try {
    const kp = loadOrCreateApproverSigner(opts.keyFile);
    signer = { kid: kp.kid, privateKey: kp.privateKey };
  } catch (err) {
    process.stderr.write(`noa-approve: ${describeThrown(err)}\n`);
    return 1;
  }

  const ts = new Date().toISOString();
  // D8 / GDPR-CCPA (THREAT-MODEL-ADDENDUM §5): the raw `--by` email is a low-entropy PII identifier and
  // MUST NOT enter the SIGNED receipt bytes. Pseudonymize it to a deterministic, tenant-scoped, opaque
  // `hmac-sha256:` id (opaque-id.mjs) — the same opaque shape the mobile/HTTP path already uses (a device
  // kid). Tenant is read off the DEFERRED hold so the id de-correlates across tenants. The raw email is
  // retained NOWHERE (neither signed nor local) — the operator supplied it on their own command line.
  const by = `HUMAN:${opaqueApproverId(opts.by, record.tenant)}`;

  // ── ORDERING IS THE CONTROL (reproduced 2026-08-12 against the real proxy, not theoretical) ────
  // The pending-store write is what makes a decision LIVE: an "approved" event mints the single-use
  // ticket the proxy consumes on the agent's retry, and the held action then EXECUTES. So every
  // other step that can fail has to fail BEFORE it.
  //
  // The pre-fix order was `recordApproved(...)` and only then `appendReceiptLog(...)`, both inside
  // one try that returns exit 1. Pointing `--receipt-log` at a DIRECTORY made the log write throw
  // EISDIR: the approver's shell reported exit 1 — "the approval failed" — while the pending store
  // already held `created, approved`, and the retried tool call executed a 7000-minor-unit transfer.
  // The approver was told the approval failed and the money moved. The deny branch had the mirror
  // shape: a denial durably recorded while its own log write fails is reported to the operator as a
  // denial that did not happen.
  //
  // Fixed by making the pending-store write the LAST FALLIBLE step in BOTH branches.
  //
  // WHAT THE RESIDUAL ACTUALLY IS — stated precisely, because an earlier version of this comment
  // said the leftover log line "leaves the action STILL HELD", and a review reproduced that that is
  // only half true. The literal half holds and was verified: NO decision path in this repo reads a
  // receipt log (the pending store's only consumers are pending-store.mjs, this file, index.mjs and
  // mcp-proxy's create-proxy-server.mjs; proxy.mjs's appender is write-only), so an orphaned line
  // authorizes nothing by itself. The absolute half is FALSE: the orphan is a validly-signed
  // ALLOWED receipt and it carries NO expiry of its own — the TTL and the ticket live only in the
  // store EVENT, and `buildApprovalReceipt` mints the ticket outside the signed bytes. A same-uid
  // writer of the pending store can therefore append a crafted "approved" event carrying that
  // orphan and a self-minted ticket, and pending-store.mjs:118-129 deliberately folds "approved"
  // onto a DENIED record — so a request the human actively denied becomes consumable. Severity is
  // LOW (it is an action the human genuinely signed once, and it needs the same-uid pending-store
  // writer that pending-store.mjs's own docstring already declares out of scope for content
  // defence), but the artifact is NOT inert and no comment here should say it is. The failing path
  // now says so on stderr — see orphanedLogWarning above.
  //
  // "LAST FALLIBLE", not "last durable": `appendConfigArtifact` (config-artifact.mjs) does
  // open -> writeFileSync -> close with NO fsync, while the sibling file-session-store.mjs:280-297
  // does fsync and documents why. So a power loss can still lose a returned "approved". The safe
  // direction holds (a lost approval leaves the action held), but the two stores in this perimeter
  // sit at different durability bars, and closing that means adding the fsync in
  // config-artifact.mjs — a shared loader this change does not own.
  let successLine = "";
  let orphanKind = null; // set once the LOG write has succeeded, cleared once the STORE write has
  try {
    if (command === "approve") {
      const { receipt, ticket, ticketExpiresAt } = buildApprovalReceipt({ deferredReceipt: record.deferredReceipt, by, ts, signer, ticketTtlMs: opts.ttlMs });
      appendReceiptLog(opts.receiptLogPath, receipt);
      if (opts.receiptLogPath) orphanKind = "approval";
      successLine = `APPROVED ${opts.id} -> ${receipt.id} (ticket expires ${ticketExpiresAt})\n`;
      // LAST fallible step. `tenant`/`sessionId: record.{tenant,sessionId}` — read back off the
      // DEFERRED hold so this "approved" event folds onto the SAME (tenant, sessionId, id) record it
      // approves (see pending-store's recordKeyOf). The ticket is live from this line onward.
      recordApproved(opts.pendingStorePath, { id: opts.id, by, ticket, ticketExpiresAt, allowedReceipt: receipt, tenant: record.tenant, sessionId: record.sessionId, ts });
      orphanKind = null;
    } else {
      // D8: the free-text `--reason` is NOT passed into the signed receipt (buildDenialReceipt fixes
      // ruleId to "human-denied"). It is kept only in the LOCAL, non-signed pending-store index below
      // (recordDenied), for operator audit — never in the signed, hash-chained bytes.
      const { receipt } = buildDenialReceipt({ deferredReceipt: record.deferredReceipt, by, ts, signer });
      appendReceiptLog(opts.receiptLogPath, receipt);
      if (opts.receiptLogPath) orphanKind = "denial";
      successLine = `DENIED ${opts.id} -> ${receipt.id}\n`;
      // LAST fallible step — same ordering rule as the approve branch above.
      recordDenied(opts.pendingStorePath, { id: opts.id, by, reason: opts.reason, deniedReceipt: receipt, tenant: record.tenant, sessionId: record.sessionId, ts });
      orphanKind = null;
    }
  } catch (err) {
    process.stderr.write(`noa-approve: ${describeThrown(err)}\n${orphanedLogWarning(opts.receiptLogPath, orphanKind)}`);
    return 1;
  }

  // OUTSIDE the try ON PURPOSE. Past this point the decision is already durable, so a failure to
  // PRINT it is a terminal problem, never an approval problem — reporting it as exit 1 would
  // re-create the exact lie this fix removes, one step later. Say so on stderr and still exit 0,
  // because the ticket really is live.
  try {
    process.stdout.write(successLine);
  } catch (err) {
    process.stderr.write(`noa-approve: the decision WAS recorded, but writing the confirmation line failed (${describeThrown(err)}) — treat this run as successful\n`);
  }
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(runApproveCli(process.argv.slice(2)));
}
