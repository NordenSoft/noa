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
import { readFileSync, writeFileSync, appendFileSync, chmodSync, openSync, fstatSync, closeSync, constants as fsConstants } from "node:fs";
import { randomUUID } from "node:crypto";
import { generateKeyPair } from "noa-receipt";
import { loadPendingIndex, recordApproved, recordDenied, PendingStoreError } from "./pending-store.mjs";
import { buildApprovalReceipt, buildDenialReceipt, DEFAULT_APPROVAL_TICKET_TTL_MS } from "./approval-decision.mjs";
import { opaqueApproverId } from "./opaque-id.mjs";

// O_NOFOLLOW symlink-attack guard — ported verbatim from packages/mcp-proxy/src/proxy.mjs's
// loadOrCreateSigner (CWE-367). Duplicated, not imported — this CLI keeps its signing identity
// fully independent of the proxy's, so neither can be made to sign with the other's key.
const READONLY_NOFOLLOW = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);

function loadOrCreateApproverSigner(keyFile) {
  let fd = null;
  try {
    fd = openSync(keyFile, READONLY_NOFOLLOW);
  } catch (err) {
    if (err.code === "ELOOP") throw new Error(`noa-approve: --key-file "${keyFile}" is a symlink — refusing to follow it (CWE-367 symlink-attack guard).`);
    if (err.code !== "ENOENT") throw err;
  }
  if (fd !== null) {
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) throw new Error(`noa-approve: --key-file "${keyFile}" is not a regular file`);
      if ((st.mode & 0o077) !== 0) throw new Error(`noa-approve: --key-file "${keyFile}" is readable/writable by group or others (mode 0${(st.mode & 0o777).toString(8)}) — chmod 600 it first.`);
      const raw = JSON.parse(readFileSync(fd, "utf8"));
      if (!raw || typeof raw.kid !== "string" || typeof raw.privateKey !== "string" || typeof raw.publicKey !== "string") {
        throw new Error(`noa-approve: --key-file "${keyFile}" is malformed (expected { kid, privateKey, publicKey })`);
      }
      return raw;
    } finally {
      closeSync(fd);
    }
  }
  const kp = generateKeyPair(`noa-approve:${randomUUID()}`);
  const record = { kid: kp.kid, privateKey: kp.privateKey, publicKey: kp.publicKey };
  writeFileSync(keyFile, JSON.stringify(record, null, 2), { mode: 0o600, flag: "wx" });
  chmodSync(keyFile, 0o600);
  return record;
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
  return { command, opts };
}

function appendReceiptLog(path, receipt) {
  if (path) appendFileSync(path, JSON.stringify(receipt) + "\n", "utf8");
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
    process.stderr.write(`${err.message}\n`);
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
    process.stderr.write(`noa-approve: ${err.message}\n`);
    return 1;
  }

  let signer;
  try {
    const kp = loadOrCreateApproverSigner(opts.keyFile);
    signer = { kid: kp.kid, privateKey: kp.privateKey };
  } catch (err) {
    process.stderr.write(`noa-approve: ${err.message}\n`);
    return 1;
  }

  const ts = new Date().toISOString();
  // D8 / GDPR-CCPA (THREAT-MODEL-ADDENDUM §5): the raw `--by` email is a low-entropy PII identifier and
  // MUST NOT enter the SIGNED receipt bytes. Pseudonymize it to a deterministic, tenant-scoped, opaque
  // `hmac-sha256:` id (opaque-id.mjs) — the same opaque shape the mobile/HTTP path already uses (a device
  // kid). Tenant is read off the DEFERRED hold so the id de-correlates across tenants. The raw email is
  // retained NOWHERE (neither signed nor local) — the operator supplied it on their own command line.
  const by = `HUMAN:${opaqueApproverId(opts.by, record.tenant)}`;

  try {
    if (command === "approve") {
      const { receipt, ticket, ticketExpiresAt } = buildApprovalReceipt({ deferredReceipt: record.deferredReceipt, by, ts, signer, ticketTtlMs: opts.ttlMs });
      // `tenant`/`sessionId: record.{tenant,sessionId}` — read back off the DEFERRED hold so this
      // "approved" event folds onto the SAME (tenant, sessionId, id) record it approves (see
      // pending-store's recordKeyOf).
      recordApproved(opts.pendingStorePath, { id: opts.id, by, ticket, ticketExpiresAt, allowedReceipt: receipt, tenant: record.tenant, sessionId: record.sessionId, ts });
      appendReceiptLog(opts.receiptLogPath, receipt);
      process.stdout.write(`APPROVED ${opts.id} -> ${receipt.id} (ticket expires ${ticketExpiresAt})\n`);
    } else {
      // D8: the free-text `--reason` is NOT passed into the signed receipt (buildDenialReceipt fixes
      // ruleId to "human-denied"). It is kept only in the LOCAL, non-signed pending-store index below
      // (recordDenied), for operator audit — never in the signed, hash-chained bytes.
      const { receipt } = buildDenialReceipt({ deferredReceipt: record.deferredReceipt, by, ts, signer });
      recordDenied(opts.pendingStorePath, { id: opts.id, by, reason: opts.reason, deniedReceipt: receipt, tenant: record.tenant, sessionId: record.sessionId, ts });
      appendReceiptLog(opts.receiptLogPath, receipt);
      process.stdout.write(`DENIED ${opts.id} -> ${receipt.id}\n`);
    }
    return 0;
  } catch (err) {
    process.stderr.write(`noa-approve: ${err.message}\n`);
    return 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(runApproveCli(process.argv.slice(2)));
}
