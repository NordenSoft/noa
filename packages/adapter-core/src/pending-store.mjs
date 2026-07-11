/**
 * pending-store.mjs — the OPERATIONAL index for outstanding human-approval requests.
 *
 * Newline-delimited JSON (JSONL), append-only, event-sourced: current state of one request is
 * the fold of every line sharing its record identity — (tenant, sessionId, id) when session-scoped,
 * else the bare receipt id (see recordKeyOf). This is an OPERATIONAL INDEX ONLY — the CRYPTOGRAPHIC
 * record lives in the signed receipt chain (DEFERRED -> ALLOWED/BLOCKED -> EXECUTED). Honest
 * limit: if this file is lost, the receipt chain remains the source of truth; a lost entry just
 * means that ONE request can no longer be resolved through the CLI. No cross-process file lock in
 * v1 (CLI-driven scale) — the real atomicity backstop for double-consumption races is
 * createChainSessionStore's in-memory `advance()` (see session-store.mjs's `adoptApprovedReceipt`).
 *
 * FAIL-CLOSED LOADING: any corrupt NON-EMPTY line makes the whole load refuse (PendingStoreError)
 * — never a silent skip. "Corrupt" includes a line that does not parse as JSON, one missing a
 * string `id`, AND one naming an `event` this store does not recognize (see KNOWN_EVENTS). The
 * single-use property of a ticket lives in the LAST event of its record ("consumed"); a loader that
 * skipped a torn/corrupt/unrecognized line would silently fold the record back to its PREVIOUS state
 * ("approved"), making an already-spent ticket consumable a second time (a replay). Refusing the
 * whole store until an operator repairs the file is the same
 * policy the sibling file-backed session store uses: on a security-bearing file, an unreadable
 * store must halt, never guess.
 */
import { appendFileSync, readFileSync, existsSync } from "node:fs";

export class PendingStoreError extends Error {
  constructor(message) {
    super(message);
    this.name = "PendingStoreError";
  }
}

/** The complete set of event names this store understands. A parseable line whose `event` is NOT
 *  one of these is a corruption/tampering signal, NOT something to skip: silently ignoring an
 *  unrecognized event (e.g. a truncated "consume" for "consumed", or an injected junk event) would
 *  leave a record folded to its PREVIOUS state, which for an already-spent ticket means resurrecting
 *  it for a second use (replay). loadPendingIndex refuses the WHOLE load on any unknown event —
 *  same fail-closed policy as an unparseable line (see loadPendingIndex's docstring). */
const KNOWN_EVENTS = new Set(["created", "approved", "denied", "consumed"]);

/** The fold/lookup identity for a record: (tenant, sessionId, id) when the event carries a sessionId,
 *  else the bare receipt id (backward-compatible with every pre-session-scope caller and test).
 *  `tenant` is part of the key because a single receipt id AND a single sessionId are NOT globally
 *  unique across tenants — two DIFFERENT tenants that coincidentally share the same (sessionId, id)
 *  over one shared --pending-store file would otherwise fold into ONE record, letting tenant B's
 *  fresh "created" clobber/hide tenant A's live "approved" ticket (a cross-tenant integrity break).
 *  Every event (created/approved/denied/consumed) therefore carries `tenant`, so all events for one
 *  logical record produce the SAME key. JSON-encoded rather than string-concatenated so no crafted
 *  tenant/sessionId/id content can be made to collide two logically-distinct records into one (the
 *  same injectivity concern createChainSessionStore's own nested-Map tenant keying documents). A
 *  record minted WITH a sessionId and one minted WITHOUT are intentionally distinct keys even for the
 *  same receipt id — a given file is, in practice, either all-legacy or all-session-scoped. */
function recordKeyOf(ev) {
  return ev.sessionId == null ? ev.id : `noa-pending ${JSON.stringify([ev.tenant ?? null, ev.sessionId, ev.id])}`;
}

function appendEvent(path, event) {
  try {
    appendFileSync(path, JSON.stringify(event) + "\n", "utf8");
  } catch (err) {
    // FAIL-CLOSED (R4 rule): never let a write failure escape as a raw fs error — always a typed,
    // greppable PendingStoreError the caller can catch and turn into a DENY.
    throw new PendingStoreError(`pending-store: could not append to "${path}" (${err.message})`);
  }
}

/** Folds one record's ordered events into its current state, enforcing the transitions that a legit
 *  event log actually obeys. Two rules are FAIL-CLOSED (throw PendingStoreError, refusing the WHOLE
 *  load — identical posture to loadPendingIndex's unparseable-line / unrecognized-event refusal):
 *
 *    - "created" is legal ONLY as the FIRST event of a record (from null). A SECOND "created" on an
 *      EXISTING record is rejected: the old permissive fold reset it straight back to "pending",
 *      silently WIPING a real "approved" (its actionId/paramsHash/deferredReceipt too) — a self-
 *      inflicted lockout / availability DoS an attacker with pending-store write access could trigger
 *      (see create-proxy-server.mjs's "anyone able to WRITE the pending-store file" threat class).
 *    - "consumed" is legal ONLY from "approved": a "consumed" with no live approval before it can
 *      never spend a ticket that was never granted.
 *    - Every non-"created" event additionally requires an EXISTING record (a bare ORPHAN
 *      approved/denied/consumed with no prior "created" is rejected — out-of-order tampering).
 *
 *  "approved"/"denied" are, by contrast, permitted onto ANY existing record — INCLUDING a "consumed"
 *  one. That is deliberate and load-bearing, NOT a hole: the store is an append-only OPERATIONAL index,
 *  and the proxy consumes a ticket BEFORE it verifies the approver signature (create-proxy-server.mjs),
 *  so a FORGED approval legitimately BURNS the ticket ("consumed") and the operator then appends a
 *  fresh, genuine "approved" to recover — the exact created->approved->consumed->approved sequence the
 *  mcp-proxy Scenario-R smoke exercises. Rejecting it here would break that recovery. Crucially, a
 *  re-"approved" fold state is NOT a single-use replay: single-use is enforced CRYPTOGRAPHICALLY, not
 *  by this index — adoptApprovedReceipt (session-store.mjs) rejects any ALLOWED receipt whose
 *  seq/prevHash/segmentId no longer match the CURRENT chain head, so a resurrected/replayed approval
 *  simply consumes-then-fails-to-adopt ("session chain has moved on"), never executing twice (proven
 *  by Scenario-R's own replay assertions). The pending-store fold is an operational convenience; the
 *  signed receipt chain is the source of truth (see the module docstring).
 *  (Event names outside KNOWN_EVENTS never reach here — loadPendingIndex already refused those.) */
function foldEvents(events) {
  let state = null;
  for (const ev of events) {
    const from = state === null ? "(none)" : state.status;
    const invalid = (why) =>
      new PendingStoreError(
        `pending-store: invalid event sequence for id "${ev.id}" — a "${ev.event}" event on a record in "${from}" status (${why}) — refusing to load; repair or restore the file before resuming`,
      );
    if (ev.event === "created") {
      if (state !== null) throw invalid("a duplicate \"created\" would reset an approved/consumed ticket back to \"pending\" (self-lockout / DoS)");
      state = { id: ev.id, sessionId: ev.sessionId, tenant: ev.tenant, chain: ev.chain, agentId: ev.agentId, actionId: ev.actionId, paramsHash: ev.paramsHash, deferredReceipt: ev.deferredReceipt, status: "pending" };
    } else if (ev.event === "approved") {
      if (state === null) throw invalid("an \"approved\" event with no prior \"created\" record is an out-of-order/orphaned event");
      state = { ...state, status: "approved", by: ev.by, ticket: ev.ticket, ticketExpiresAt: ev.ticketExpiresAt, allowedReceipt: ev.allowedReceipt };
    } else if (ev.event === "denied") {
      if (state === null) throw invalid("a \"denied\" event with no prior \"created\" record is an out-of-order/orphaned event");
      state = { ...state, status: "denied", by: ev.by, reason: ev.reason, deniedReceipt: ev.deniedReceipt };
    } else if (ev.event === "consumed") {
      if (from !== "approved") throw invalid("only an \"approved\" ticket may be consumed (a \"consumed\" without a live approval before it can never spend an ungranted ticket)");
      state = { ...state, status: "consumed" };
    }
  }
  return state;
}

/**
 * Reads the WHOLE file and folds it into `Map<id, currentState>`. A missing file folds to an
 * empty Map (the very first recordDeferred legitimately targets a not-yet-existing path).
 *
 * FAIL-CLOSED on corruption (see the module docstring): a NON-EMPTY line that does not parse as
 * JSON, or parses to something without a string `id`, refuses the ENTIRE load with a typed
 * PendingStoreError naming the offending line. Silently skipping a torn line would fold a record
 * back to its previous state — concretely, a half-written "consumed" event would resurrect an
 * already-spent ticket for a second use (replay). Every caller (findOutstanding /
 * consumeApprovalTicket / the CLI) inherits the refusal, so a corrupt store can never approve,
 * consume, or execute anything until an operator repairs it.
 */
export function loadPendingIndex(path) {
  if (!existsSync(path)) return new Map();
  const byId = new Map();
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().length === 0) continue;
    let ev;
    try {
      ev = JSON.parse(line);
    } catch {
      throw new PendingStoreError(
        `pending-store: corrupt line ${i + 1} in "${path}" (not valid JSON) — refusing to load; repair or restore the file before resuming (fail-closed: a skipped torn line could resurrect a spent ticket)`,
      );
    }
    if (!ev || typeof ev !== "object" || typeof ev.id !== "string") {
      throw new PendingStoreError(
        `pending-store: corrupt line ${i + 1} in "${path}" (missing string "id") — refusing to load; repair or restore the file before resuming`,
      );
    }
    if (typeof ev.event !== "string" || !KNOWN_EVENTS.has(ev.event)) {
      // FAIL-CLOSED (see KNOWN_EVENTS): a parseable line naming an event this store does not
      // understand is refused outright — never silently skipped, which would fold a record back to
      // an earlier state and could resurrect an already-spent ticket for a replay.
      throw new PendingStoreError(
        `pending-store: corrupt line ${i + 1} in "${path}" (unrecognized event ${JSON.stringify(ev.event)}) — refusing to load; repair or restore the file before resuming`,
      );
    }
    // Record IDENTITY is (tenant, sessionId, id): a single receipt id (e.g. preCheck's seq-derived
    // "rcpt_0") is NOT globally unique — two independent sessions each begin their own chain at
    // seq 0 and both mint "rcpt_0", and two different TENANTS can likewise reuse the same (sessionId,
    // id). When distinct sessions/tenants share ONE pending-store file (one logical agent fronted by
    // two proxy processes over a shared --pending-store), keying purely by receipt id — or by
    // (sessionId, id) alone — would fold their events into one record, so one fresh "created" would
    // silently clobber another's live "approved". Composite-keying keeps them independent.
    // Backward-compatible: an event with NO sessionId (every pre-R4-session-scope caller, and every
    // existing test) falls back to keying by `id` alone — identical behavior to before.
    const key = recordKeyOf(ev);
    if (!byId.has(key)) byId.set(key, []);
    byId.get(key).push(ev);
  }
  const index = new Map();
  for (const [id, events] of byId) {
    const folded = foldEvents(events);
    if (folded) index.set(id, folded);
  }
  return index;
}

/** Records a fresh DEFERRED hold. Fail-closed: throws PendingStoreError on write failure.
 *  `sessionId` (optional) scopes the record to ONE session so a shared pending-store file never
 *  cross-folds two sessions that coincidentally minted the same receipt id (see recordKeyOf). */
export function recordDeferred(path, { deferredReceipt, tenant, agentId, sessionId, actionId, paramsHash, ts = new Date().toISOString() }) {
  appendEvent(path, { event: "created", id: deferredReceipt.id, sessionId, tenant, chain: deferredReceipt.scope.chain, agentId, actionId, paramsHash, ts, deferredReceipt });
}

/** Records the human's APPROVE decision + mints the ticket window. Fail-closed on write failure.
 *  `tenant` and `sessionId` MUST match the DEFERRED hold's own values (approve-cli reads them back
 *  off the loaded record) so this "approved" event folds onto the SAME (tenant, sessionId, id)
 *  record it approves (see recordKeyOf). */
export function recordApproved(path, { id, by, ticket, ticketExpiresAt, allowedReceipt, tenant, sessionId, ts = new Date().toISOString() }) {
  appendEvent(path, { event: "approved", id, tenant, sessionId, ts, by, ticket, ticketExpiresAt, allowedReceipt });
}

/** Records the human's DENY decision. Fail-closed on write failure. `tenant`+`sessionId` scope it to
 *  the same record as the DEFERRED hold (see recordApproved). */
export function recordDenied(path, { id, by, reason, deniedReceipt, tenant, sessionId, ts = new Date().toISOString() }) {
  appendEvent(path, { event: "denied", id, tenant, sessionId, ts, by, reason: reason ?? null, deniedReceipt });
}

/**
 * Consumes an approved-and-unexpired ticket: appends a "consumed" event and returns the folded
 * record (including `allowedReceipt`). FAIL-CLOSED on every disqualifying condition — unknown id,
 * wrong status (never-approved / already-denied / already-consumed), or expired ticket — always a
 * typed `PendingStoreError`. This is the SINGLE enforcement point for both "ticket-tekrar -> DENY"
 * (status check) and "TTL -> DENY" (expiry check).
 */
export function consumeApprovalTicket(path, id, now = Date.now(), { sessionId, tenant } = {}) {
  const record = loadPendingIndex(path).get(recordKeyOf({ id, sessionId, tenant }));
  if (!record) throw new PendingStoreError(`consumeApprovalTicket: no pending record for id "${id}"`);
  // FIX-H2 defense-in-depth: the loaded record MUST belong to the caller's tenant. For a session-scoped
  // record tenant is ALREADY baked into the fold key (recordKeyOf), so a wrong-tenant caller would
  // simply miss above ("no pending record"). This belt additionally covers the LEGACY no-sessionId path,
  // where recordKeyOf falls back to the bare id and tenant is NOT in the key — there, a caller claiming
  // a different tenant would otherwise fold onto, and consume, another tenant's ticket. `tenant != null`
  // keeps the pre-tenant callers (no tenant supplied) behaving exactly as before.
  if (tenant != null && record.tenant !== tenant) {
    throw new PendingStoreError(`consumeApprovalTicket: id "${id}"'s record belongs to a different tenant — refusing to consume (cross-tenant)`);
  }
  if (record.status !== "approved") {
    throw new PendingStoreError(`consumeApprovalTicket: id "${id}" is not in "approved" status (got "${record.status}")`);
  }
  // FAIL-CLOSED TTL (fixes a fail-OPEN edge): a missing/malformed ticketExpiresAt makes Date.parse
  // return NaN, and `NaN <= now` is always false — which would let a ticket with no valid expiry be
  // consumed FOREVER. A non-finite expiry is treated as already-expired: the safe direction is
  // "no valid expiry -> not consumable", never "no valid expiry -> never expires".
  const expiresAt = Date.parse(record.ticketExpiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    throw new PendingStoreError(`consumeApprovalTicket: id "${id}"'s ticket is expired or has no valid expiry (ticketExpiresAt=${JSON.stringify(record.ticketExpiresAt)})`);
  }
  appendEvent(path, { event: "consumed", id, tenant, sessionId, ts: new Date(now).toISOString() });
  return record;
}

/**
 * The single outstanding (status "pending" or "approved") record for a (tenant, agentId[, sessionId])
 * scope, or `null`. Used by the MCP proxy to block a session pending resolution. Does NOT itself
 * check ticket expiry — the caller always routes actual ticket-use through `consumeApprovalTicket`,
 * which is the one authoritative expiry check.
 *
 * `sessionId` (optional) narrows the scope to ONE session: without it (the pre-R4 behavior) a
 * second session sharing the same (tenant, agentId) — e.g. one logical agent fronted by two proxy
 * processes over a shared --pending-store — could SELECT and then consume/burn another session's
 * ticket via a coincidentally-identical retried call. With it, a foreign session never even sees a
 * ticket that isn't its own. When omitted, matching stays (tenant, agentId)-only, unchanged.
 */
export function findOutstanding(path, { tenant, agentId, sessionId }) {
  for (const record of loadPendingIndex(path).values()) {
    if (
      record.tenant === tenant &&
      record.agentId === agentId &&
      (sessionId === undefined || record.sessionId === sessionId) &&
      (record.status === "pending" || record.status === "approved")
    ) {
      return record;
    }
  }
  return null;
}
