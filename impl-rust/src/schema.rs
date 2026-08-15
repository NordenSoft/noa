//! Strict structural validation of a single NOA Receipt v0.1 — faithful port of impl-py
//! `validate_receipt_shape` / `src/schema.ts validateReceiptShape`. `additionalProperties:false` at
//! every level (an unknown field is a smuggling channel and MUST be rejected), required-field presence,
//! enums, and RFC 3339 / hash formats. Returns `Err(first-error)` on any violation; the caller maps that
//! to MALFORMED. Never panics (fail-closed) — every access is type-guarded first.
//!
//! ASCII-only discipline: digit classes are matched against `b'0'..=b'9'` (never a Unicode "digit"
//! category) so a crypto-genuine receipt carrying a Unicode-digit `ts` is MALFORMED, matching the
//! ECMA-262 `\d` dialect the normative JSON-Schema uses.

use crate::json::{Json, SAFE_INT_MAX};

const RECEIPT_SPEC: &str = "noa.receipt/0.1";
const RISK_CLASSES: [&str; 5] = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE"];
const PRINCIPALS: [&str; 4] = ["HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM"];
const MODES: [&str; 4] = ["off", "shadow", "approvals_on", "on"];
const VERDICTS: [&str; 7] = [
    "ALLOWED",
    "BLOCKED",
    "DEFERRED",
    "EXECUTED",
    "FAILED",
    "ROLLED_BACK",
    "SIMULATED",
];

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `^sha256:[0-9a-f]{64}$`
pub fn is_hash(s: &str) -> bool {
    s.strip_prefix("sha256:").map(is_hex64).unwrap_or(false)
}

/// `^(sha256|hmac-sha256):[0-9a-f]{64}$`
fn is_params_hash(s: &str) -> bool {
    if let Some(r) = s.strip_prefix("sha256:") {
        is_hex64(r)
    } else if let Some(r) = s.strip_prefix("hmac-sha256:") {
        is_hex64(r)
    } else {
        false
    }
}

fn take_digits(b: &[u8], i: &mut usize, count: usize) -> bool {
    for _ in 0..count {
        if *i >= b.len() || !b[*i].is_ascii_digit() {
            return false;
        }
        *i += 1;
    }
    true
}

fn take_lit(b: &[u8], i: &mut usize, allowed: &[u8]) -> bool {
    if *i < b.len() && allowed.contains(&b[*i]) {
        *i += 1;
        true
    } else {
        false
    }
}

/// `^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})$`
/// full-match, ASCII digits only. LEXICAL FORM ONLY — month 13 and hour 99 match `[0-9]{2}`. A
/// trust artifact's timestamp is validated with [`is_rfc3339_instant`]; this alone is not enough.
pub fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    if !take_digits(b, &mut i, 4) {
        return false;
    }
    if !take_lit(b, &mut i, b"-") {
        return false;
    }
    if !take_digits(b, &mut i, 2) {
        return false;
    }
    if !take_lit(b, &mut i, b"-") {
        return false;
    }
    if !take_digits(b, &mut i, 2) {
        return false;
    }
    if !take_lit(b, &mut i, b"Tt") {
        return false;
    }
    if !take_digits(b, &mut i, 2) {
        return false;
    }
    if !take_lit(b, &mut i, b":") {
        return false;
    }
    if !take_digits(b, &mut i, 2) {
        return false;
    }
    if !take_lit(b, &mut i, b":") {
        return false;
    }
    if !take_digits(b, &mut i, 2) {
        return false;
    }
    // optional fractional seconds: `.` then 1..=9 digits
    if i < n && b[i] == b'.' {
        i += 1;
        let mut cnt = 0;
        while i < n && b[i].is_ascii_digit() && cnt < 9 {
            i += 1;
            cnt += 1;
        }
        if cnt < 1 {
            return false;
        }
    }
    // timezone: Z/z OR [+-]dd:dd
    if i < n && (b[i] == b'Z' || b[i] == b'z') {
        i += 1;
    } else if i < n && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
        if !take_digits(b, &mut i, 2) {
            return false;
        }
        if !take_lit(b, &mut i, b":") {
            return false;
        }
        if !take_digits(b, &mut i, 2) {
            return false;
        }
    } else {
        return false;
    }
    i == n
}

/// Real length of `month` in `year`; 0 for an out-of-range month, so any day then fails.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// The two ASCII digits at `i` as a number. The caller has already proven they ARE digits.
fn two(b: &[u8], i: usize) -> u32 {
    (b[i] - b'0') as u32 * 10 + (b[i + 1] - b'0') as u32
}

/// RFC 3339 §5.6 `date-time`: the LEXICAL form [`is_rfc3339`] accepts PLUS the field ranges the
/// ABNF's own comments impose (month 01-12, mday by month and year including leap years, hour
/// 00-23, minute 00-59, second 00-60, numoffset hours 00-23 / minutes 00-59). Mirrors
/// impl-py `_is_rfc3339_instant` / `src/scan.ts isRfc3339Instant`.
///
/// The pattern alone accepted `2026-13-45T99:99:99.000Z` — month 13, day 45, hour 99 — on a SIGNED,
/// chain-valid CRITICAL receipt, in all five implementations. A `ts` that denotes no instant cannot
/// be ordered against its neighbours; it is a "when" that can be argued both ways after the fact,
/// and it is decidable with NO key material at all, so it belongs in the shape validator.
///
/// SECOND 60 IS ACCEPTED ON PURPOSE: a leap second is a real instant that has really occurred 27
/// times, and which UTC days carry one is an IERS table, not a property of the string.
pub fn is_rfc3339_instant(s: &str) -> bool {
    if !is_rfc3339(s) {
        return false;
    }
    let b = s.as_bytes();
    let year = two(b, 0) * 100 + two(b, 2);
    let month = two(b, 5);
    let day = two(b, 8);
    if month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) {
        return false;
    }
    if two(b, 11) > 23 || two(b, 14) > 59 || two(b, 17) > 60 {
        // 60 is the leap second, and it is legal
        return false;
    }
    // The lexical check already proved the tail is EITHER a single Z/z OR exactly ±HH:MM.
    let n = b.len();
    if b[n - 1] == b'Z' || b[n - 1] == b'z' {
        return true;
    }
    two(b, n - 5) <= 23 && two(b, n - 2) <= 59
}

/// `additionalProperties:false` + required presence at one object level.
fn check_exact_keys(
    obj: &[(String, Json)],
    required: &[&str],
    optional: &[&str],
    path: &str,
) -> Result<(), String> {
    for (k, _) in obj {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Err(format!("{path}: unknown field \"{k}\""));
        }
    }
    for r in required {
        if !obj.iter().any(|(k, _)| k == r) {
            return Err(format!("{path}: missing required field \"{r}\""));
        }
    }
    Ok(())
}

fn is_nonempty_str(v: Option<&Json>) -> bool {
    matches!(v, Some(Json::Str(s)) if !s.is_empty())
}

/// Validate one receipt. `Ok(())` iff structurally valid; `Err` carries the first violation.
pub fn validate_receipt_shape(value: &Json) -> Result<(), String> {
    let r = match value {
        Json::Object(o) => o,
        _ => return Err("receipt: not an object".into()),
    };

    check_exact_keys(
        r,
        &[
            "spec",
            "id",
            "ts",
            "scope",
            "agent",
            "action",
            "governance",
            "chain",
            "sig",
        ],
        &[],
        "receipt",
    )?;

    if value.get("spec").and_then(|v| v.as_str()) != Some(RECEIPT_SPEC) {
        return Err(format!("receipt.spec: must be \"{RECEIPT_SPEC}\""));
    }
    match value.get("id") {
        Some(Json::Str(s)) if !s.is_empty() && s.chars().count() <= 128 => {}
        _ => return Err("receipt.id: non-empty string <=128 chars".into()),
    }
    // R5: is_rfc3339_instant, not the bare lexical form — a `ts` matching `[0-9]{2}` for a month is
    // not a moment in time. See that function for why second 60 (a leap second) stays accepted.
    match value.get("ts") {
        Some(Json::Str(s)) if is_rfc3339_instant(s) => {}
        _ => return Err("receipt.ts: must be RFC 3339 UTC timestamp".into()),
    }

    // scope
    match value.get("scope") {
        Some(scope @ Json::Object(so)) => {
            check_exact_keys(so, &["chain"], &["tenant"], "receipt.scope")?;
            if !is_nonempty_str(scope.get("chain")) {
                return Err("receipt.scope.chain: non-empty string".into());
            }
            if let Some(t) = scope.get("tenant") {
                if !matches!(t, Json::Str(_)) {
                    return Err("receipt.scope.tenant: string".into());
                }
            }
        }
        _ => return Err("receipt.scope: object required".into()),
    }

    // agent
    match value.get("agent") {
        Some(agent @ Json::Object(ao)) => {
            check_exact_keys(ao, &["id", "principal"], &["model"], "receipt.agent")?;
            if !is_nonempty_str(agent.get("id")) {
                return Err("receipt.agent.id: non-empty string".into());
            }
            match agent.get("principal").and_then(|v| v.as_str()) {
                Some(p) if PRINCIPALS.contains(&p) => {}
                _ => return Err("receipt.agent.principal: invalid enum".into()),
            }
            if let Some(m) = agent.get("model") {
                if !matches!(m, Json::Str(_) | Json::Null) {
                    return Err("receipt.agent.model: string or null".into());
                }
            }
        }
        _ => return Err("receipt.agent: object required".into()),
    }

    // action
    match value.get("action") {
        Some(action @ Json::Object(aco)) => {
            check_exact_keys(
                aco,
                &["id", "canonical", "riskClass", "paramsHash", "reversible"],
                &["rollbackRef"],
                "receipt.action",
            )?;
            if !is_nonempty_str(action.get("id")) {
                return Err("receipt.action.id: non-empty string".into());
            }
            if !is_nonempty_str(action.get("canonical")) {
                return Err("receipt.action.canonical: non-empty string".into());
            }
            match action.get("riskClass").and_then(|v| v.as_str()) {
                Some(rc) if RISK_CLASSES.contains(&rc) => {}
                _ => return Err("receipt.action.riskClass: invalid enum".into()),
            }
            match action.get("paramsHash") {
                Some(Json::Str(s)) if is_params_hash(s) => {}
                _ => {
                    return Err(
                        "receipt.action.paramsHash: must match (sha256|hmac-sha256):<64 hex>".into(),
                    )
                }
            }
            if action.get("reversible").and_then(|v| v.as_bool()).is_none() {
                return Err("receipt.action.reversible: boolean".into());
            }
            if let Some(rb) = action.get("rollbackRef") {
                if !matches!(rb, Json::Str(_) | Json::Null) {
                    return Err("receipt.action.rollbackRef: string or null".into());
                }
            }
        }
        _ => return Err("receipt.action: object required".into()),
    }

    // governance
    match value.get("governance") {
        Some(gov @ Json::Object(go)) => {
            check_exact_keys(
                go,
                &["mode", "verdict", "sandboxed"],
                &["ruleId", "approval", "compliance"],
                "receipt.governance",
            )?;
            match gov.get("mode").and_then(|v| v.as_str()) {
                Some(m) if MODES.contains(&m) => {}
                _ => return Err("receipt.governance.mode: invalid enum".into()),
            }
            match gov.get("verdict").and_then(|v| v.as_str()) {
                Some(vd) if VERDICTS.contains(&vd) => {}
                _ => return Err("receipt.governance.verdict: invalid enum".into()),
            }
            if gov.get("sandboxed").and_then(|v| v.as_bool()).is_none() {
                return Err("receipt.governance.sandboxed: boolean".into());
            }
            if let Some(rid) = gov.get("ruleId") {
                if !matches!(rid, Json::Str(_) | Json::Null) {
                    return Err("receipt.governance.ruleId: string or null".into());
                }
            }
            if let Some(ap) = gov.get("approval") {
                if !ap.is_object() && !matches!(ap, Json::Null) {
                    return Err("receipt.governance.approval: object or null".into());
                }
                if let Json::Object(apo) = ap {
                    check_exact_keys(apo, &["by", "at"], &[], "receipt.governance.approval")?;
                    if !matches!(ap.get("by"), Some(Json::Str(_))) {
                        return Err("receipt.governance.approval.by: string".into());
                    }
                    match ap.get("at") {
                        Some(Json::Str(s)) if is_rfc3339_instant(s) => {}
                        _ => return Err("receipt.governance.approval.at: RFC 3339 UTC".into()),
                    }
                }
            }
            if let Some(c) = gov.get("compliance") {
                if !c.is_object() && !matches!(c, Json::Null) {
                    return Err("receipt.governance.compliance: object or null".into());
                }
                if let Json::Object(co) = c {
                    check_exact_keys(
                        co,
                        &["policyHash", "readSetHash", "inputsHash"],
                        &["verdict"],
                        "receipt.governance.compliance",
                    )?;
                    for k in ["policyHash", "readSetHash", "inputsHash"] {
                        match c.get(k) {
                            Some(Json::Str(s)) if is_hash(s) => {}
                            _ => {
                                return Err(format!(
                                    "receipt.governance.compliance.{k}: sha256:<64 hex>"
                                ))
                            }
                        }
                    }
                    if let Some(cv) = c.get("verdict") {
                        match cv.as_str() {
                            Some("ALLOW") | Some("DENY") => {}
                            _ => {
                                return Err(
                                    "receipt.governance.compliance.verdict: must be \"ALLOW\" or \"DENY\""
                                        .into(),
                                )
                            }
                        }
                    }
                }
            }
        }
        _ => return Err("receipt.governance: object required".into()),
    }

    // ── CROSS-FIELD COHERENCE — A SIGNED RECEIPT MAY NOT CONTRADICT ITSELF ───────────────────────
    // Every check above reads ONE field. A receipt can satisfy all of them and still argue both
    // ways: `agent.principal: "SANDBOX_SIM"` (the actor was the sandbox simulator) beside
    // `governance.sandboxed: false` (this really happened), on a CRITICAL `wire.transfer`, signed
    // and chain-valid. Reproduced across all five verifiers, 25 of 25 VALID, before this block.
    //
    // They live in the SHAPE validator, not on the signature path, for the same reason an unknown
    // smuggled field does: they are decidable with NO key material at all. Mirrors impl-py
    // `validate_receipt_shape` / `src/schema.ts validateReceiptShapeParsed`.
    //
    // Each rule is ONE-DIRECTIONAL, because the converse is legitimate: a SERVICE agent may run
    // inside a sandbox (`conformance/golden/0.3.0/multi/chain.json` holds such a VALID receipt), and
    // a reversible action need not carry a `rollbackRef`. Every field read here already passed its
    // own type check above, so a malformed receipt reports its one real defect.
    {
        let principal = value.get("agent").and_then(|a| a.get("principal")).and_then(|v| v.as_str());
        let verdict = value.get("governance").and_then(|g| g.get("verdict")).and_then(|v| v.as_str());
        let sandboxed = value.get("governance").and_then(|g| g.get("sandboxed")).and_then(|v| v.as_bool());
        let reversible = value.get("action").and_then(|a| a.get("reversible")).and_then(|v| v.as_bool());
        let rollback_present = matches!(
            value.get("action").and_then(|a| a.get("rollbackRef")),
            Some(v) if !matches!(v, Json::Null)
        );
        // R1. Names the SANDBOX SIMULATOR as the actor while denying it was a simulation.
        if principal == Some("SANDBOX_SIM") && sandboxed == Some(false) {
            return Err(
                "receipt.governance.sandboxed: must be true when agent.principal is \"SANDBOX_SIM\"".into(),
            );
        }
        // R2. Records a SIMULATED outcome while denying it was a simulation.
        if verdict == Some("SIMULATED") && sandboxed == Some(false) {
            return Err(
                "receipt.governance.sandboxed: must be true when governance.verdict is \"SIMULATED\"".into(),
            );
        }
        // R3. An action declared impossible to undo, carrying the reference used to undo it.
        if reversible == Some(false) && rollback_present {
            return Err(
                "receipt.action.rollbackRef: must be absent or null when action.reversible is false".into(),
            );
        }
        // R4. Says the action WAS undone while declaring it could not be.
        if verdict == Some("ROLLED_BACK") && reversible == Some(false) {
            return Err(
                "receipt.action.reversible: must be true when governance.verdict is \"ROLLED_BACK\"".into(),
            );
        }
    }

    // chain
    match value.get("chain") {
        Some(ch @ Json::Object(cho)) => {
            check_exact_keys(cho, &["seq", "prevHash", "hash"], &[], "receipt.chain")?;
            match ch.get("seq").and_then(|v| v.as_int()) {
                Some(seq) if (0..=SAFE_INT_MAX).contains(&seq) => {}
                _ => return Err("receipt.chain.seq: non-negative safe integer".into()),
            }
            match ch.get("prevHash") {
                Some(Json::Null) => {}
                Some(Json::Str(s)) if is_hash(s) => {}
                _ => return Err("receipt.chain.prevHash: sha256:<64 hex> or null".into()),
            }
            match ch.get("hash") {
                Some(Json::Str(s)) if is_hash(s) => {}
                _ => return Err("receipt.chain.hash: sha256:<64 hex>".into()),
            }
        }
        _ => return Err("receipt.chain: object required".into()),
    }

    // sig (mandatory)
    match value.get("sig") {
        Some(sig @ Json::Object(sgo)) => {
            check_exact_keys(sgo, &["alg", "kid", "value"], &[], "receipt.sig")?;
            if sig.get("alg").and_then(|v| v.as_str()) != Some("ed25519") {
                return Err("receipt.sig.alg: must be \"ed25519\"".into());
            }
            if !is_nonempty_str(sig.get("kid")) {
                return Err("receipt.sig.kid: non-empty string".into());
            }
            if !is_nonempty_str(sig.get("value")) {
                return Err("receipt.sig.value: non-empty string".into());
            }
        }
        _ => return Err("receipt.sig: object required (signatures are mandatory in v0.1)".into()),
    }

    Ok(())
}

// ── CROSS-FIELD COHERENCE (R1-R5) + the real-instant timestamp rule ──────────────────────────────
//
// A receipt can satisfy every single-field check and still be a statement that argues both ways:
// `agent.principal: "SANDBOX_SIM"` (the actor was the sandbox simulator) beside
// `governance.sandboxed: false` (this really happened), on a CRITICAL `wire.transfer`. Five such
// receipts — signed, chain-valid, hash-genuine — verified VALID 25 times out of 25 across the five
// shipped verifiers before these rules landed.
//
// Every rule is tested BOTH ways. A rule that refuses everything is an outage, not a control, so
// each contradiction is paired with a NEGATIVE CONTROL in which the same two fields agree.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    /// One structurally-complete receipt. `chain.hash`/`sig.value` are well-formed but not
    /// recomputed — `validate_receipt_shape` runs BEFORE any hashing (it is the step that decides
    /// MALFORMED), so shape is the only thing under test.
    fn receipt(ts: &str, principal: &str, verdict: &str, sandboxed: bool, reversible: bool, rollback: Option<&str>) -> String {
        let h = format!("sha256:{}", "a".repeat(64));
        let rb = match rollback {
            Some(v) => format!("\"{v}\""),
            None => "null".to_string(),
        };
        format!(
            "{{\"spec\":\"noa.receipt/0.1\",\"id\":\"rcpt_1\",\"ts\":\"{ts}\",\
             \"scope\":{{\"tenant\":\"acme\",\"chain\":\"c1\"}},\
             \"agent\":{{\"id\":\"agent-1\",\"model\":null,\"principal\":\"{principal}\"}},\
             \"action\":{{\"id\":\"wire.transfer\",\"canonical\":\"wire.transfer\",\"riskClass\":\"CRITICAL\",\
             \"paramsHash\":\"{h}\",\"reversible\":{reversible},\"rollbackRef\":{rb}}},\
             \"governance\":{{\"mode\":\"on\",\"verdict\":\"{verdict}\",\"ruleId\":\"r\",\"approval\":null,\"sandboxed\":{sandboxed}}},\
             \"chain\":{{\"seq\":0,\"prevHash\":null,\"hash\":\"{h}\"}},\
             \"sig\":{{\"alg\":\"ed25519\",\"kid\":\"k1\",\"value\":\"AAAA\"}}}}"
        )
    }

    fn shape_ok(js: &str) -> bool {
        let v = parse(js).expect("fixture did not parse");
        validate_receipt_shape(&v).is_ok()
    }

    const OK_TS: &str = "2026-08-14T00:00:00.000Z";

    #[test]
    fn coherence_rules() {
        // The baseline every case below is a one-field edit away from.
        assert!(shape_ok(&receipt(OK_TS, "SERVICE", "EXECUTED", false, true, None)), "baseline must be VALID");

        // R1 — the actor is the sandbox simulator while the receipt denies it was a simulation.
        assert!(!shape_ok(&receipt(OK_TS, "SANDBOX_SIM", "EXECUTED", false, true, None)));
        assert!(shape_ok(&receipt(OK_TS, "SANDBOX_SIM", "EXECUTED", true, true, None)), "R1 control");
        // …and it is ONE-DIRECTIONAL: a SERVICE agent may legitimately run inside a sandbox.
        assert!(shape_ok(&receipt(OK_TS, "SERVICE", "EXECUTED", true, true, None)), "R1 one-directional");

        // R2 — a SIMULATED outcome while the receipt denies it was a simulation.
        assert!(!shape_ok(&receipt(OK_TS, "SERVICE", "SIMULATED", false, true, None)));
        assert!(shape_ok(&receipt(OK_TS, "SERVICE", "SIMULATED", true, true, None)), "R2 control");

        // R3 — an action declared impossible to undo, carrying the reference used to undo it.
        assert!(!shape_ok(&receipt(OK_TS, "SERVICE", "EXECUTED", false, false, Some("snap_1"))));
        assert!(shape_ok(&receipt(OK_TS, "SERVICE", "EXECUTED", false, false, None)), "R3 control (null)");
        assert!(shape_ok(&receipt(OK_TS, "SERVICE", "EXECUTED", false, true, Some("snap_1"))), "R3 control (reversible)");

        // R4 — the receipt says the action WAS undone while declaring it could not be.
        assert!(!shape_ok(&receipt(OK_TS, "SERVICE", "ROLLED_BACK", false, false, None)));
        assert!(shape_ok(&receipt(OK_TS, "SERVICE", "ROLLED_BACK", false, true, Some("snap_1"))), "R4 control");

        // R5 — a `ts` with the SHAPE of RFC 3339 that denotes no instant.
        assert!(!shape_ok(&receipt("2026-13-45T99:99:99.000Z", "SERVICE", "EXECUTED", false, true, None)));
        assert!(shape_ok(&receipt("2026-06-30T23:59:60.000Z", "SERVICE", "EXECUTED", false, true, None)), "leap second");
    }

    /// The calendar layer, including the one acceptance that must never be "tightened" away: second
    /// 60. A leap second is a real instant that has really occurred 27 times, and refusing it would
    /// refuse a truthful receipt.
    #[test]
    fn rfc3339_instant() {
        for s in [
            "2026-06-20T07:30:54Z",
            "2026-06-20t07:30:54z", // RFC 3339 §5.6 permits lowercase
            "2024-02-29T00:00:00Z", // a leap day
            "2000-02-29T00:00:00Z", // the %400 rule: 2000 IS a leap year
            "2026-06-30T23:59:60Z", // THE LEAP SECOND — must stay accepted
            "2026-06-30T23:59:60.000+14:00",
            "2026-06-20T07:30:54.123456789-12:45",
            "2026-12-31T23:59:59Z",
        ] {
            assert!(is_rfc3339_instant(s), "should be accepted: {s}");
        }
        for s in [
            "2026-13-45T99:99:99.000Z", // the reproduction's own timestamp
            "2026-00-10T00:00:00Z",     // month 0
            "2026-06-00T00:00:00Z",     // day 0
            "2026-06-31T00:00:00Z",     // June has 30 days
            "2026-02-29T00:00:00Z",     // 2026 is not a leap year
            "1900-02-29T00:00:00Z",     // 1900 is NOT a leap year (the %100 rule)
            "2026-01-01T24:00:00Z",     // hour 24
            "2026-01-01T00:60:00Z",     // minute 60
            "2026-01-01T00:00:61Z",     // second 61
            "2026-01-01T00:00:00+24:00",
            "2026-01-01T00:00:00-05:60",
        ] {
            assert!(!is_rfc3339_instant(s), "should be refused: {s}");
            // …and the LEXICAL layer must still accept every one of them: the shape was never the
            // question, which is exactly why a second layer exists.
            assert!(is_rfc3339(s), "the lexical form should still match: {s}");
        }
    }
}
