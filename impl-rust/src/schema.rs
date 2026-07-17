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
/// full-match, ASCII digits only. (Range validity like month<=12 is intentionally NOT checked — the
/// normative pattern doesn't check it either.)
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
    match value.get("ts") {
        Some(Json::Str(s)) if is_rfc3339(s) => {}
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
                        Some(Json::Str(s)) if is_rfc3339(s) => {}
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
