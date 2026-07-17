//! NOA receipt-chain verification — verdict-equivalent to impl-py `verify_chain` / `src/verify.ts`.
//! Order of checks is preserved exactly (structural → partition/dup-seq → seq-walk[hash, key-continuity,
//! signature, identity, linkage] → checkpoint tail-truncation + genesis-bound checkpoint identity), because
//! the order determines which verdict class wins when an input violates several rules at once.

use crate::jcs::canonicalize;
use crate::json::{Json, SAFE_INT_MAX};
use crate::keys::verify_sig;
use crate::schema::{is_hash, is_rfc3339, validate_receipt_shape};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const RECEIPT_DOMAIN: &[u8] = b"NOA-Receipt-v0.1-sig:";
const CHECKPOINT_DOMAIN: &[u8] = b"NOA-Checkpoint-v0.1-sig:";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Valid,
    Unverified,
    Tampered,
    Malformed,
    Untrusted,
}

impl Status {
    pub fn exit_code(self) -> i32 {
        match self {
            Status::Valid => 0,
            Status::Unverified => 1,
            Status::Tampered => 2,
            Status::Malformed => 3,
            Status::Untrusted => 5,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Status::Valid => "VALID",
            Status::Unverified => "UNVERIFIED",
            Status::Tampered => "TAMPERED",
            Status::Malformed => "MALFORMED",
            Status::Untrusted => "UNTRUSTED",
        }
    }
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn sha256_hex_prefixed(s: &str) -> String {
    format!("sha256:{}", hex_lower(&sha256(s.as_bytes())))
}

/// JCS hash input for a receipt: canonicalize with `chain.hash` and `sig.value` removed.
fn receipt_hash_input(r: &Json) -> String {
    let mut clone = r.clone();
    if let Json::Object(fields) = &mut clone {
        for (k, v) in fields.iter_mut() {
            if k == "chain" {
                if let Json::Object(cf) = v {
                    cf.retain(|(ck, _)| ck != "hash");
                }
            } else if k == "sig" {
                if let Json::Object(sf) = v {
                    sf.retain(|(sk, _)| sk != "value");
                }
            }
        }
    }
    canonicalize(&clone)
}

/// JCS hash input for a checkpoint: canonicalize with `sig.value` removed.
fn checkpoint_hash_input(cp: &Json) -> String {
    let mut clone = cp.clone();
    if let Json::Object(fields) = &mut clone {
        for (k, v) in fields.iter_mut() {
            if k == "sig" {
                if let Json::Object(sf) = v {
                    sf.retain(|(sk, _)| sk != "value");
                }
            }
        }
    }
    canonicalize(&clone)
}

fn authorized(identity: &Json, agent_id: &str, kid: &str) -> bool {
    match identity.get(agent_id) {
        Some(Json::Array(kids)) => kids.iter().any(|k| k.as_str() == Some(kid)),
        _ => false,
    }
}

/// Strict checkpoint validation + authentication. Returns "ok" / "unverified" / "bad".
/// (Any non-valid keyring entry collapses to "unverified" — with a keyring that becomes TAMPERED and
/// without one it can never reach "ok", so the final verdict is identical either way.)
fn verify_checkpoint(cp: &Json, keyring: Option<&Json>) -> &'static str {
    let obj = match cp {
        Json::Object(o) => o,
        _ => return "bad",
    };
    for (k, _) in obj {
        if !["spec", "chain", "highestSeq", "headHash", "ts", "sig"].contains(&k.as_str()) {
            return "bad";
        }
    }
    if cp.get("spec").and_then(|v| v.as_str()) != Some("noa.checkpoint/0.1") {
        return "bad";
    }
    match cp.get("chain") {
        Some(Json::Str(s)) if !s.is_empty() => {}
        _ => return "bad",
    }
    match cp.get("highestSeq").and_then(|v| v.as_int()) {
        Some(i) if (0..=SAFE_INT_MAX).contains(&i) => {}
        _ => return "bad",
    }
    match cp.get("headHash") {
        Some(Json::Str(s)) if is_hash(s) => {}
        _ => return "bad",
    }
    match cp.get("ts") {
        Some(Json::Str(s)) if is_rfc3339(s) => {}
        _ => return "bad",
    }
    let sig = match cp.get("sig") {
        Some(sig @ Json::Object(so)) => {
            for (k, _) in so {
                if !["alg", "kid", "value"].contains(&k.as_str()) {
                    return "bad";
                }
            }
            sig
        }
        _ => return "bad",
    };
    if sig.get("alg").and_then(|v| v.as_str()) != Some("ed25519") {
        return "bad";
    }
    let kid = match sig.get("kid") {
        Some(Json::Str(s)) if !s.is_empty() => s.as_str(),
        _ => return "bad",
    };
    let value = match sig.get("value") {
        Some(Json::Str(s)) if !s.is_empty() => s.as_str(),
        _ => return "bad",
    };
    let pub_b64 = match keyring.and_then(|k| k.get(kid)) {
        Some(Json::Str(p)) if !p.is_empty() => p.as_str(),
        _ => return "unverified",
    };
    let hi = checkpoint_hash_input(cp);
    let mut msg = CHECKPOINT_DOMAIN.to_vec();
    msg.extend_from_slice(&sha256(hi.as_bytes()));
    match verify_sig(pub_b64, &msg, value) {
        Ok(true) => "ok",
        _ => "bad",
    }
}

/// Verify a receipt chain. Pure, offline, deterministic. Never panics — malformed shape → MALFORMED.
pub fn verify_chain(
    receipts: &Json,
    keyring: Option<&Json>,
    identity: Option<&Json>,
    checkpoint: Option<&Json>,
) -> (Status, String) {
    let arr = match receipts {
        Json::Array(a) if !a.is_empty() => a,
        _ => return (Status::Malformed, "input is not a non-empty array".into()),
    };
    if let Some(k) = keyring {
        if !k.is_object() {
            return (
                Status::Malformed,
                "keyring must be an object (kid -> base64 SPKI)".into(),
            );
        }
    }
    if let Some(id) = identity {
        match id {
            Json::Object(entries) => {
                for (aid, kids) in entries {
                    let ok = matches!(kids, Json::Array(list) if list.iter().all(|k| matches!(k, Json::Str(_))));
                    if !ok {
                        return (
                            Status::Malformed,
                            format!("identityManifest[\"{aid}\"] must be an array of kid strings"),
                        );
                    }
                }
            }
            _ => {
                return (
                    Status::Malformed,
                    "identityManifest must be an object (agent.id -> kid[])".into(),
                )
            }
        }
    }

    // Step 1: structural validation of every element, BEFORE any hashing.
    for (idx, r) in arr.iter().enumerate() {
        if let Err(e) = validate_receipt_shape(r) {
            return (Status::Malformed, format!("receipt[{idx}]: {e}"));
        }
    }

    let have_keyring = keyring.is_some();
    let chain_id = arr[0]
        .get("scope")
        .and_then(|s| s.get("chain"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();

    // Step 2/3: single partition + unique seq.
    let mut by_seq: HashMap<i64, usize> = HashMap::new();
    for (idx, r) in arr.iter().enumerate() {
        let rc = r
            .get("scope")
            .and_then(|s| s.get("chain"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if rc != chain_id {
            return (Status::Tampered, "multiple chain partitions".into());
        }
        let seq = r
            .get("chain")
            .and_then(|c| c.get("seq"))
            .and_then(|v| v.as_int())
            .unwrap_or(-1);
        if by_seq.contains_key(&seq) {
            return (Status::Tampered, format!("duplicate seq {seq}"));
        }
        by_seq.insert(seq, idx);
    }

    // Step 4: seq-walk.
    let n = arr.len();
    let mut pinned: HashMap<String, String> = HashMap::new();
    let mut prev_hash: Option<String> = None;
    for s in 0..n as i64 {
        let idx = match by_seq.get(&s) {
            Some(i) => *i,
            None => return (Status::Tampered, format!("seq gap: missing {s}")),
        };
        let r = &arr[idx];

        // 4a. hash integrity
        let hi = receipt_hash_input(r);
        let stored_hash = r
            .get("chain")
            .and_then(|c| c.get("hash"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if sha256_hex_prefixed(&hi) != stored_hash {
            return (Status::Tampered, format!("hash mismatch at seq {s}"));
        }

        let aid = r
            .get("agent")
            .and_then(|a| a.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let kid = r
            .get("sig")
            .and_then(|sg| sg.get("kid"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // 4b. key continuity per agent.id
        if let Some(pk) = pinned.get(&aid) {
            if pk != &kid {
                return (
                    Status::Tampered,
                    format!("key swap for agent \"{aid}\" at seq {s}"),
                );
            }
        } else {
            pinned.insert(aid.clone(), kid.clone());
        }

        // 4c. signature (any missing / non-string / bad key or sig → TAMPERED, mirroring impl-py)
        if have_keyring {
            let kr = keyring.unwrap();
            let pub_b64 = match kr.get(&kid) {
                Some(Json::Str(p)) if !p.is_empty() => p.as_str(),
                _ => return (Status::Tampered, format!("unknown/invalid kid {kid} at seq {s}")),
            };
            let sig_value = r
                .get("sig")
                .and_then(|sg| sg.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut msg = RECEIPT_DOMAIN.to_vec();
            msg.extend_from_slice(&sha256(hi.as_bytes()));
            match verify_sig(pub_b64, &msg, sig_value) {
                Ok(true) => {}
                _ => return (Status::Tampered, format!("invalid signature at seq {s}")),
            }

            // 4c-bis. identity binding (only meaningful once authenticated)
            if let Some(id) = identity {
                if !authorized(id, &aid, &kid) {
                    return (
                        Status::Untrusted,
                        format!("agent \"{aid}\" not authorized for kid \"{kid}\" at seq {s}"),
                    );
                }
            }
        }

        // 4d. linkage
        let link = r.get("chain").and_then(|c| c.get("prevHash"));
        if s == 0 {
            if !matches!(link, Some(Json::Null)) {
                return (Status::Tampered, "genesis prevHash must be null".into());
            }
        } else if link.and_then(|v| v.as_str()) != prev_hash.as_deref() {
            return (Status::Tampered, format!("broken linkage at seq {s}"));
        }
        prev_hash = Some(stored_hash.to_string());
    }

    // Step 5: tail-truncation via checkpoint.
    let head = &arr[*by_seq.get(&((n - 1) as i64)).unwrap()];
    if let Some(cp) = checkpoint {
        let cpv = verify_checkpoint(cp, keyring);
        if cpv == "bad" {
            return (Status::Tampered, "checkpoint invalid".into());
        }
        if have_keyring && cpv != "ok" {
            return (
                Status::Tampered,
                "checkpoint not authenticated against keyring".into(),
            );
        }
        if cp.get("chain").and_then(|v| v.as_str()).unwrap_or("") != chain_id {
            return (Status::Tampered, "checkpoint chain mismatch".into());
        }
        let cp_high = cp.get("highestSeq").and_then(|v| v.as_int());
        let head_seq = head
            .get("chain")
            .and_then(|c| c.get("seq"))
            .and_then(|v| v.as_int());
        let cp_head = cp.get("headHash").and_then(|v| v.as_str());
        let head_hash = head
            .get("chain")
            .and_then(|c| c.get("hash"))
            .and_then(|v| v.as_str());
        if cp_high != head_seq || cp_head != head_hash {
            return (
                Status::Tampered,
                "chain head does not match checkpoint (tail truncated/extended)".into(),
            );
        }
        // 5b. checkpoint identity binding to the chain OPENER (genesis, seq 0).
        if let (true, Some(id)) = (have_keyring, identity) {
            let genesis = &arr[*by_seq.get(&0).unwrap()];
            let gaid = genesis
                .get("agent")
                .and_then(|a| a.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cp_kid = cp
                .get("sig")
                .and_then(|sg| sg.get("kid"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !authorized(id, gaid, cp_kid) {
                return (
                    Status::Untrusted,
                    "checkpoint kid not authorized for chain opener (genesis) agent".into(),
                );
            }
        }
    }

    let status = if have_keyring {
        Status::Valid
    } else {
        Status::Unverified
    };
    (status, format!("{n} receipts, chain {chain_id}"))
}
