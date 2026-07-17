//! NOA Receipt — third, independent verifier (Rust, from-scratch).
//!
//! A separate crypto/JCS stack (own strict parser + own RFC 8785 canonicalizer + ed25519-dalek
//! `verify_strict`) re-verifies the exact same receipts as the TS reference (node:crypto) and the Python
//! reference (from-scratch RFC 8032). If three independent stacks agree on the verdict, the canonical
//! bytes + signing preimage are unambiguous — the interop bar for the `noa.receipt/0.1` profile.
//!
//! Usage:  noa-verify <receipts.json> [keyring.json] [--identity <m.json>] [--checkpoint <cp.json>]
//! Exit:   0 VALID · 1 UNVERIFIED (no keyring) · 2 TAMPERED · 3 MALFORMED · 4 USAGE · 5 UNTRUSTED

mod jcs;
mod json;
mod keys;
mod schema;
mod verify;

use json::Json;
use std::process::exit;
use verify::{verify_chain, Status};

const USAGE: &str =
    "usage: noa-verify <receipts.json> [keyring.json] [--identity <m.json>] [--checkpoint <cp.json>]";

/// Minimal JSON-string escape for the emitted `detail` (exit code is the contract; this is diagnostic).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn emit_malformed(detail: &str) -> i32 {
    println!("{{\"status\": \"MALFORMED\", \"detail\": \"{}\"}}", esc(detail));
    Status::Malformed.exit_code()
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut receipts_path: Option<String> = None;
    let mut keyring_path: Option<String> = None;
    let mut identity_path: Option<String> = None;
    let mut checkpoint_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--identity" {
            if i + 1 >= args.len() {
                eprintln!("{USAGE}");
                return 4;
            }
            i += 1;
            identity_path = Some(args[i].clone());
        } else if a == "--checkpoint" {
            if i + 1 >= args.len() {
                eprintln!("{USAGE}");
                return 4;
            }
            i += 1;
            checkpoint_path = Some(args[i].clone());
        } else if a.starts_with("--") {
            eprintln!("unknown flag: {a}");
            return 4;
        } else if receipts_path.is_none() {
            receipts_path = Some(a.clone());
        } else if keyring_path.is_none() {
            keyring_path = Some(a.clone());
        } else {
            eprintln!("unexpected arg: {a}");
            return 4;
        }
        i += 1;
    }

    let receipts_path = match receipts_path {
        Some(p) => p,
        None => {
            eprintln!("{USAGE}");
            return 4;
        }
    };

    // Parse every input file with the strict parser (parity with the TS CLI readJsonFile -> safeParse).
    let receipts = match read_and_parse(&receipts_path) {
        Ok(v) => v,
        Err(e) => return emit_malformed(&e),
    };
    let keyring = match &keyring_path {
        Some(p) => match read_and_parse(p) {
            Ok(v) => Some(v),
            Err(e) => return emit_malformed(&e),
        },
        None => None,
    };
    let identity = match &identity_path {
        Some(p) => match read_and_parse(p) {
            Ok(v) => Some(v),
            Err(e) => return emit_malformed(&e),
        },
        None => None,
    };
    let checkpoint = match &checkpoint_path {
        Some(p) => match read_and_parse(p) {
            Ok(v) => Some(v),
            Err(e) => return emit_malformed(&e),
        },
        None => None,
    };

    // A trust/aux file that was GIVEN but is not an object is an operator error → MALFORMED (parity with
    // the Python CLI guards), NOT silently treated as absent (which would drop the security control).
    if identity_path.is_some() && !identity.as_ref().map(Json::is_object).unwrap_or(false) {
        return emit_malformed("identityManifest must be an object (agent.id -> kid[])");
    }
    if checkpoint_path.is_some() && !checkpoint.as_ref().map(Json::is_object).unwrap_or(false) {
        return emit_malformed("checkpoint must be an object");
    }
    if keyring_path.is_some() && !keyring.as_ref().map(Json::is_object).unwrap_or(false) {
        return emit_malformed("keyring must be an object (kid -> base64 SPKI)");
    }

    let (status, detail) = verify_chain(
        &receipts,
        keyring.as_ref(),
        identity.as_ref(),
        checkpoint.as_ref(),
    );
    println!(
        "{{\n  \"status\": \"{}\",\n  \"detail\": \"{}\"\n}}",
        status.label(),
        esc(&detail)
    );
    status.exit_code()
}

fn read_and_parse(path: &str) -> Result<Json, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    json::parse(&text)
}

fn main() {
    exit(run());
}
