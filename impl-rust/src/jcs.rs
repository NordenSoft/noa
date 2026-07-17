//! RFC 8785 (JSON Canonicalization Scheme), hardened for NOA receipts. Byte-for-byte mirror of
//! `src/jcs.ts` and impl-py `jcs`:
//!   - integers emitted as their shortest decimal (values are already range-checked at parse; floats
//!     never reach here — the parser rejects them),
//!   - object keys sorted by UTF-16 code units (NOT Unicode scalar / UTF-8 byte order — they differ for
//!     astral code points, which encode as surrogate pairs 0xD800..0xDFFF, sorting AFTER 0xE000..0xFFFF),
//!   - strings: escape " \ \b \f \n \r \t and control chars < 0x20 as \u00xx (lowercase); every other
//!     code point emitted literally as UTF-8, NO \u-escaping of non-controls, NO Unicode normalization.
//!
//! A Rust `&str` cannot contain an unpaired surrogate, so RFC 8785 well-formedness holds by construction.

use crate::json::Json;
use std::cmp::Ordering;

/// Compare two keys by their UTF-16 code-unit sequences (RFC 8785 / JS default string sort /
/// Python `key.encode("utf-16-be")` byte order).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn serialize_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn serialize(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::Str(s) => serialize_string(s, out),
        Json::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize(item, out);
            }
            out.push(']');
        }
        Json::Object(o) => {
            let mut keys: Vec<&(String, Json)> = o.iter().collect();
            keys.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            for (i, (k, val)) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_string(k, out);
                out.push(':');
                serialize(val, out);
            }
            out.push('}');
        }
    }
}

/// Canonicalize a `Json` value to its RFC 8785 byte-string form (returned as a `String`; its UTF-8
/// bytes are the hash input).
pub fn canonicalize(v: &Json) -> String {
    let mut out = String::new();
    serialize(v, &mut out);
    out
}
