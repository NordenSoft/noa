//! Strict JSON parse — parity with impl-py `strict_load_text` and the TS `safeParse`.
//!
//! serde_json is used ONLY to drive tokenization; the value model is our own `Json` enum with a
//! hand-written `Deserialize` that rejects, at parse time, exactly what the reference verifiers reject:
//!   - duplicate object keys (last-wins would defeat the T8 dup-key mitigation),
//!   - `__proto__` / `constructor` / `prototype` keys (prototype-pollution channel),
//!   - floats / non-integer numbers (receipts are integer-only),
//!   - integers outside the JS safe range (|n| > 2^53-1),
//!   - lone UTF-16 surrogates in strings (serde_json rejects these during string scanning; a Rust
//!     `String` cannot even represent one, so this is enforced by construction after parse).
//!
//! serde_json additionally rejects trailing garbage and enforces a nesting-depth limit — both map to
//! MALFORMED, matching the reference (the reference reaches MALFORMED via structural validation on the
//! over-nested / trailing-garbage inputs; the verdict is identical).

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

/// JS `Number.isSafeInteger` upper bound (2^53 - 1). Receipts use integers only, within this range.
pub const SAFE_INT_MAX: i64 = (1i64 << 53) - 1;

/// A strict JSON value. Objects preserve insertion order (JCS sorts at emit time) and are guaranteed
/// duplicate-free by the parser.
#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn as_object(&self) -> Option<&Vec<(String, Json)>> {
        match self {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn is_object(&self) -> bool {
        matches!(self, Json::Object(_))
    }
    /// Field lookup on an object (None if not an object or key absent).
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object()
            .and_then(|o| o.iter().find(|(k, _)| k == key).map(|(_, v)| v))
    }
}

const FORBIDDEN_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a strict JSON value")
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Json, E> {
        if !(-SAFE_INT_MAX..=SAFE_INT_MAX).contains(&v) {
            return Err(E::custom("integer outside safe range"));
        }
        Ok(Json::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Json, E> {
        if v > SAFE_INT_MAX as u64 {
            return Err(E::custom("integer outside safe range"));
        }
        Ok(Json::Int(v as i64))
    }

    fn visit_i128<E: de::Error>(self, _v: i128) -> Result<Json, E> {
        Err(E::custom("integer outside safe range"))
    }

    fn visit_u128<E: de::Error>(self, _v: u128) -> Result<Json, E> {
        Err(E::custom("integer outside safe range"))
    }

    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<Json, E> {
        Err(E::custom("non-integer (float) not allowed"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Json, E> {
        Ok(Json::Str(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Json, E> {
        Ok(Json::Str(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut arr = Vec::new();
        while let Some(e) = seq.next_element::<Json>()? {
            arr.push(e);
        }
        Ok(Json::Array(arr))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut obj: Vec<(String, Json)> = Vec::new();
        while let Some(k) = map.next_key::<String>()? {
            if FORBIDDEN_KEYS.contains(&k.as_str()) {
                return Err(de::Error::custom(format!("forbidden key: {k}")));
            }
            if obj.iter().any(|(ek, _)| ek == &k) {
                return Err(de::Error::custom(format!("duplicate key: {k}")));
            }
            let v = map.next_value::<Json>()?;
            obj.push((k, v));
        }
        Ok(Json::Object(obj))
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(JsonVisitor)
    }
}

/// Parse strict JSON text into a `Json` value. Any deviation (dup key, float, oversized int, forbidden
/// key, lone surrogate, trailing garbage, over-deep nesting) is an `Err` → the caller maps it to MALFORMED.
pub fn parse(text: &str) -> Result<Json, String> {
    serde_json::from_str::<Json>(text).map_err(|e| e.to_string())
}
