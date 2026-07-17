package main

// Value is the parsed JSON tree produced by the strict parser (parse.go). It is the ONLY
// representation the verifier operates on — no reliance on encoding/json (which would silently
// accept duplicate keys, collapse lone surrogates to U+FFFD, and lose integer/float distinction).
// bool is a distinct Kind from int (mirrors impl-py's `isinstance(v, bool)` exclusion in `_is_int`).
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindInt
	KindString
	KindArray
	KindObject
)

type Value struct {
	Kind Kind
	Bool bool
	Int  int64
	Str  string
	Arr  []*Value
	Obj  map[string]*Value
}

// ── type predicates (mirror impl-py _is_obj/_is_str/_is_bool/_is_int) ─────────────
// All are nil-safe: an absent object key resolves to a nil *Value, and every predicate
// returns false for nil — matching Python's `_is_str(None) == False` etc.

func (v *Value) isObj() bool  { return v != nil && v.Kind == KindObject }
func (v *Value) isStr() bool  { return v != nil && v.Kind == KindString }
func (v *Value) isBool() bool { return v != nil && v.Kind == KindBool }
func (v *Value) isInt() bool  { return v != nil && v.Kind == KindInt }
func (v *Value) isNull() bool { return v != nil && v.Kind == KindNull }

// get returns the value for key k, or nil if v is not an object or k is absent. A key present
// with a JSON null returns a non-nil *Value{Kind:KindNull} — so callers can distinguish
// "absent" (nil) from "present null" (isNull()), exactly as impl-py distinguishes
// `"k" in d` from `d.get("k")`.
func (v *Value) get(k string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	return v.Obj[k]
}

// has reports whether key k is present (regardless of its value type/null-ness).
func (v *Value) has(k string) bool {
	if v == nil || v.Kind != KindObject {
		return false
	}
	_, ok := v.Obj[k]
	return ok
}

// deepClone copies a Value tree so hash-input construction can delete chain.hash / sig.value
// without mutating the original receipt (mirrors impl-py's json.loads(json.dumps(...)) deep copy).
func deepClone(v *Value) *Value {
	if v == nil {
		return nil
	}
	nv := &Value{Kind: v.Kind, Bool: v.Bool, Int: v.Int, Str: v.Str}
	switch v.Kind {
	case KindArray:
		nv.Arr = make([]*Value, len(v.Arr))
		for i, e := range v.Arr {
			nv.Arr[i] = deepClone(e)
		}
	case KindObject:
		nv.Obj = make(map[string]*Value, len(v.Obj))
		for k, e := range v.Obj {
			nv.Obj[k] = deepClone(e)
		}
	}
	return nv
}
