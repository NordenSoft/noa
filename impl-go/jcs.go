package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// jcs implements RFC 8785 (JSON Canonicalization Scheme), byte-for-byte identical to impl-py's
// jcs() and src/jcs.ts:
//   - integers serialized as their decimal form (floats are impossible here — the parser rejects them),
//   - object keys sorted by UTF-16 code units (NOT UTF-8 byte order),
//   - RFC-8785 string escaping (control chars escaped, every other code point emitted literally),
//   - no Unicode normalization.
// The canonical string is the exact input to sha256 for the receipt hash + signing preimage.
func jcs(v *Value) (string, error) {
	switch v.Kind {
	case KindNull:
		return "null", nil
	case KindBool:
		if v.Bool {
			return "true", nil
		}
		return "false", nil
	case KindInt:
		return strconv.FormatInt(v.Int, 10), nil
	case KindString:
		return jcsString(v.Str)
	case KindArray:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				b.WriteByte(',')
			}
			s, err := jcs(e)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		}
		b.WriteByte(']')
		return b.String(), nil
	case KindObject:
		keys := make([]string, 0, len(v.Obj))
		for k := range v.Obj {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			ks, err := jcsString(k)
			if err != nil {
				return "", err
			}
			b.WriteString(ks)
			b.WriteByte(':')
			vs, err := jcs(v.Obj[k])
			if err != nil {
				return "", err
			}
			b.WriteString(vs)
		}
		b.WriteByte('}')
		return b.String(), nil
	}
	return "", fmt.Errorf("unsupported value type")
}

// jcsString mirrors impl-py jcs_string / src/jcs.ts serializeString.
func jcsString(s string) (string, error) {
	// Parser already guarantees valid UTF-8 with no lone surrogates; this guard mirrors impl-py's
	// s.encode("utf-8") / isWellFormed() check for defense in depth.
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("unpaired surrogate / invalid UTF-8 in string")
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, ch := range s {
		switch ch {
		case '"':
			b.WriteString("\\\"")
		case '\\':
			b.WriteString("\\\\")
		case '\b':
			b.WriteString("\\b")
		case '\f':
			b.WriteString("\\f")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if ch < 0x20 {
				b.WriteString(fmt.Sprintf("\\u%04x", ch))
			} else {
				b.WriteRune(ch)
			}
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// sortUTF16 sorts keys by UTF-16 code-unit order, equivalent to impl-py's
// sorted(keys, key=lambda k: k.encode("utf-16-be")) and JS's default string sort (RFC 8785).
func sortUTF16(keys []string) {
	sort.Slice(keys, func(a, b int) bool { return lessUTF16(keys[a], keys[b]) })
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
