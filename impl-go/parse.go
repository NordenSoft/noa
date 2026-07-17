package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Strict JSON parser — the byte-parity twin of impl-py's strict_load_text (json.loads with
// object_pairs_hook/parse_float/parse_int/parse_constant overrides + _reject_lone_surrogate).
//
// It REJECTS, exactly as impl-py does:
//   - duplicate object keys,
//   - the prototype-pollution keys __proto__ / constructor / prototype,
//   - floats / non-integer numbers (any '.' , 'e' , 'E'),
//   - integers with abs value > 2^53-1 (Number.isSafeInteger bound),
//   - NaN / Infinity / -Infinity (not valid number tokens → parse error),
//   - LONE UTF-16 surrogates in ANY string (a forgery channel: a lone surrogate would collapse
//     to U+FFFD at the UTF-8 hashing step). Go's encoding/json silently does that collapse, so a
//     hand-written string scanner that inspects the raw \uXXXX escapes is REQUIRED for parity.
//   - trailing garbage after the top-level value,
//   - unescaped control characters (< 0x20) inside strings, and invalid UTF-8.
//
// maxDepth is a generous DoS bound; every committed vector nests < 300 deep, and a value deeper
// than the bound errors out to MALFORMED just like an over-deep value fails structural validation
// in impl-py — so the verdict (MALFORMED) is unchanged either way.
const maxDepth = 2000

const maxSafeInt = (int64(1) << 53) - 1

var forbiddenKeys = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}

type parser struct {
	s     string
	i     int
	depth int
}

func parseStrict(text string) (*Value, error) {
	p := &parser{s: text}
	p.skipWS()
	v, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("trailing garbage at offset %d", p.i)
	}
	return v, nil
}

func (p *parser) skipWS() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (*Value, error) {
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("unexpected end of input")
	}
	c := p.s[p.i]
	switch {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		s, err := p.parseString()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, Str: s}, nil
	case c == 't', c == 'f':
		return p.parseBool()
	case c == 'n':
		return p.parseNull()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	default:
		return nil, fmt.Errorf("unexpected character %q at offset %d", c, p.i)
	}
}

func (p *parser) parseObject() (*Value, error) {
	p.depth++
	if p.depth > maxDepth {
		return nil, fmt.Errorf("max nesting depth exceeded")
	}
	defer func() { p.depth-- }()
	p.i++ // consume '{'
	obj := map[string]*Value{}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return &Value{Kind: KindObject, Obj: obj}, nil
	}
	for {
		p.skipWS()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, fmt.Errorf("expected string key at offset %d", p.i)
		}
		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key: %s", key)
		}
		if forbiddenKeys[key] {
			return nil, fmt.Errorf("forbidden key: %s", key)
		}
		p.skipWS()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("expected ':' at offset %d", p.i)
		}
		p.i++
		p.skipWS()
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		obj[key] = val
		p.skipWS()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return &Value{Kind: KindObject, Obj: obj}, nil
		default:
			return nil, fmt.Errorf("expected ',' or '}' at offset %d", p.i)
		}
	}
}

func (p *parser) parseArray() (*Value, error) {
	p.depth++
	if p.depth > maxDepth {
		return nil, fmt.Errorf("max nesting depth exceeded")
	}
	defer func() { p.depth-- }()
	p.i++ // consume '['
	arr := []*Value{}
	p.skipWS()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return &Value{Kind: KindArray, Arr: arr}, nil
	}
	for {
		p.skipWS()
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		arr = append(arr, val)
		p.skipWS()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return &Value{Kind: KindArray, Arr: arr}, nil
		default:
			return nil, fmt.Errorf("expected ',' or ']' at offset %d", p.i)
		}
	}
}

func (p *parser) parseBool() (*Value, error) {
	if strings.HasPrefix(p.s[p.i:], "true") {
		p.i += 4
		return &Value{Kind: KindBool, Bool: true}, nil
	}
	if strings.HasPrefix(p.s[p.i:], "false") {
		p.i += 5
		return &Value{Kind: KindBool, Bool: false}, nil
	}
	return nil, fmt.Errorf("invalid literal at offset %d", p.i)
}

func (p *parser) parseNull() (*Value, error) {
	if strings.HasPrefix(p.s[p.i:], "null") {
		p.i += 4
		return &Value{Kind: KindNull}, nil
	}
	return nil, fmt.Errorf("invalid literal at offset %d", p.i)
}

// parseNumber enforces the JSON number grammar and REJECTS every float / non-integer form
// (mirrors impl-py's parse_float override raising) plus integers whose absolute value exceeds
// 2^53-1. NaN/Infinity/-Infinity are never valid tokens here, so they error out — matching
// impl-py's parse_constant override.
func (p *parser) parseNumber() (*Value, error) {
	start := p.i
	if p.i < len(p.s) && p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("invalid number at offset %d", start)
	}
	if p.s[p.i] == '0' {
		p.i++
	} else if p.s[p.i] >= '1' && p.s[p.i] <= '9' {
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	} else {
		return nil, fmt.Errorf("invalid number at offset %d", start)
	}
	isFloat := false
	if p.i < len(p.s) && p.s[p.i] == '.' {
		isFloat = true
		p.i++
		if p.i >= len(p.s) || p.s[p.i] < '0' || p.s[p.i] > '9' {
			return nil, fmt.Errorf("invalid fraction at offset %d", p.i)
		}
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		isFloat = true
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.s) || p.s[p.i] < '0' || p.s[p.i] > '9' {
			return nil, fmt.Errorf("invalid exponent at offset %d", p.i)
		}
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	raw := p.s[start:p.i]
	if isFloat {
		return nil, fmt.Errorf("float not allowed (integers only): %s", raw)
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("integer outside safe range: %s", raw)
	}
	if n > maxSafeInt || n < -maxSafeInt {
		return nil, fmt.Errorf("integer outside safe range: %s", raw)
	}
	return &Value{Kind: KindInt, Int: n}, nil
}

// parseString parses a JSON string starting at the opening quote and returns a valid-UTF-8 Go
// string. It REJECTS any lone/unpaired UTF-16 surrogate escape (and invalid raw UTF-8), so the
// tree never carries a code point that would collapse to U+FFFD when hashed.
func (p *parser) parseString() (string, error) {
	p.i++ // consume opening quote
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", fmt.Errorf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", fmt.Errorf("unterminated escape")
			}
			switch p.s[p.i] {
			case '"':
				b.WriteByte('"')
				p.i++
			case '\\':
				b.WriteByte('\\')
				p.i++
			case '/':
				b.WriteByte('/')
				p.i++
			case 'b':
				b.WriteByte('\b')
				p.i++
			case 'f':
				b.WriteByte('\f')
				p.i++
			case 'n':
				b.WriteByte('\n')
				p.i++
			case 'r':
				b.WriteByte('\r')
				p.i++
			case 't':
				b.WriteByte('\t')
				p.i++
			case 'u':
				r, err := p.parseUnicodeEscape()
				if err != nil {
					return "", err
				}
				b.WriteRune(r)
			default:
				return "", fmt.Errorf("invalid escape \\%c", p.s[p.i])
			}
		case c < 0x20:
			return "", fmt.Errorf("unescaped control character 0x%02x in string", c)
		case c < 0x80:
			b.WriteByte(c)
			p.i++
		default:
			r, size := utf8.DecodeRuneInString(p.s[p.i:])
			if r == utf8.RuneError && size == 1 {
				return "", fmt.Errorf("invalid UTF-8 in string")
			}
			b.WriteString(p.s[p.i : p.i+size])
			p.i += size
		}
	}
}

// parseUnicodeEscape is entered with p.s[p.i] == 'u'. It reads one \uXXXX code unit and, for a
// high surrogate, REQUIRES an immediately-following \uXXXX low surrogate (combining them). A high
// surrogate not followed by a low one, or a bare low surrogate, is a lone surrogate → error.
func (p *parser) parseUnicodeEscape() (rune, error) {
	cu, err := p.readHex4()
	if err != nil {
		return 0, err
	}
	if cu >= 0xD800 && cu <= 0xDBFF {
		if p.i+1 < len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
			p.i++ // consume the backslash; p.i now at 'u'
			low, err := p.readHex4()
			if err != nil {
				return 0, err
			}
			if low >= 0xDC00 && low <= 0xDFFF {
				return utf16.DecodeRune(rune(cu), rune(low)), nil
			}
			return 0, fmt.Errorf("invalid low surrogate in pair")
		}
		return 0, fmt.Errorf("unpaired high surrogate")
	}
	if cu >= 0xDC00 && cu <= 0xDFFF {
		return 0, fmt.Errorf("unpaired low surrogate")
	}
	return rune(cu), nil
}

// readHex4 is entered with p.s[p.i] == 'u'; it consumes 'u' + 4 hex digits and returns the code unit.
func (p *parser) readHex4() (uint32, error) {
	if p.i+5 > len(p.s) {
		return 0, fmt.Errorf("truncated \\u escape")
	}
	var v uint32
	for k := 1; k <= 4; k++ {
		d := p.s[p.i+k]
		var nib uint32
		switch {
		case d >= '0' && d <= '9':
			nib = uint32(d - '0')
		case d >= 'a' && d <= 'f':
			nib = uint32(d-'a') + 10
		case d >= 'A' && d <= 'F':
			nib = uint32(d-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex digit in \\u escape")
		}
		v = v<<4 | nib
	}
	p.i += 5
	return v, nil
}
