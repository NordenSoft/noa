package main

import "testing"

// TestJCSByteParity asserts the Go JCS produces byte-identical canonical output to impl-py's jcs()
// on the hard cases the ASCII-only committed vectors do NOT exercise:
//   - UTF-16 code-unit key sort with a BMP key (é, U+00E9) and an ASTRAL key (😀, U+1F600 →
//     surrogate pair) — note z (0x7A) sorts BEFORE é (0x00E9) which sorts before 😀 (0xD83D…),
//   - RFC-8785 string escaping of a control char < 0x20 (, ) vs a literal DEL (0x7F),
//     the two-char escapes (\" \\ \n \t), and a literal astral code point in a value,
//   - integers, booleans, and null inside an array.
// The expected SHA-256 is the INDEPENDENT ground truth printed by impl-py's own jcs():
//   python3 (import noa_verify; jcs(obj)) -> sha256 = 9d711c2d1432b4e3eacdec438431928464691939fb934bbee40c87f92a86ef5c
// A single differing byte would change the digest, so this is a definitive byte-parity check.
func TestJCSByteParity(t *testing.T) {
	note := "\U0001F600 q=\" bs=\\ c01=\x01 c1f=\x1f nl=\n tab=\t del=\x7f end"
	obj := &Value{Kind: KindObject, Obj: map[string]*Value{
		"z":            {Kind: KindInt, Int: 1},
		"a":            {Kind: KindInt, Int: 2},
		"é":       {Kind: KindInt, Int: 3},
		"\U0001F600":   {Kind: KindInt, Int: 4},
		"b\tc":         {Kind: KindInt, Int: 5},
		"note":         {Kind: KindString, Str: note},
		"arr": {Kind: KindArray, Arr: []*Value{
			{Kind: KindInt, Int: 1},
			{Kind: KindString, Str: "x"},
			{Kind: KindBool, Bool: true},
			{Kind: KindBool, Bool: false},
			{Kind: KindNull},
			{Kind: KindInt, Int: -7},
		}},
	}}

	canon, err := jcs(obj)
	if err != nil {
		t.Fatalf("jcs error: %v", err)
	}
	const wantSHA = "sha256:9d711c2d1432b4e3eacdec438431928464691939fb934bbee40c87f92a86ef5c"
	got := sha256Prefixed(canon)
	if got != wantSHA {
		t.Fatalf("JCS byte-parity FAILED\n got sha = %s\n want    = %s\n canon   = %q", got, wantSHA, canon)
	}
}

// TestUTF16KeySort pins the exact UTF-16 code-unit ordering (not UTF-8 byte order) for keys whose
// UTF-8 and UTF-16 orderings could differ.
func TestUTF16KeySort(t *testing.T) {
	keys := []string{"\U0001F600", "é", "z", "b", "a"}
	sortUTF16(keys)
	want := []string{"a", "b", "z", "é", "\U0001F600"}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("UTF-16 sort mismatch at %d: got %q want %q (full %q)", i, keys[i], want[i], keys)
		}
	}
}
