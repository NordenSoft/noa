package main

import (
	"strings"
	"testing"
)

// ── CROSS-FIELD COHERENCE (R1-R5) + the real-instant timestamp rule ──────────────────────────────
//
// A receipt can satisfy every single-field check and still be a statement that argues both ways:
// agent.principal "SANDBOX_SIM" (the actor was the sandbox simulator) beside governance.sandboxed
// false (this really happened), on a CRITICAL wire.transfer. Five such receipts — signed,
// chain-valid, hash-genuine — verified VALID 25 times out of 25 across the five shipped verifiers
// before these rules landed.
//
// Every rule is tested BOTH ways. A rule that refuses everything is an outage, not a control, so
// each contradiction is paired with a NEGATIVE CONTROL in which the same two fields agree.

// receiptJSON builds one structurally-complete receipt. The chain.hash/sig.value here are
// well-formed but not recomputed — validateReceiptShape runs BEFORE any hashing (it is the step
// that decides MALFORMED), so shape is the only thing under test.
func receiptJSON(ts, principal, verdict string, sandboxed, reversible bool, rollbackRef string) string {
	rb := "null"
	if rollbackRef != "" {
		rb = `"` + rollbackRef + `"`
	}
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	h := "sha256:" + strings.Repeat("a", 64)
	return `{"spec":"noa.receipt/0.1","id":"rcpt_1","ts":"` + ts + `",` +
		`"scope":{"tenant":"acme","chain":"c1"},` +
		`"agent":{"id":"agent-1","model":null,"principal":"` + principal + `"},` +
		`"action":{"id":"wire.transfer","canonical":"wire.transfer","riskClass":"CRITICAL",` +
		`"paramsHash":"` + h + `","reversible":` + b(reversible) + `,"rollbackRef":` + rb + `},` +
		`"governance":{"mode":"on","verdict":"` + verdict + `","ruleId":"r","approval":null,"sandboxed":` + b(sandboxed) + `},` +
		`"chain":{"seq":0,"prevHash":null,"hash":"` + h + `"},` +
		`"sig":{"alg":"ed25519","kid":"k1","value":"AAAA"}}`
}

func shapeOK(t *testing.T, js string) bool {
	t.Helper()
	v, err := parseStrict(js)
	if err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	return validateReceiptShape(v)
}

const okTS = "2026-08-14T00:00:00.000Z"

func TestCoherenceRules(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want bool
	}{
		// The baseline every case below is a one-field edit away from.
		{"baseline is VALID", receiptJSON(okTS, "SERVICE", "EXECUTED", false, true, ""), true},

		// R1 — the actor is the sandbox simulator while the receipt denies it was a simulation.
		{"R1 SANDBOX_SIM + sandboxed false", receiptJSON(okTS, "SANDBOX_SIM", "EXECUTED", false, true, ""), false},
		{"R1 control: SANDBOX_SIM + sandboxed true", receiptJSON(okTS, "SANDBOX_SIM", "EXECUTED", true, true, ""), true},
		{"R1 is one-directional: SERVICE + sandboxed true", receiptJSON(okTS, "SERVICE", "EXECUTED", true, true, ""), true},

		// R2 — a SIMULATED outcome while the receipt denies it was a simulation.
		{"R2 SIMULATED + sandboxed false", receiptJSON(okTS, "SERVICE", "SIMULATED", false, true, ""), false},
		{"R2 control: SIMULATED + sandboxed true", receiptJSON(okTS, "SERVICE", "SIMULATED", true, true, ""), true},

		// R3 — an action declared impossible to undo, carrying the reference used to undo it.
		{"R3 reversible false + rollbackRef", receiptJSON(okTS, "SERVICE", "EXECUTED", false, false, "snap_1"), false},
		{"R3 control: reversible false + rollbackRef null", receiptJSON(okTS, "SERVICE", "EXECUTED", false, false, ""), true},
		{"R3 control: reversible true + rollbackRef", receiptJSON(okTS, "SERVICE", "EXECUTED", false, true, "snap_1"), true},

		// R4 — the receipt says the action WAS undone while declaring it could not be.
		{"R4 ROLLED_BACK + reversible false", receiptJSON(okTS, "SERVICE", "ROLLED_BACK", false, false, ""), false},
		{"R4 control: ROLLED_BACK + reversible true", receiptJSON(okTS, "SERVICE", "ROLLED_BACK", false, true, "snap_1"), true},

		// R5 — a ts with the SHAPE of RFC 3339 that denotes no instant.
		{"R5 ts month 13 day 45 hour 99", receiptJSON("2026-13-45T99:99:99.000Z", "SERVICE", "EXECUTED", false, true, ""), false},
		{"R5 control: leap second is a real instant", receiptJSON("2026-06-30T23:59:60.000Z", "SERVICE", "EXECUTED", false, true, ""), true},
	}
	for _, c := range cases {
		if got := shapeOK(t, c.js); got != c.want {
			t.Errorf("%s: validateReceiptShape = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRfc3339Instant pins the calendar layer, including the one acceptance that must never be
// "tightened" away: second 60. A leap second is a real instant that has really occurred 27 times,
// and refusing it would refuse a truthful receipt.
func TestRfc3339Instant(t *testing.T) {
	accept := []string{
		"2026-06-20T07:30:54Z",
		"2026-06-20t07:30:54z", // RFC 3339 §5.6 permits lowercase
		"2024-02-29T00:00:00Z", // a leap day
		"2000-02-29T00:00:00Z", // the %400 rule: 2000 IS a leap year
		"2026-06-30T23:59:60Z", // THE LEAP SECOND — must stay accepted
		"2026-06-30T23:59:60.000+14:00",
		"2026-06-20T07:30:54.123456789-12:45",
		"2026-12-31T23:59:59Z",
	}
	reject := []string{
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
	}
	for _, s := range accept {
		if !rfc3339Instant(s) {
			t.Errorf("rfc3339Instant(%q) = false, want true", s)
		}
	}
	for _, s := range reject {
		if rfc3339Instant(s) {
			t.Errorf("rfc3339Instant(%q) = true, want false", s)
		}
		// …and the LEXICAL layer must still accept every one of them: the shape was never the
		// question, which is exactly why a second layer exists.
		if !rfc3339Re.MatchString(s) {
			t.Errorf("the lexical pattern should still match %q — the calendar layer is what rejects it", s)
		}
	}
}
