package main

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"unicode/utf8"
)

// Verdict status strings (exit codes are mapped in main.go).
const (
	statusValid      = "VALID"
	statusUnverified = "UNVERIFIED"
	statusTampered   = "TAMPERED"
	statusMalformed  = "MALFORMED"
	statusUntrusted  = "UNTRUSTED"
)

const receiptSpec = "noa.receipt/0.1"

// Domain-separation prefixes for the signing preimage (mirror impl-py _RECEIPT_DOMAIN / _CHECKPOINT_DOMAIN).
var (
	receiptDomain    = []byte("NOA-Receipt-v0.1-sig:")
	checkpointDomain = []byte("NOA-Checkpoint-v0.1-sig:")
)

// Frozen enum sets + format regexes (mirror impl-py). Regexes use \A...\z so they behave as
// Python's re.fullmatch (the whole string, with NO trailing-newline leniency) — matching the
// normative JSON-Schema `pattern` dialect + src/schema.ts. Digit classes are [0-9] (ASCII only),
// NOT \d, to avoid RE2's Unicode-Nd expansion diverging from JS/ECMA-262.
var (
	riskClasses    = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true, "IRREVERSIBLE": true}
	principals     = map[string]bool{"HUMAN": true, "SERVICE": true, "POLICY": true, "SANDBOX_SIM": true}
	modes          = map[string]bool{"off": true, "shadow": true, "approvals_on": true, "on": true}
	verdicts       = map[string]bool{"ALLOWED": true, "BLOCKED": true, "DEFERRED": true, "EXECUTED": true, "FAILED": true, "ROLLED_BACK": true, "SIMULATED": true}
	checkpointKeys = map[string]bool{"spec": true, "chain": true, "highestSeq": true, "headHash": true, "ts": true, "sig": true}

	hashRe       = regexp.MustCompile(`\Asha256:[0-9a-f]{64}\z`)
	paramsHashRe = regexp.MustCompile(`\A(sha256|hmac-sha256):[0-9a-f]{64}\z`)
	rfc3339Re    = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})\z`)
)

func inStrSet(v *Value, set map[string]bool) bool { return v.isStr() && set[v.Str] }

// daysInMonth is the real length of month in year; 0 for an out-of-range month, so any day fails.
func daysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 0
}

// two reads the two ASCII digits at i as a number. The caller has already proven they ARE digits.
func two(s string, i int) int { return int(s[i]-'0')*10 + int(s[i+1]-'0') }

// rfc3339Instant is RFC 3339 §5.6 date-time: the LEXICAL form rfc3339Re matches PLUS the field
// ranges the ABNF's own comments impose (month 01-12, mday by month and year including leap years,
// hour 00-23, minute 00-59, second 00-60, numoffset hours 00-23 / minutes 00-59). Mirrors impl-py
// _is_rfc3339_instant / src/scan.ts isRfc3339Instant.
//
// The pattern alone accepted `2026-13-45T99:99:99.000Z` — month 13, day 45, hour 99 — on a SIGNED,
// chain-valid CRITICAL receipt, in all five implementations. A ts that denotes no instant cannot be
// ordered against its neighbours; it is a "when" that can be argued both ways after the fact, and it
// is decidable with NO key material at all, so it belongs in the shape validator.
//
// SECOND 60 IS ACCEPTED ON PURPOSE: a leap second is a real instant that has really occurred 27
// times, and which UTC days carry one is an IERS table, not a property of the string.
func rfc3339Instant(s string) bool {
	if !rfc3339Re.MatchString(s) {
		return false
	}
	year := int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
	month := two(s, 5)
	day := two(s, 8)
	if month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) {
		return false
	}
	if two(s, 11) > 23 || two(s, 14) > 59 || two(s, 17) > 60 { // 60 is the leap second, and it is legal
		return false
	}
	// The lexical check already proved the tail is EITHER a single Z/z OR exactly ±HH:MM.
	n := len(s)
	if s[n-1] == 'Z' || s[n-1] == 'z' {
		return true
	}
	return two(s, n-5) <= 23 && two(s, n-2) <= 59
}

// checkExactKeys enforces additionalProperties:false (no unknown fields) + presence of every
// required field at this object level. Mirrors impl-py _check_exact_keys / TS checkExactKeys.
func checkExactKeys(obj *Value, required, optional []string) bool {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, k := range required {
		allowed[k] = true
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range obj.Obj {
		if !allowed[k] {
			return false
		}
	}
	for _, k := range required {
		if _, ok := obj.Obj[k]; !ok {
			return false
		}
	}
	return true
}

// validateReceiptShape is the STRICT structural validator, an exact-verdict mirror of impl-py
// validate_receipt_shape / src/schema.ts validateReceiptShape. It returns true iff the value is a
// well-formed NOA Receipt v0.1. Run BEFORE any hashing so a crypto-consistent but out-of-spec
// receipt (smuggled field, bad enum, wrong spec, sig.alg != "ed25519", over-long id) is MALFORMED.
// Short-circuits on the first violation — the boolean result matches impl-py's "no errors" outcome.
func validateReceiptShape(v *Value) bool {
	if !v.isObj() {
		return false
	}
	r := v
	if !checkExactKeys(r, []string{"spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig"}, nil) {
		return false
	}
	if sp := r.get("spec"); !sp.isStr() || sp.Str != receiptSpec {
		return false
	}
	if rid := r.get("id"); !rid.isStr() || utf8.RuneCountInString(rid.Str) == 0 || utf8.RuneCountInString(rid.Str) > 128 {
		return false
	}
	// R5: rfc3339Instant, not the bare pattern — a `ts` matching `[0-9]{2}` for a month is not a
	// moment in time. See rfc3339Instant for why second 60 (a leap second) stays accepted.
	if ts := r.get("ts"); !ts.isStr() || !rfc3339Instant(ts.Str) {
		return false
	}

	// scope
	scope := r.get("scope")
	if !scope.isObj() {
		return false
	}
	if !checkExactKeys(scope, []string{"chain"}, []string{"tenant"}) {
		return false
	}
	if sc := scope.get("chain"); !sc.isStr() || len(sc.Str) == 0 {
		return false
	}
	if scope.has("tenant") && !scope.get("tenant").isStr() {
		return false
	}

	// agent
	agent := r.get("agent")
	if !agent.isObj() {
		return false
	}
	if !checkExactKeys(agent, []string{"id", "principal"}, []string{"model"}) {
		return false
	}
	if aid := agent.get("id"); !aid.isStr() || len(aid.Str) == 0 {
		return false
	}
	if !inStrSet(agent.get("principal"), principals) {
		return false
	}
	if agent.has("model") && !agent.get("model").isNull() && !agent.get("model").isStr() {
		return false
	}

	// action
	action := r.get("action")
	if !action.isObj() {
		return false
	}
	if !checkExactKeys(action, []string{"id", "canonical", "riskClass", "paramsHash", "reversible"}, []string{"rollbackRef"}) {
		return false
	}
	if acid := action.get("id"); !acid.isStr() || len(acid.Str) == 0 {
		return false
	}
	if can := action.get("canonical"); !can.isStr() || len(can.Str) == 0 {
		return false
	}
	if !inStrSet(action.get("riskClass"), riskClasses) {
		return false
	}
	if ph := action.get("paramsHash"); !ph.isStr() || !paramsHashRe.MatchString(ph.Str) {
		return false
	}
	if !action.get("reversible").isBool() {
		return false
	}
	if action.has("rollbackRef") && !action.get("rollbackRef").isNull() && !action.get("rollbackRef").isStr() {
		return false
	}

	// governance
	gov := r.get("governance")
	if !gov.isObj() {
		return false
	}
	if !checkExactKeys(gov, []string{"mode", "verdict", "sandboxed"}, []string{"ruleId", "approval", "compliance"}) {
		return false
	}
	if !inStrSet(gov.get("mode"), modes) {
		return false
	}
	if !inStrSet(gov.get("verdict"), verdicts) {
		return false
	}
	if !gov.get("sandboxed").isBool() {
		return false
	}
	if gov.has("ruleId") && !gov.get("ruleId").isNull() && !gov.get("ruleId").isStr() {
		return false
	}
	if gov.has("approval") && !gov.get("approval").isNull() {
		ap := gov.get("approval")
		if !ap.isObj() {
			return false
		}
		if !checkExactKeys(ap, []string{"by", "at"}, nil) {
			return false
		}
		if !ap.get("by").isStr() {
			return false
		}
		if at := ap.get("at"); !at.isStr() || !rfc3339Instant(at.Str) {
			return false
		}
	}
	if gov.has("compliance") && !gov.get("compliance").isNull() {
		c := gov.get("compliance")
		if !c.isObj() {
			return false
		}
		if !checkExactKeys(c, []string{"policyHash", "readSetHash", "inputsHash"}, []string{"verdict"}) {
			return false
		}
		for _, k := range []string{"policyHash", "readSetHash", "inputsHash"} {
			if cv := c.get(k); !cv.isStr() || !hashRe.MatchString(cv.Str) {
				return false
			}
		}
		if c.has("verdict") {
			if cvd := c.get("verdict"); !cvd.isStr() || (cvd.Str != "ALLOW" && cvd.Str != "DENY") {
				return false
			}
		}
	}

	// ── CROSS-FIELD COHERENCE — A SIGNED RECEIPT MAY NOT CONTRADICT ITSELF ───────────────────────
	// Every check above reads ONE field. A receipt can satisfy all of them and still argue both
	// ways: agent.principal "SANDBOX_SIM" (the actor was the sandbox simulator) beside
	// governance.sandboxed false (this really happened), on a CRITICAL wire.transfer, signed and
	// chain-valid. Reproduced across all five verifiers, 25 of 25 VALID, before this block.
	//
	// They live in the SHAPE validator, not on the signature path, for the same reason an unknown
	// smuggled field does: they are decidable with NO key material at all. Mirrors impl-py
	// validate_receipt_shape / src/schema.ts validateReceiptShapeParsed.
	//
	// Each rule is ONE-DIRECTIONAL, because the converse is legitimate: a SERVICE agent may run
	// inside a sandbox (conformance/golden/0.3.0/multi/chain.json holds such a VALID receipt), and a
	// reversible action need not carry a rollbackRef. Every field read here has already passed its
	// own type check above, so a malformed receipt reports its one real defect.
	principal := agent.get("principal").Str
	verdict := gov.get("verdict").Str
	sandboxed := gov.get("sandboxed").Bool
	reversible := action.get("reversible").Bool
	rollbackPresent := action.has("rollbackRef") && !action.get("rollbackRef").isNull()
	// R1. Names the SANDBOX SIMULATOR as the actor while denying it was a simulation.
	if principal == "SANDBOX_SIM" && !sandboxed {
		return false
	}
	// R2. Records a SIMULATED outcome while denying it was a simulation.
	if verdict == "SIMULATED" && !sandboxed {
		return false
	}
	// R3. An action declared impossible to undo, carrying the reference used to undo it.
	if !reversible && rollbackPresent {
		return false
	}
	// R4. Says the action WAS undone while declaring it could not be.
	if verdict == "ROLLED_BACK" && !reversible {
		return false
	}

	// chain
	ch := r.get("chain")
	if !ch.isObj() {
		return false
	}
	if !checkExactKeys(ch, []string{"seq", "prevHash", "hash"}, nil) {
		return false
	}
	if seq := ch.get("seq"); !seq.isInt() || seq.Int < 0 || seq.Int > maxSafeInt {
		return false
	}
	if pv := ch.get("prevHash"); !pv.isNull() && (!pv.isStr() || !hashRe.MatchString(pv.Str)) {
		return false
	}
	if hv := ch.get("hash"); !hv.isStr() || !hashRe.MatchString(hv.Str) {
		return false
	}

	// sig (mandatory)
	sig := r.get("sig")
	if !sig.isObj() {
		return false
	}
	if !checkExactKeys(sig, []string{"alg", "kid", "value"}, nil) {
		return false
	}
	if alg := sig.get("alg"); !alg.isStr() || alg.Str != "ed25519" {
		return false
	}
	if kid := sig.get("kid"); !kid.isStr() || len(kid.Str) == 0 {
		return false
	}
	if val := sig.get("value"); !val.isStr() || len(val.Str) == 0 {
		return false
	}
	return true
}

func sha256Prefixed(s string) string {
	d := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(d[:])
}

// signingMessage builds domain ++ raw-sha256(hashInput) — the exact preimage Ed25519 signs over
// (raw 32 digest bytes, NOT hex). Mirrors impl-py's `_DOMAIN + hashlib.sha256(hi).digest()`.
func signingMessage(domain []byte, hashInput string) []byte {
	d := sha256.Sum256([]byte(hashInput))
	msg := make([]byte, 0, len(domain)+len(d))
	msg = append(msg, domain...)
	msg = append(msg, d[:]...)
	return msg
}

// receiptHashInput = JCS(receipt WITHOUT chain.hash AND WITHOUT sig.value). Mirrors impl-py
// receipt_hash_input / src/canonicalize.ts receiptHashInput.
func receiptHashInput(r *Value) (string, error) {
	clone := deepClone(r)
	if ch := clone.get("chain"); ch != nil && ch.Kind == KindObject {
		delete(ch.Obj, "hash")
	}
	if sig := clone.get("sig"); sig != nil && sig.Kind == KindObject {
		delete(sig.Obj, "value")
	}
	return jcs(clone)
}

// checkpointHashInput = JCS(checkpoint WITHOUT sig.value).
func checkpointHashInput(cp *Value) (string, error) {
	clone := deepClone(cp)
	if sig := clone.get("sig"); sig != nil && sig.Kind == KindObject {
		delete(sig.Obj, "value")
	}
	return jcs(clone)
}

// authorized mirrors impl-py _authorized: (agent.id, kid) is authorized iff the manifest lists kid
// for that agent.id.
func authorized(manifest *Value, agentID, kid string) bool {
	kids := manifest.get(agentID)
	if kids == nil || kids.Kind != KindArray {
		return false
	}
	for _, k := range kids.Arr {
		if k.isStr() && k.Str == kid {
			return true
		}
	}
	return false
}

// verifyCheckpoint mirrors impl-py _verify_checkpoint. Returns "bad" (structurally invalid /
// authentication failure), "unverified" (kid not resolvable in the keyring), or "ok".
func verifyCheckpoint(cp *Value, keyring *Value) string {
	if cp == nil || cp.Kind != KindObject {
		return "bad"
	}
	for k := range cp.Obj {
		if !checkpointKeys[k] {
			return "bad"
		}
	}
	if sp := cp.get("spec"); !sp.isStr() || sp.Str != "noa.checkpoint/0.1" {
		return "bad"
	}
	if c := cp.get("chain"); !c.isStr() || len(c.Str) == 0 {
		return "bad"
	}
	if hs := cp.get("highestSeq"); !hs.isInt() || hs.Int < 0 || hs.Int > maxSafeInt {
		return "bad"
	}
	if hh := cp.get("headHash"); !hh.isStr() || !hashRe.MatchString(hh.Str) {
		return "bad"
	}
	if ts := cp.get("ts"); !ts.isStr() || !rfc3339Instant(ts.Str) {
		return "bad"
	}
	sig := cp.get("sig")
	if !sig.isObj() {
		return "bad"
	}
	for k := range sig.Obj {
		if k != "alg" && k != "kid" && k != "value" {
			return "bad"
		}
	}
	if alg := sig.get("alg"); !alg.isStr() || alg.Str != "ed25519" {
		return "bad"
	}
	if kid := sig.get("kid"); !kid.isStr() || len(kid.Str) == 0 {
		return "bad"
	}
	if val := sig.get("value"); !val.isStr() || len(val.Str) == 0 {
		return "bad"
	}
	pub := keyring.get(cp.get("sig").get("kid").Str)
	if pub == nil || !pub.isStr() || pub.Str == "" {
		return "unverified"
	}
	hi, err := checkpointHashInput(cp)
	if err != nil {
		return "bad"
	}
	sigBytes, err := strictB64Decode(cp.get("sig").get("value").Str)
	if err != nil {
		return "bad"
	}
	pubRaw, err := spkiToRaw(pub.Str)
	if err != nil {
		return "bad"
	}
	if ed25519Verify(pubRaw, signingMessage(checkpointDomain, hi), sigBytes) {
		return "ok"
	}
	return "bad"
}

// verifyChain is the verdict-equivalent port of impl-py verify_chain / src/verify.ts verifyChain:
// structural validation → single chain partition + contiguous unique seq → per-receipt hash / key
// continuity / signature / identity binding / linkage → checkpoint tail-truncation + §5b binding.
// Any nil optional argument means "not supplied". Returns a status constant.
func verifyChain(receipts, keyring, identity, checkpoint *Value) string {
	if receipts == nil || receipts.Kind != KindArray || len(receipts.Arr) == 0 {
		return statusMalformed
	}
	haveKeyring := keyring != nil
	if haveKeyring && keyring.Kind != KindObject {
		return statusMalformed
	}
	if identity != nil {
		if identity.Kind != KindObject {
			return statusMalformed
		}
		for _, kids := range identity.Obj {
			if kids.Kind != KindArray {
				return statusMalformed
			}
			for _, k := range kids.Arr {
				if !k.isStr() {
					return statusMalformed
				}
			}
		}
	}

	// Step 1: structural validation of every element, BEFORE any hashing.
	for _, r := range receipts.Arr {
		if !validateReceiptShape(r) {
			return statusMalformed
		}
	}

	chainID := receipts.Arr[0].get("scope").get("chain").Str
	bySeq := make(map[int64]*Value, len(receipts.Arr))
	for _, r := range receipts.Arr {
		if r.get("scope").get("chain").Str != chainID {
			return statusTampered // multiple chain partitions
		}
		seq := r.get("chain").get("seq").Int
		if _, dup := bySeq[seq]; dup {
			return statusTampered // duplicate seq
		}
		bySeq[seq] = r
	}

	// Chain-wide scope.tenant consistency (fail-closed; matches the TS reference DEFAULT and
	// impl-py). scope.tenant sits beside scope.chain but was enforced nowhere, so a chain mixing
	// tenants verified clean in every implementation. Tenant isolation is a security boundary; the
	// same verdict class as the partition split above is the right one. Walked in SEQ order.
	// Only a present->DIFFERENT-present drift is a cross-tenant splice. absent<->present is a
	// producer-version change on an OPTIONAL field and is not tampering (see src/verify.ts).
	//
	// The comparison is NOT adjacent: comparing neighbours let an omission RESET the boundary, so
	// `acme -> globex` was TAMPERED while `acme -> absent -> globex` — the same splice with one
	// optional field left out in between — was VALID in all five implementations. The last PRESENT
	// tenant is carried across absences instead. Absence stays non-fatal; it just no longer erases
	// what the chain already committed to.
	nTenant := int64(len(receipts.Arr))
	lastPresent := ""
	haveLastPresent := false
	for s := int64(0); s < nTenant; s++ {
		cur, okCur := bySeq[s]
		if !okCur {
			break // a gap is reported by the seq-walk below; don't pre-empt it
		}
		if !cur.get("scope").has("tenant") {
			continue // absence never resets the boundary, and is never fatal
		}
		curTenant := cur.get("scope").get("tenant").Str
		if haveLastPresent && curTenant != lastPresent {
			return statusTampered // cross-tenant splice
		}
		lastPresent = curTenant
		haveLastPresent = true
	}

	pinned := make(map[string]string)
	var prev *Value
	n := int64(len(receipts.Arr))
	for s := int64(0); s < n; s++ {
		r, ok := bySeq[s]
		if !ok {
			return statusTampered // seq gap
		}
		hi, err := receiptHashInput(r)
		if err != nil {
			return statusMalformed // non-canonicalizable
		}
		if sha256Prefixed(hi) != r.get("chain").get("hash").Str {
			return statusTampered // hash mismatch
		}
		aid := r.get("agent").get("id").Str
		kid := r.get("sig").get("kid").Str
		if pk, ok := pinned[aid]; ok {
			if pk != kid {
				return statusTampered // key swap for agent
			}
		} else {
			pinned[aid] = kid
		}
		if haveKeyring {
			pub := keyring.get(kid)
			if pub == nil || !pub.isStr() || pub.Str == "" {
				return statusTampered // unknown kid
			}
			sigBytes, err := strictB64Decode(r.get("sig").get("value").Str)
			if err != nil {
				return statusTampered // bad signature/key encoding
			}
			pubRaw, err := spkiToRaw(pub.Str)
			if err != nil {
				return statusTampered
			}
			if !ed25519Verify(pubRaw, signingMessage(receiptDomain, hi), sigBytes) {
				return statusTampered // invalid signature
			}
			if identity != nil && !authorized(identity, aid, kid) {
				return statusUntrusted // cross-agent impersonation
			}
		}
		link := r.get("chain").get("prevHash")
		if s == 0 {
			if !link.isNull() {
				return statusTampered // genesis prevHash must be null
			}
		} else if !link.isStr() || link.Str != prev.get("chain").get("hash").Str {
			return statusTampered // broken linkage
		}
		prev = r
	}

	head := bySeq[n-1]
	if checkpoint != nil {
		cpv := verifyCheckpoint(checkpoint, keyring)
		if cpv == "bad" {
			return statusTampered
		}
		if haveKeyring && cpv != "ok" {
			return statusTampered // checkpoint not authenticated against keyring
		}
		if c := checkpoint.get("chain"); !c.isStr() || c.Str != chainID {
			return statusTampered // checkpoint chain mismatch
		}
		if hs := checkpoint.get("highestSeq"); !hs.isInt() || hs.Int != head.get("chain").get("seq").Int {
			return statusTampered // tail truncated/extended
		}
		if hh := checkpoint.get("headHash"); !hh.isStr() || hh.Str != head.get("chain").get("hash").Str {
			return statusTampered // tail truncated/extended
		}
		if haveKeyring && identity != nil {
			genesis := bySeq[0]
			gAid := genesis.get("agent").get("id").Str
			cpKid := checkpoint.get("sig").get("kid").Str
			if !authorized(identity, gAid, cpKid) {
				return statusUntrusted // checkpoint kid not authorized for chain opener
			}
		}
	}

	if haveKeyring {
		return statusValid
	}
	return statusUnverified
}
