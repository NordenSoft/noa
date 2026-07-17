// Command noa-verify is a THIRD, independent NOA-receipt verifier — pure Go, standard library
// only (crypto/ed25519, crypto/sha256, encoding/base64/hex), NO third-party modules and NO shared
// crypto or JCS with the TypeScript reference or the Python second verifier. It re-implements the
// frozen rules from scratch (its own strict JSON parser, its own RFC-8785 JCS, its own SPKI decode)
// and returns the SAME verdict as impl-py/noa_verify.py + src/verify.ts across the conformance corpus.
//
// Usage:  noa-verify <receipts.json> [keyring.json] [--identity <m.json>] [--checkpoint <cp.json>]
// Exit:   0 VALID · 1 UNVERIFIED (no keyring) · 2 TAMPERED · 3 MALFORMED · 4 usage · 5 UNTRUSTED
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var exitCodes = map[string]int{
	statusValid:      0,
	statusUnverified: 1,
	statusTampered:   2,
	statusMalformed:  3,
	statusUntrusted:  5,
}

func main() {
	os.Exit(run(os.Args))
}

func run(argv []string) (code int) {
	// Fail-closed: any unexpected panic collapses to MALFORMED (exit 3), never a raw crash —
	// matching impl-py's "never throws out of the verifier" contract.
	defer func() {
		if r := recover(); r != nil {
			printResult(statusMalformed, fmt.Sprintf("internal error: %v", r))
			code = exitCodes[statusMalformed]
		}
	}()

	args := argv[1:]
	var receiptsPath, keyringPath, identityPath, checkpointPath string
	const usage = "usage: noa-verify <receipts.json> [keyring.json] [--identity <m.json>] [--checkpoint <cp.json>]\n"

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--identity":
			if i+1 >= len(args) {
				fmt.Fprint(os.Stderr, usage)
				return 4
			}
			i++
			identityPath = args[i]
		case a == "--checkpoint":
			if i+1 >= len(args) {
				fmt.Fprint(os.Stderr, usage)
				return 4
			}
			i++
			checkpointPath = args[i]
		case strings.HasPrefix(a, "--"):
			fmt.Fprintf(os.Stderr, "unknown flag: %s\n", a)
			return 4
		case receiptsPath == "":
			receiptsPath = a
		case keyringPath == "":
			keyringPath = a
		default:
			fmt.Fprintf(os.Stderr, "unexpected arg: %s\n", a)
			return 4
		}
	}
	if receiptsPath == "" {
		fmt.Fprint(os.Stderr, usage)
		return 4
	}

	receipts, err := loadFile(receiptsPath)
	if err != nil {
		return malformed(err.Error())
	}
	var keyring, identity, checkpoint *Value
	if keyringPath != "" {
		if keyring, err = loadFile(keyringPath); err != nil {
			return malformed(err.Error())
		}
	}
	if identityPath != "" {
		if identity, err = loadFile(identityPath); err != nil {
			return malformed(err.Error())
		}
	}
	if checkpointPath != "" {
		if checkpoint, err = loadFile(checkpointPath); err != nil {
			return malformed(err.Error())
		}
	}

	// Parity with impl-py _main: an aux file that WAS given but loaded to a non-object is an
	// operator error → MALFORMED (never silently dropped, which would weaken enforcement).
	if identityPath != "" && (identity == nil || identity.Kind != KindObject) {
		return malformed("identityManifest must be an object (agent.id -> kid[])")
	}
	if checkpointPath != "" && (checkpoint == nil || checkpoint.Kind != KindObject) {
		return malformed("checkpoint must be an object")
	}
	if keyringPath != "" && (keyring == nil || keyring.Kind != KindObject) {
		return malformed("keyring must be an object (kid -> base64 SPKI)")
	}

	status := verifyChain(receipts, keyring, identity, checkpoint)
	printResult(status, "")
	return exitCodes[status]
}

func loadFile(path string) (*Value, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseStrict(string(data))
}

func malformed(detail string) int {
	printResult(statusMalformed, detail)
	return exitCodes[statusMalformed]
}

func printResult(status, detail string) {
	out := map[string]string{"status": status}
	if detail != "" {
		out["detail"] = detail
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
