using System.Text.RegularExpressions;

namespace NoaReceipt;

/// <summary>
/// STRICT structural validation of a single NOA Receipt v0.1 — a faithful port of impl-py's
/// validate_receipt_shape / src/schema.ts validateReceiptShape. Runs BEFORE any hashing so a
/// crypto-consistent-but-out-of-spec receipt (smuggled field / bad enum / wrong spec / sig.alg
/// != ed25519 / over-long id) is MALFORMED, not VALID. Never throws (fail-closed).
///
/// Regex note: patterns are anchored with \A ... \z (NOT ^ ... $). .NET's `$` also matches just
/// before a single trailing newline, so \z is required to reject "value\n" exactly as the
/// normative JSON-Schema pattern (JS `$` = end-of-input) does.
/// </summary>
public static class Schema
{
    public const string ReceiptSpec = "noa.receipt/0.1";
    private const long SafeIntMax = 9007199254740991L; // 2^53 - 1

    private static readonly HashSet<string> RiskClasses =
        new(StringComparer.Ordinal) { "LOW", "MEDIUM", "HIGH", "CRITICAL", "IRREVERSIBLE" };
    private static readonly HashSet<string> Principals =
        new(StringComparer.Ordinal) { "HUMAN", "SERVICE", "POLICY", "SANDBOX_SIM" };
    private static readonly HashSet<string> Modes =
        new(StringComparer.Ordinal) { "off", "shadow", "approvals_on", "on" };
    private static readonly HashSet<string> Verdicts =
        new(StringComparer.Ordinal) { "ALLOWED", "BLOCKED", "DEFERRED", "EXECUTED", "FAILED", "ROLLED_BACK", "SIMULATED" };

    private static readonly Regex HashRe =
        new(@"\Asha256:[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex ParamsHashRe =
        new(@"\A(sha256|hmac-sha256):[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Rfc3339Re =
        new(@"\A[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:[0-9]{2})\z",
            RegexOptions.CultureInvariant);

    /// <summary>LEXICAL FORM ONLY — month 13 and hour 99 match [0-9]{2}. A trust artifact's
    /// timestamp is validated with <see cref="Rfc3339Instant"/>; this alone is not enough.</summary>
    public static bool Rfc3339(string s) => Rfc3339Re.IsMatch(s);
    public static bool HashFormat(string s) => HashRe.IsMatch(s);

    /// <summary>Real length of <paramref name="month"/> in <paramref name="year"/>; 0 for an
    /// out-of-range month, so any day then fails.</summary>
    private static int DaysInMonth(int year, int month) => month switch
    {
        1 or 3 or 5 or 7 or 8 or 10 or 12 => 31,
        4 or 6 or 9 or 11 => 30,
        2 => (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 29 : 28,
        _ => 0,
    };

    /// <summary>The two ASCII digits at <paramref name="i"/> as a number. The caller has already
    /// proven they ARE digits (Rfc3339Re matched).</summary>
    private static int Two(string s, int i) => (s[i] - '0') * 10 + (s[i + 1] - '0');

    /// <summary>
    /// RFC 3339 §5.6 date-time: the LEXICAL form <see cref="Rfc3339"/> accepts PLUS the field ranges
    /// the ABNF's own comments impose (month 01-12, mday by month and year including leap years,
    /// hour 00-23, minute 00-59, second 00-60, numoffset hours 00-23 / minutes 00-59). Mirrors
    /// impl-py _is_rfc3339_instant / src/scan.ts isRfc3339Instant.
    ///
    /// The pattern alone accepted "2026-13-45T99:99:99.000Z" — month 13, day 45, hour 99 — on a
    /// SIGNED, chain-valid CRITICAL receipt, in all five implementations. A ts that denotes no
    /// instant cannot be ordered against its neighbours; it is a "when" that can be argued both ways
    /// after the fact, and it is decidable with NO key material at all, so it belongs in the shape
    /// validator.
    ///
    /// SECOND 60 IS ACCEPTED ON PURPOSE: a leap second is a real instant that has really occurred 27
    /// times, and which UTC days carry one is an IERS table, not a property of the string.
    /// </summary>
    public static bool Rfc3339Instant(string s)
    {
        if (!Rfc3339Re.IsMatch(s)) return false;
        int year = Two(s, 0) * 100 + Two(s, 2);
        int month = Two(s, 5);
        int day = Two(s, 8);
        if (month < 1 || month > 12 || day < 1 || day > DaysInMonth(year, month)) return false;
        // 60 is the leap second, and it is legal.
        if (Two(s, 11) > 23 || Two(s, 14) > 59 || Two(s, 17) > 60) return false;
        // The lexical check already proved the tail is EITHER a single Z/z OR exactly ±HH:MM.
        int n = s.Length;
        if (s[n - 1] == 'Z' || s[n - 1] == 'z') return true;
        return Two(s, n - 5) <= 23 && Two(s, n - 2) <= 59;
    }

    public static (bool ok, List<string> errors) Validate(JVal value)
    {
        var errors = new List<string>();
        try
        {
            if (value is not JObj r)
                return (false, new List<string> { "receipt: not an object" });

            CheckExactKeys(r,
                new[] { "spec", "id", "ts", "scope", "agent", "action", "governance", "chain", "sig" },
                Array.Empty<string>(), "receipt", errors);

            if (Str(r, "spec") != ReceiptSpec)
                errors.Add($"receipt.spec: must be \"{ReceiptSpec}\"");

            string? rid = Str(r, "id");
            if (rid is null || rid.Length == 0 || CodePointCount(rid) > 128)
                errors.Add("receipt.id: non-empty string <=128 chars");

            string? ts = Str(r, "ts");
            // R5: Rfc3339Instant, not the bare pattern — a `ts` matching [0-9]{2} for a month is not a
            // moment in time. See Rfc3339Instant for why second 60 (a leap second) stays accepted.
            if (ts is null || !Rfc3339Instant(ts))
                errors.Add("receipt.ts: must be RFC 3339 UTC timestamp");

            // scope
            if (r.Get("scope") is JObj scope)
            {
                CheckExactKeys(scope, new[] { "chain" }, new[] { "tenant" }, "receipt.scope", errors);
                string? sc = Str(scope, "chain");
                if (sc is null || sc.Length == 0)
                    errors.Add("receipt.scope.chain: non-empty string");
                if (scope.Has("tenant") && scope.Get("tenant") is not JStr)
                    errors.Add("receipt.scope.tenant: string");
            }
            else
            {
                errors.Add("receipt.scope: object required");
            }

            // agent
            if (r.Get("agent") is JObj agent)
            {
                CheckExactKeys(agent, new[] { "id", "principal" }, new[] { "model" }, "receipt.agent", errors);
                string? aid = Str(agent, "id");
                if (aid is null || aid.Length == 0)
                    errors.Add("receipt.agent.id: non-empty string");
                if (!(Str(agent, "principal") is string pr && Principals.Contains(pr)))
                    errors.Add("receipt.agent.principal: invalid enum");
                if (agent.Has("model") && agent.Get("model") is not JNull && agent.Get("model") is not JStr)
                    errors.Add("receipt.agent.model: string or null");
            }
            else
            {
                errors.Add("receipt.agent: object required");
            }

            // action
            if (r.Get("action") is JObj action)
            {
                CheckExactKeys(action,
                    new[] { "id", "canonical", "riskClass", "paramsHash", "reversible" },
                    new[] { "rollbackRef" }, "receipt.action", errors);
                string? acid = Str(action, "id");
                if (acid is null || acid.Length == 0)
                    errors.Add("receipt.action.id: non-empty string");
                string? can = Str(action, "canonical");
                if (can is null || can.Length == 0)
                    errors.Add("receipt.action.canonical: non-empty string");
                if (!(Str(action, "riskClass") is string rc && RiskClasses.Contains(rc)))
                    errors.Add("receipt.action.riskClass: invalid enum");
                string? ph = Str(action, "paramsHash");
                if (ph is null || !ParamsHashRe.IsMatch(ph))
                    errors.Add("receipt.action.paramsHash: must match (sha256|hmac-sha256):<64 hex>");
                if (action.Get("reversible") is not JBool)
                    errors.Add("receipt.action.reversible: boolean");
                if (action.Has("rollbackRef") && action.Get("rollbackRef") is not JNull &&
                    action.Get("rollbackRef") is not JStr)
                    errors.Add("receipt.action.rollbackRef: string or null");
            }
            else
            {
                errors.Add("receipt.action: object required");
            }

            // governance
            if (r.Get("governance") is JObj gov)
            {
                CheckExactKeys(gov,
                    new[] { "mode", "verdict", "sandboxed" },
                    new[] { "ruleId", "approval", "compliance" }, "receipt.governance", errors);
                if (!(Str(gov, "mode") is string md && Modes.Contains(md)))
                    errors.Add("receipt.governance.mode: invalid enum");
                if (!(Str(gov, "verdict") is string vd && Verdicts.Contains(vd)))
                    errors.Add("receipt.governance.verdict: invalid enum");
                if (gov.Get("sandboxed") is not JBool)
                    errors.Add("receipt.governance.sandboxed: boolean");
                if (gov.Has("ruleId") && gov.Get("ruleId") is not JNull && gov.Get("ruleId") is not JStr)
                    errors.Add("receipt.governance.ruleId: string or null");

                if (gov.Has("approval") && gov.Get("approval") is not JNull)
                {
                    if (gov.Get("approval") is JObj ap)
                    {
                        CheckExactKeys(ap, new[] { "by", "at" }, Array.Empty<string>(),
                            "receipt.governance.approval", errors);
                        if (Str(ap, "by") is null)
                            errors.Add("receipt.governance.approval.by: string");
                        string? at = Str(ap, "at");
                        if (at is null || !Rfc3339Instant(at))
                            errors.Add("receipt.governance.approval.at: RFC 3339 UTC");
                    }
                    else
                    {
                        errors.Add("receipt.governance.approval: object or null");
                    }
                }

                if (gov.Has("compliance") && gov.Get("compliance") is not JNull)
                {
                    if (gov.Get("compliance") is JObj c)
                    {
                        CheckExactKeys(c, new[] { "policyHash", "readSetHash", "inputsHash" },
                            new[] { "verdict" }, "receipt.governance.compliance", errors);
                        foreach (string k in new[] { "policyHash", "readSetHash", "inputsHash" })
                        {
                            string? cv = Str(c, k);
                            if (cv is null || !HashRe.IsMatch(cv))
                                errors.Add($"receipt.governance.compliance.{k}: sha256:<64 hex>");
                        }
                        if (c.Has("verdict"))
                        {
                            string? cvd = Str(c, "verdict");
                            if (cvd != "ALLOW" && cvd != "DENY")
                                errors.Add("receipt.governance.compliance.verdict: must be \"ALLOW\" or \"DENY\"");
                        }
                    }
                    else
                    {
                        errors.Add("receipt.governance.compliance: object or null");
                    }
                }
            }
            else
            {
                errors.Add("receipt.governance: object required");
            }

            // ── CROSS-FIELD COHERENCE — A SIGNED RECEIPT MAY NOT CONTRADICT ITSELF ───────────────
            // Every check above reads ONE field. A receipt can satisfy all of them and still argue
            // both ways: agent.principal "SANDBOX_SIM" (the actor was the sandbox simulator) beside
            // governance.sandboxed false (this really happened), on a CRITICAL wire.transfer, signed
            // and chain-valid. Reproduced across all five verifiers, 25 of 25 VALID, before this.
            //
            // They live in the SHAPE validator, not on the signature path, for the same reason an
            // unknown smuggled field does: they are decidable with NO key material at all. Mirrors
            // impl-py validate_receipt_shape / src/schema.ts validateReceiptShapeParsed.
            //
            // Each rule is ONE-DIRECTIONAL, because the converse is legitimate: a SERVICE agent may
            // run inside a sandbox (conformance/golden/0.3.0/multi/chain.json holds such a VALID
            // receipt), and a reversible action need not carry a rollbackRef. The `is JBool { Value:
            // false }` patterns mean a field that already failed its own type check reports one
            // defect, not two.
            if (r.Get("agent") is JObj cAgent && r.Get("action") is JObj cAction &&
                r.Get("governance") is JObj cGov)
            {
                string? principal = Str(cAgent, "principal");
                string? verdict = Str(cGov, "verdict");
                bool sandboxedFalse = cGov.Get("sandboxed") is JBool { Value: false };
                bool reversibleFalse = cAction.Get("reversible") is JBool { Value: false };
                bool rollbackPresent = cAction.Has("rollbackRef") && cAction.Get("rollbackRef") is not JNull;

                // R1. Names the SANDBOX SIMULATOR as the actor while denying it was a simulation.
                if (principal == "SANDBOX_SIM" && sandboxedFalse)
                    errors.Add("receipt.governance.sandboxed: must be true when agent.principal is \"SANDBOX_SIM\"");
                // R2. Records a SIMULATED outcome while denying it was a simulation.
                if (verdict == "SIMULATED" && sandboxedFalse)
                    errors.Add("receipt.governance.sandboxed: must be true when governance.verdict is \"SIMULATED\"");
                // R3. An action declared impossible to undo, carrying the reference used to undo it.
                if (reversibleFalse && rollbackPresent)
                    errors.Add("receipt.action.rollbackRef: must be absent or null when action.reversible is false");
                // R4. Says the action WAS undone while declaring it could not be.
                if (verdict == "ROLLED_BACK" && reversibleFalse)
                    errors.Add("receipt.action.reversible: must be true when governance.verdict is \"ROLLED_BACK\"");
            }

            // chain
            if (r.Get("chain") is JObj ch)
            {
                CheckExactKeys(ch, new[] { "seq", "prevHash", "hash" }, Array.Empty<string>(),
                    "receipt.chain", errors);
                if (ch.Get("seq") is JInt seq)
                {
                    if (seq.Value < 0 || seq.Value > SafeIntMax)
                        errors.Add("receipt.chain.seq: non-negative safe integer");
                }
                else
                {
                    errors.Add("receipt.chain.seq: non-negative safe integer");
                }
                JVal? pv = ch.Get("prevHash");
                if (pv is not JNull && !(pv is JStr pvs && HashRe.IsMatch(pvs.Value)))
                    errors.Add("receipt.chain.prevHash: sha256:<64 hex> or null");
                string? hv = Str(ch, "hash");
                if (hv is null || !HashRe.IsMatch(hv))
                    errors.Add("receipt.chain.hash: sha256:<64 hex>");
            }
            else
            {
                errors.Add("receipt.chain: object required");
            }

            // sig (mandatory)
            if (r.Get("sig") is JObj sig)
            {
                CheckExactKeys(sig, new[] { "alg", "kid", "value" }, Array.Empty<string>(),
                    "receipt.sig", errors);
                if (Str(sig, "alg") != "ed25519")
                    errors.Add("receipt.sig.alg: must be \"ed25519\"");
                string? kid = Str(sig, "kid");
                if (kid is null || kid.Length == 0)
                    errors.Add("receipt.sig.kid: non-empty string");
                string? val = Str(sig, "value");
                if (val is null || val.Length == 0)
                    errors.Add("receipt.sig.value: non-empty string");
            }
            else
            {
                errors.Add("receipt.sig: object required (signatures are mandatory in v0.1)");
            }
        }
        catch (Exception e)
        {
            return (false, new List<string> { "receipt: structural-validation error: " + e.Message });
        }

        return (errors.Count == 0, errors);
    }

    private static void CheckExactKeys(JObj obj, string[] required, string[] optional, string path,
        List<string> errors)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal);
        foreach (string k in required) allowed.Add(k);
        foreach (string k in optional) allowed.Add(k);
        foreach (string k in obj.Keys)
            if (!allowed.Contains(k))
                errors.Add($"{path}: unknown field \"{k}\"");
        foreach (string k in required)
            if (!obj.Has(k))
                errors.Add($"{path}: missing required field \"{k}\"");
    }

    private static string? Str(JObj o, string key) => o.Get(key) is JStr s ? s.Value : null;

    /// <summary>Unicode code-point count (astral chars = 1), matching Python len() and the
    /// normative schema maxLength — NOT UTF-16 code units (string.Length).</summary>
    private static int CodePointCount(string s)
    {
        int count = 0;
        for (int i = 0; i < s.Length; i++)
        {
            count++;
            if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                i++;
        }
        return count;
    }
}
