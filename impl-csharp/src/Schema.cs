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

    public static bool Rfc3339(string s) => Rfc3339Re.IsMatch(s);
    public static bool HashFormat(string s) => HashRe.IsMatch(s);

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
            if (ts is null || !Rfc3339(ts))
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
                        if (at is null || !Rfc3339(at))
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
