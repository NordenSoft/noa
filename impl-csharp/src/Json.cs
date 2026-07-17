using System.Numerics;
using System.Text.Json;

namespace NoaReceipt;

/// <summary>Thrown for any input that must map to the MALFORMED verdict (exit 3).</summary>
public sealed class MalformedException : Exception
{
    public MalformedException(string message) : base(message) { }
}

// ── Parsed-tree model (integers only; floats/oversized ints are rejected at parse time) ──
public abstract class JVal { }

public sealed class JNull : JVal
{
    public static readonly JNull Instance = new();
    private JNull() { }
}

public sealed class JBool : JVal
{
    public readonly bool Value;
    public JBool(bool v) { Value = v; }
}

public sealed class JInt : JVal
{
    public readonly long Value; // guaranteed |v| <= 2^53-1
    public JInt(long v) { Value = v; }
}

public sealed class JStr : JVal
{
    public readonly string Value; // guaranteed well-formed UTF-16 (no lone surrogates)
    public JStr(string v) { Value = v; }
}

public sealed class JArr : JVal
{
    public readonly List<JVal> Items = new();
}

/// <summary>Insertion-ordered JSON object (duplicate keys are rejected at parse time).</summary>
public sealed class JObj : JVal
{
    public readonly List<string> Keys = new();
    public readonly Dictionary<string, JVal> Map = new(StringComparer.Ordinal);

    public bool Has(string k) => Map.ContainsKey(k);
    public JVal? Get(string k) => Map.TryGetValue(k, out var v) ? v : null;

    public void Add(string k, JVal v)
    {
        Keys.Add(k);
        Map[k] = v;
    }

    public void Remove(string k)
    {
        if (Map.Remove(k)) Keys.Remove(k);
    }

    public JObj DeepCloneObj() => (JObj)StrictJson.DeepClone(this);
}

/// <summary>
/// Strict JSON parser — parity with the TypeScript safeParse / Python strict_load_text:
/// rejects duplicate keys, floats, oversized ints (&gt; 2^53-1), NaN/Infinity, prototype-pollution
/// keys, lone UTF-16 surrogates in ANY string (key or value, any depth), and trailing garbage.
/// </summary>
public static class StrictJson
{
    private const long SafeIntMax = 9007199254740991L; // 2^53 - 1
    private static readonly BigInteger SafeIntMaxBig = SafeIntMax;

    // Mirror impl-py _strict_pairs: reject these object keys outright.
    private static readonly HashSet<string> Forbidden =
        new(StringComparer.Ordinal) { "__proto__", "constructor", "prototype" };

    public static JVal Parse(string text)
    {
        JsonDocument doc;
        try
        {
            // Default JsonDocumentOptions: MaxDepth 64, no comments, no trailing commas, and
            // trailing non-whitespace after the top-level value is rejected (→ MALFORMED).
            doc = JsonDocument.Parse(text);
        }
        catch (Exception e)
        {
            throw new MalformedException("invalid JSON: " + e.Message);
        }

        using (doc)
        {
            try
            {
                return Convert(doc.RootElement);
            }
            catch (MalformedException)
            {
                throw;
            }
            catch (Exception e)
            {
                // GetString()/property-name access throws on a lone surrogate (System.Text.Json
                // refuses to transcode it to UTF-8) — that is a MALFORMED input, never a crash.
                throw new MalformedException("invalid JSON content: " + e.Message);
            }
        }
    }

    private static JVal Convert(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Null:
                return JNull.Instance;
            case JsonValueKind.True:
                return new JBool(true);
            case JsonValueKind.False:
                return new JBool(false);
            case JsonValueKind.Number:
            {
                string raw = e.GetRawText();
                // Integers only. A '.', 'e' or 'E' means a float/exponent form → rejected
                // (parity with impl-py parse_float / jcs float-reject).
                if (raw.IndexOf('.') >= 0 || raw.IndexOf('e') >= 0 || raw.IndexOf('E') >= 0)
                    throw new MalformedException("non-integer (float) not allowed");
                if (!BigInteger.TryParse(raw, out BigInteger b))
                    throw new MalformedException("invalid integer literal");
                if (BigInteger.Abs(b) > SafeIntMaxBig)
                    throw new MalformedException("integer outside safe range (> 2^53-1)");
                return new JInt((long)b);
            }
            case JsonValueKind.String:
            {
                string s = e.GetString()!; // throws on a lone surrogate → caught → MALFORMED
                CheckWellFormed(s);
                return new JStr(s);
            }
            case JsonValueKind.Array:
            {
                var arr = new JArr();
                foreach (JsonElement item in e.EnumerateArray())
                    arr.Items.Add(Convert(item));
                return arr;
            }
            case JsonValueKind.Object:
            {
                var obj = new JObj();
                foreach (JsonProperty prop in e.EnumerateObject())
                {
                    string k = prop.Name; // throws on a lone surrogate → caught → MALFORMED
                    CheckWellFormed(k);
                    if (obj.Map.ContainsKey(k))
                        throw new MalformedException("duplicate key: " + k);
                    if (Forbidden.Contains(k))
                        throw new MalformedException("forbidden key: " + k);
                    obj.Add(k, Convert(prop.Value));
                }
                return obj;
            }
            default:
                throw new MalformedException("unsupported JSON token");
        }
    }

    /// <summary>Reject any lone (unpaired) UTF-16 surrogate — a forgery channel (would collapse
    /// to U+FFFD at the UTF-8 hashing step). Parity with jcs_string / isWellFormed().</summary>
    private static void CheckWellFormed(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1]))
                    throw new MalformedException("unpaired surrogate in string");
                i++; // valid pair — skip the low surrogate
            }
            else if (char.IsLowSurrogate(c))
            {
                throw new MalformedException("unpaired surrogate in string");
            }
        }
    }

    public static JVal DeepClone(JVal v)
    {
        switch (v)
        {
            case JNull:
                return JNull.Instance;
            case JBool b:
                return new JBool(b.Value);
            case JInt i:
                return new JInt(i.Value);
            case JStr s:
                return new JStr(s.Value);
            case JArr a:
            {
                var arr = new JArr();
                foreach (JVal it in a.Items) arr.Items.Add(DeepClone(it));
                return arr;
            }
            case JObj o:
            {
                var obj = new JObj();
                foreach (string k in o.Keys) obj.Add(k, DeepClone(o.Map[k]));
                return obj;
            }
            default:
                throw new MalformedException("uncloneable value");
        }
    }
}
