using System.Globalization;
using System.Text;

namespace NoaReceipt;

/// <summary>
/// RFC 8785 (JSON Canonicalization Scheme), hardened for NOA receipts — a byte-exact port of
/// src/jcs.ts and impl-py's jcs():
///   - integer-only numbers (floats already rejected at parse);
///   - object keys sorted by UTF-16 code units (ordinal);
///   - RFC 8785 string escaping (control chars escaped, everything else literal UTF-8, no NFC);
///   - lone surrogates already rejected at parse, so every surrogate here is paired.
/// The canonical STRING is the hash input; its UTF-8 bytes are what get SHA-256'd.
/// </summary>
public static class Jcs
{
    public static string Canonicalize(JVal v)
    {
        var sb = new StringBuilder();
        Write(v, sb);
        return sb.ToString();
    }

    private static void Write(JVal v, StringBuilder sb)
    {
        switch (v)
        {
            case JNull:
                sb.Append("null");
                break;
            case JBool b:
                sb.Append(b.Value ? "true" : "false");
                break;
            case JInt i:
                sb.Append(i.Value.ToString(CultureInfo.InvariantCulture));
                break;
            case JStr s:
                WriteString(s.Value, sb);
                break;
            case JArr a:
            {
                sb.Append('[');
                for (int k = 0; k < a.Items.Count; k++)
                {
                    if (k > 0) sb.Append(',');
                    Write(a.Items[k], sb);
                }
                sb.Append(']');
                break;
            }
            case JObj o:
            {
                // UTF-16 code-unit key order: StringComparer.Ordinal compares char-by-char by
                // numeric code-unit value, identical to JS default sort + Python utf-16-be sort.
                var keys = new List<string>(o.Keys);
                keys.Sort(StringComparer.Ordinal);
                sb.Append('{');
                for (int k = 0; k < keys.Count; k++)
                {
                    if (k > 0) sb.Append(',');
                    WriteString(keys[k], sb);
                    sb.Append(':');
                    Write(o.Map[keys[k]], sb);
                }
                sb.Append('}');
                break;
            }
            default:
                throw new MalformedException("unsupported value type in canonicalization");
        }
    }

    private static void WriteString(string s, StringBuilder sb)
    {
        sb.Append('"');
        foreach (char ch in s)
        {
            switch (ch)
            {
                case '"':
                    sb.Append("\\\"");
                    break;
                case '\\':
                    sb.Append("\\\\");
                    break;
                case '\b':
                    sb.Append("\\b");
                    break;
                case '\f':
                    sb.Append("\\f");
                    break;
                case '\n':
                    sb.Append("\\n");
                    break;
                case '\r':
                    sb.Append("\\r");
                    break;
                case '\t':
                    sb.Append("\\t");
                    break;
                default:
                    if (ch < 0x20)
                        sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else
                        sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
    }
}
