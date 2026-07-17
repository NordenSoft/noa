using System.Numerics;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace NoaReceipt;

/// <summary>
/// Ed25519 verification + SPKI/base64 handling, byte-for-byte strict with impl-py/noa_verify.py
/// and src/keys.ts. BouncyCastle performs the core RFC 8032 group equation; every strictness rule
/// that makes independent verifiers AGREE is re-implemented here at the boundary rather than left
/// to a library's runtime behavior:
///   - canonical base64 (round-trip) for both the signature and the keyring SPKI;
///   - exact 12-byte Ed25519 SPKI prefix + 44-byte length;
///   - small-order public-key rejection (the 8 canonical torsion encodings);
///   - non-canonical y &gt;= q public-key rejection;
///   - S &lt; L scalar check (Ed25519 signature malleability, RFC 8032 §5.1.7).
/// </summary>
public static class Crypto
{
    // AlgorithmIdentifier{1.3.101.112} + BIT STRING header for an Ed25519 SPKI.
    private static readonly byte[] SpkiPrefix = FromHex("302a300506032b6570032100");

    private static readonly BigInteger Q = (BigInteger.One << 255) - 19;
    private static readonly BigInteger L =
        (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    // The 8 canonical small-order Ed25519 public-key encodings (torsion subgroup, order dividing 8).
    // Mirrors SMALL_ORDER_PUBKEYS in src/keys.ts + impl-py — rejected so cofactored (OpenSSL) and
    // strict (Python/this) verifiers agree; a legitimate signing key is never a low-order point.
    private static readonly HashSet<string> SmallOrder = new(StringComparer.Ordinal)
    {
        "0100000000000000000000000000000000000000000000000000000000000000", // order 1 (identity)
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
        "0000000000000000000000000000000000000000000000000000000000000000", // order 4
        "0000000000000000000000000000000000000000000000000000000000000080", // order 4
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
    };

    /// <summary>
    /// Strict CANONICAL base64: .NET's decoder tolerates embedded whitespace and does not reject
    /// non-canonical trailing bits, so we require the decoded bytes to RE-ENCODE to exactly the
    /// input (parity with Python base64.b64decode(validate=True) + canonical round-trip and the TS
    /// Buffer.from round-trip). Throws on any non-canonical / non-alphabet input.
    /// </summary>
    public static byte[] StrictB64Decode(string s)
    {
        byte[] raw;
        try
        {
            raw = System.Convert.FromBase64String(s);
        }
        catch (Exception)
        {
            throw new FormatException("invalid base64");
        }
        if (System.Convert.ToBase64String(raw) != s)
            throw new FormatException("non-canonical base64");
        return raw;
    }

    /// <summary>base64(DER SPKI Ed25519) → raw 32-byte key. Rejects non-canonical base64, a wrong
    /// SPKI prefix/length, and small-order keys (parity with spki_to_raw).</summary>
    public static byte[] SpkiToRaw(string pubB64)
    {
        byte[] der = StrictB64Decode(pubB64);
        if (der.Length != 44 || !PrefixMatches(der))
            throw new FormatException("not a canonical Ed25519 SPKI");
        var raw = new byte[32];
        Array.Copy(der, 12, raw, 0, 32);
        if (SmallOrder.Contains(ToHex(raw)))
            throw new FormatException("small-order Ed25519 public key rejected");
        return raw;
    }

    /// <summary>True iff <paramref name="signature"/> (64 bytes) is a valid Ed25519 signature over
    /// <paramref name="message"/> for the raw 32-byte <paramref name="public32"/>. Never throws.</summary>
    public static bool Ed25519Verify(byte[] public32, byte[] message, byte[] signature)
    {
        try
        {
            if (signature.Length != 64 || public32.Length != 32) return false;

            // S < L (RFC 8032 §5.1.7): reject a non-canonical / malleated scalar (S' = S + L).
            BigInteger s = LittleEndianToBig(signature, 32, 32);
            if (s >= L) return false;

            // Public-key y-coordinate MUST be canonical (y < q); OpenSSL/cofactored verify would
            // otherwise accept a non-canonical y >= q encoding that the strict references reject.
            if (!PublicKeyYCanonical(public32)) return false;

            return Ed25519.Verify(signature, 0, public32, 0, message, 0, message.Length);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static bool PublicKeyYCanonical(byte[] pub32)
    {
        var y = new byte[32];
        Array.Copy(pub32, y, 32);
        y[31] = (byte)(y[31] & 0x7f); // clear the x-sign bit (bit 255)
        BigInteger yv = LittleEndianToBig(y, 0, 32);
        return yv < Q;
    }

    private static BigInteger LittleEndianToBig(byte[] data, int off, int len)
    {
        BigInteger v = BigInteger.Zero;
        for (int i = off + len - 1; i >= off; i--)
            v = (v << 8) | data[i];
        return v;
    }

    private static bool PrefixMatches(byte[] der)
    {
        for (int i = 0; i < SpkiPrefix.Length; i++)
            if (der[i] != SpkiPrefix[i]) return false;
        return true;
    }

    private static byte[] FromHex(string hex)
    {
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = System.Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private static string ToHex(byte[] data)
    {
        var sb = new System.Text.StringBuilder(data.Length * 2);
        foreach (byte b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
