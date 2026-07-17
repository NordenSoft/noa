using System.Security.Cryptography;
using System.Text;

namespace NoaReceipt;

public enum VerifyStatus
{
    Valid,
    Unverified,
    Tampered,
    Malformed,
    Untrusted,
}

public readonly struct VerifyResult
{
    public readonly VerifyStatus Status;
    public readonly string Detail;
    public VerifyResult(VerifyStatus status, string detail)
    {
        Status = status;
        Detail = detail;
    }
}

/// <summary>
/// Receipt-chain verification — verdict-equivalent to impl-py/noa_verify.py verify_chain and the
/// TS reference: structural validation, hash-chain integrity, Ed25519 signatures, per-agent key
/// continuity, identity binding (UNTRUSTED), and checkpoint tail-truncation + §5b opener-binding.
/// </summary>
public static class Verifier
{
    private static readonly byte[] ReceiptDomain = Encoding.UTF8.GetBytes("NOA-Receipt-v0.1-sig:");
    private static readonly byte[] CheckpointDomain = Encoding.UTF8.GetBytes("NOA-Checkpoint-v0.1-sig:");
    private const long SafeIntMax = 9007199254740991L;

    private static readonly HashSet<string> CheckpointKeys =
        new(StringComparer.Ordinal) { "spec", "chain", "highestSeq", "headHash", "ts", "sig" };

    // ── hash inputs ──────────────────────────────────────────────────────────
    private static string Sha256Prefixed(string canonical) =>
        "sha256:" + ToHex(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

    private static byte[] Sha256Digest(string canonical) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(canonical));

    /// <summary>JCS(receipt WITHOUT chain.hash AND sig.value).</summary>
    private static string ReceiptHashInput(JObj receipt)
    {
        JObj clone = receipt.DeepCloneObj();
        if (clone.Get("chain") is JObj ch) ch.Remove("hash");
        if (clone.Get("sig") is JObj sg) sg.Remove("value");
        return Jcs.Canonicalize(clone);
    }

    /// <summary>JCS(checkpoint WITHOUT sig.value).</summary>
    private static string CheckpointHashInput(JObj cp)
    {
        JObj clone = cp.DeepCloneObj();
        if (clone.Get("sig") is JObj sg) sg.Remove("value");
        return Jcs.Canonicalize(clone);
    }

    // ── checkpoint verification (mirrors _verify_checkpoint) ───────────────────
    private enum CpVerdict { Ok, Unverified, Bad }

    private static CpVerdict VerifyCheckpoint(JVal cpVal, JObj? keyring)
    {
        if (cpVal is not JObj cp) return CpVerdict.Bad;
        foreach (string k in cp.Keys)
            if (!CheckpointKeys.Contains(k)) return CpVerdict.Bad;
        if (StrOf(cp, "spec") != "noa.checkpoint/0.1") return CpVerdict.Bad;
        if (!(cp.Get("chain") is JStr chn && chn.Value.Length > 0)) return CpVerdict.Bad;
        if (cp.Get("highestSeq") is not JInt hs || hs.Value < 0 || hs.Value > SafeIntMax) return CpVerdict.Bad;
        if (!(cp.Get("headHash") is JStr hh && Schema.HashFormat(hh.Value))) return CpVerdict.Bad;
        if (!(cp.Get("ts") is JStr ts && Schema.Rfc3339(ts.Value))) return CpVerdict.Bad;

        if (cp.Get("sig") is not JObj sig) return CpVerdict.Bad;
        foreach (string k in sig.Keys)
            if (k != "alg" && k != "kid" && k != "value") return CpVerdict.Bad;
        if (StrOf(sig, "alg") != "ed25519") return CpVerdict.Bad;
        if (!(sig.Get("kid") is JStr kid && kid.Value.Length > 0)) return CpVerdict.Bad;
        if (!(sig.Get("value") is JStr sval && sval.Value.Length > 0)) return CpVerdict.Bad;

        JVal? pub = keyring?.Get(kid.Value);
        if (pub is not JStr pubStr) return CpVerdict.Unverified;

        try
        {
            byte[] digest = Sha256Digest(CheckpointHashInput(cp));
            byte[] msg = Concat(CheckpointDomain, digest);
            byte[] rawKey = Crypto.SpkiToRaw(pubStr.Value);
            byte[] sigBytes = Crypto.StrictB64Decode(sval.Value);
            return Crypto.Ed25519Verify(rawKey, msg, sigBytes) ? CpVerdict.Ok : CpVerdict.Bad;
        }
        catch (Exception)
        {
            return CpVerdict.Bad;
        }
    }

    private static bool Authorized(JObj manifest, string? agentId, string kid)
    {
        if (agentId is null) return false;
        if (manifest.Get(agentId) is not JArr kids) return false;
        foreach (JVal k in kids.Items)
            if (k is JStr ks && ks.Value == kid) return true;
        return false;
    }

    // ── the chain verifier ─────────────────────────────────────────────────────
    public static VerifyResult VerifyChain(JVal receiptsVal, JVal? keyringVal, JVal? identityVal, JVal? checkpointVal)
    {
        if (receiptsVal is not JArr arr || arr.Items.Count == 0)
            return new VerifyResult(VerifyStatus.Malformed, "input is not a non-empty array");

        if (keyringVal is not null && keyringVal is not JObj)
            return new VerifyResult(VerifyStatus.Malformed, "keyring must be an object (kid -> base64 SPKI)");

        JObj? identity = null;
        if (identityVal is not null)
        {
            if (identityVal is not JObj im)
                return new VerifyResult(VerifyStatus.Malformed, "identityManifest must be an object (agent.id -> kid[])");
            foreach (string aid in im.Keys)
            {
                if (im.Get(aid) is not JArr kids || !kids.Items.TrueForAll(x => x is JStr))
                    return new VerifyResult(VerifyStatus.Malformed, $"identityManifest[\"{aid}\"] must be an array of kid strings");
            }
            identity = im;
        }

        // Step 1: structural validation of every element, BEFORE any hashing.
        for (int idx = 0; idx < arr.Items.Count; idx++)
        {
            var (ok, errs) = Schema.Validate(arr.Items[idx]);
            if (!ok)
                return new VerifyResult(VerifyStatus.Malformed, $"receipt[{idx}]: " + string.Join("; ", errs));
        }

        JObj? keyring = keyringVal as JObj;
        bool haveKeyring = keyringVal is not null;

        var receipts = new List<JObj>();
        foreach (JVal v in arr.Items) receipts.Add((JObj)v);

        string? chainId = ChainOf(receipts[0]);

        // Single chain partition + duplicate-seq detection.
        var bySeq = new Dictionary<long, JObj>();
        foreach (JObj r in receipts)
        {
            if (ChainOf(r) != chainId)
                return new VerifyResult(VerifyStatus.Tampered, "multiple chain partitions");
            long seq = SeqOf(r);
            if (bySeq.ContainsKey(seq))
                return new VerifyResult(VerifyStatus.Tampered, $"duplicate seq {seq}");
            bySeq[seq] = r;
        }

        var pinned = new Dictionary<string, string>(StringComparer.Ordinal);
        JObj? prev = null;
        for (int s = 0; s < receipts.Count; s++)
        {
            if (!bySeq.TryGetValue(s, out JObj? r))
                return new VerifyResult(VerifyStatus.Tampered, $"seq gap: missing {s}");

            string hi;
            try
            {
                hi = ReceiptHashInput(r);
            }
            catch (Exception e)
            {
                return new VerifyResult(VerifyStatus.Malformed, $"non-canonicalizable: {e.Message}");
            }

            if (Sha256Prefixed(hi) != ChainHash(r))
                return new VerifyResult(VerifyStatus.Tampered, $"hash mismatch at seq {s}");

            string? aid = AgentId(r);
            string kid = SigKid(r);
            if (aid is not null)
            {
                if (pinned.TryGetValue(aid, out string? pk))
                {
                    if (pk != kid)
                        return new VerifyResult(VerifyStatus.Tampered, $"key swap for agent \"{aid}\" at seq {s}");
                }
                else
                {
                    pinned[aid] = kid;
                }
            }

            if (haveKeyring)
            {
                JVal? pub = keyring!.Get(kid);
                if (pub is not JStr pubStr)
                    return new VerifyResult(VerifyStatus.Tampered, $"unknown kid {kid} at seq {s}");
                byte[] msg = Concat(ReceiptDomain, Sha256Digest(hi));
                bool sigOk;
                try
                {
                    byte[] sigBytes = Crypto.StrictB64Decode(SigValue(r));
                    byte[] rawKey = Crypto.SpkiToRaw(pubStr.Value);
                    sigOk = Crypto.Ed25519Verify(rawKey, msg, sigBytes);
                }
                catch (Exception)
                {
                    return new VerifyResult(VerifyStatus.Tampered, $"bad signature/key encoding at seq {s}");
                }
                if (!sigOk)
                    return new VerifyResult(VerifyStatus.Tampered, $"invalid signature at seq {s}");

                if (identity is not null && !Authorized(identity, aid, kid))
                    return new VerifyResult(VerifyStatus.Untrusted, $"agent \"{aid}\" not authorized for kid \"{kid}\" at seq {s}");
            }

            // Linkage.
            JVal? link = PrevHash(r);
            if (s == 0)
            {
                if (link is not JNull)
                    return new VerifyResult(VerifyStatus.Tampered, "genesis prevHash must be null");
            }
            else
            {
                string? linkStr = link is JStr ls ? ls.Value : null;
                if (linkStr != ChainHash(prev!))
                    return new VerifyResult(VerifyStatus.Tampered, $"broken linkage at seq {s}");
            }
            prev = r;
        }

        JObj head = bySeq[receipts.Count - 1];
        var warnings = new List<string>();

        if (checkpointVal is not null)
        {
            CpVerdict cpv = VerifyCheckpoint(checkpointVal, keyring);
            if (cpv == CpVerdict.Bad)
                return new VerifyResult(VerifyStatus.Tampered, "checkpoint invalid");
            if (haveKeyring && cpv != CpVerdict.Ok)
                return new VerifyResult(VerifyStatus.Tampered, "checkpoint not authenticated against keyring");

            var cp = (JObj)checkpointVal;
            if (StrOf(cp, "chain") != chainId)
                return new VerifyResult(VerifyStatus.Tampered, "checkpoint chain mismatch");

            long cpSeq = cp.Get("highestSeq") is JInt hsq ? hsq.Value : -1;
            string? cpHead = StrOf(cp, "headHash");
            if (cpSeq != SeqOf(head) || cpHead != ChainHash(head))
                return new VerifyResult(VerifyStatus.Tampered, "chain head does not match checkpoint (tail truncated/extended)");

            if (haveKeyring && identity is not null)
            {
                JObj genesis = bySeq[0];
                string cpKid = SigKid(cp);
                if (!Authorized(identity, AgentId(genesis), cpKid))
                    return new VerifyResult(VerifyStatus.Untrusted, "checkpoint kid not authorized for chain opener (genesis) agent");

                var agents = new HashSet<string?>();
                foreach (JObj r in receipts) agents.Add(AgentId(r));
                if (agents.Count > 1)
                    warnings.Add("checkpoint completeness is opener-scoped: chain has >1 agent.id, a co-agent's tail is NOT separately certified");
            }
        }

        string detail = $"{receipts.Count} receipts, chain {chainId}";
        if (warnings.Count > 0)
            detail += " | " + string.Join(" | ", warnings);
        return new VerifyResult(haveKeyring ? VerifyStatus.Valid : VerifyStatus.Unverified, detail);
    }

    // ── field accessors (structural validation already guarantees presence/shape) ──
    private static string? ChainOf(JObj r) =>
        r.Get("scope") is JObj sc && sc.Get("chain") is JStr c ? c.Value : null;

    private static long SeqOf(JObj r) =>
        r.Get("chain") is JObj ch && ch.Get("seq") is JInt s ? s.Value : -1;

    private static string? ChainHash(JObj r) =>
        r.Get("chain") is JObj ch && ch.Get("hash") is JStr h ? h.Value : null;

    private static JVal? PrevHash(JObj r) =>
        r.Get("chain") is JObj ch ? ch.Get("prevHash") : null;

    private static string? AgentId(JObj r) =>
        r.Get("agent") is JObj a && a.Get("id") is JStr id ? id.Value : null;

    private static string SigKid(JObj r) =>
        r.Get("sig") is JObj s && s.Get("kid") is JStr k ? k.Value : "";

    private static string SigValue(JObj r) =>
        r.Get("sig") is JObj s && s.Get("value") is JStr v ? v.Value : "";

    private static string? StrOf(JObj o, string key) => o.Get(key) is JStr s ? s.Value : null;

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }

    private static string ToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
