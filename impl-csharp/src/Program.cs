using System.Text.Json;

namespace NoaReceipt;

/// <summary>
/// CLI — a faithful port of impl-py/noa_verify.py's _main.
///
/// Usage: noa-verify &lt;receipts.json&gt; [keyring.json] [--identity m.json] [--checkpoint cp.json]
///        dotnet run --project impl-csharp -- &lt;receipts.json&gt; [keyring.json] [...]
///
/// Exit: 0 VALID · 1 UNVERIFIED (no keyring) · 2 TAMPERED · 3 MALFORMED · 4 USAGE · 5 UNTRUSTED
/// </summary>
public static class Program
{
    private const string Usage =
        "usage: noa-verify <receipts.json> [keyring.json] [--identity <m.json>] [--checkpoint <cp.json>]";

    private static int ExitCode(VerifyStatus s) => s switch
    {
        VerifyStatus.Valid => 0,
        VerifyStatus.Unverified => 1,
        VerifyStatus.Tampered => 2,
        VerifyStatus.Malformed => 3,
        VerifyStatus.Untrusted => 5,
        _ => 3,
    };

    public static int Main(string[] args)
    {
        string? receiptsPath = null, keyringPath = null, identityPath = null, checkpointPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            // A trailing --identity/--checkpoint with NO following path must NOT silently drop the
            // control (fail-open); emit usage + exit 4, exactly like the Python/TS CLI.
            if (a == "--identity")
            {
                if (i + 1 >= args.Length) { Console.Error.WriteLine(Usage); return 4; }
                identityPath = args[++i];
            }
            else if (a == "--checkpoint")
            {
                if (i + 1 >= args.Length) { Console.Error.WriteLine(Usage); return 4; }
                checkpointPath = args[++i];
            }
            else if (a.StartsWith("--", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("unknown flag: " + a);
                return 4;
            }
            else if (receiptsPath is null) receiptsPath = a;
            else if (keyringPath is null) keyringPath = a;
            else { Console.Error.WriteLine("unexpected arg: " + a); return 4; }
        }

        if (receiptsPath is null) { Console.Error.WriteLine(Usage); return 4; }

        JVal receipts, keyring = null!, identity = null!, checkpoint = null!;
        bool haveKeyring = keyringPath is not null;
        bool haveIdentity = identityPath is not null;
        bool haveCheckpoint = checkpointPath is not null;
        try
        {
            receipts = StrictJson.Parse(File.ReadAllText(receiptsPath));
            if (haveKeyring) keyring = StrictJson.Parse(File.ReadAllText(keyringPath!));
            if (haveIdentity) identity = StrictJson.Parse(File.ReadAllText(identityPath!));
            if (haveCheckpoint) checkpoint = StrictJson.Parse(File.ReadAllText(checkpointPath!));
        }
        catch (Exception e)
        {
            PrintCompact("MALFORMED", e.Message);
            return 3;
        }

        // A trust/aux file GIVEN but loaded to a non-object is an operator error, not "absent"
        // (mirrors the TS in-process `opts.X !== undefined` semantics + the Python _main guards).
        if (haveIdentity && identity is not JObj)
        {
            PrintCompact("MALFORMED", "identityManifest must be an object (agent.id -> kid[])");
            return 3;
        }
        if (haveCheckpoint && checkpoint is not JObj)
        {
            PrintCompact("MALFORMED", "checkpoint must be an object");
            return 3;
        }
        if (haveKeyring && keyring is not JObj)
        {
            PrintCompact("MALFORMED", "keyring must be an object (kid -> base64 SPKI)");
            return 3;
        }

        VerifyResult result = Verifier.VerifyChain(
            receipts,
            haveKeyring ? keyring : null,
            haveIdentity ? identity : null,
            haveCheckpoint ? checkpoint : null);

        PrintPretty(StatusName(result.Status), result.Detail);
        return ExitCode(result.Status);
    }

    private static string StatusName(VerifyStatus s) => s switch
    {
        VerifyStatus.Valid => "VALID",
        VerifyStatus.Unverified => "UNVERIFIED",
        VerifyStatus.Tampered => "TAMPERED",
        VerifyStatus.Malformed => "MALFORMED",
        VerifyStatus.Untrusted => "UNTRUSTED",
        _ => "MALFORMED",
    };

    private static void PrintCompact(string status, string detail)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { status, detail }));
    }

    private static void PrintPretty(string status, string detail)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { status, detail },
            new JsonSerializerOptions { WriteIndented = true }));
    }
}
