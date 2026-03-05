namespace OpenID4VP.Parsers;

using OpenID4VC.Core.Results;
using OpenID4VP.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public static class SdJwtParser
{
    public static Result<SdJwtResult> Parse(string sdJwtCombined)
    {
        var result = new SdJwtResult();

        // --- 1. Split --- //
        var parts = sdJwtCombined.Split('~');
        var jwt = parts[0];
        var disclosures = parts.Skip(1).Take(2).ToList();

        // --- 2. Decode JWT --- //
        var jwtParts = jwt.Split('.');
        result.HeaderJson = DecodeBase64UrlToString(jwtParts[0]);
        result.PayloadJson = DecodeBase64UrlToString(jwtParts[1]);

        using JsonDocument payloadDoc = JsonDocument.Parse(result.PayloadJson);
        var payload = payloadDoc.RootElement;
        var sdNode = payload.GetProperty("_sd");
        var sdAlg = payload.GetProperty("_sd_alg");
        var sdHashes = sdNode.EnumerateArray()
            .Select(x => x.GetString()!)
            .ToHashSet();

        // --- 3. Decode & validate disclosures --- //
        foreach (var d in disclosures)
        {
            var disclosureJson = DecodeBase64UrlToString(d);
            using var doc = JsonDocument.Parse(disclosureJson);
            var arr = doc.RootElement.EnumerateArray().ToList();

            var disp = new Disclosure
            {
                RawJson = disclosureJson,
                ClaimName = arr[1].GetString()!,
                Value = JsonSerializer.Deserialize<object>(arr[2].GetRawText()),
                Salt = arr[0].GetString()!,
            };

            // canonical JSON → hash
            string canonicalJson = JsonSerializer.Serialize(doc.RootElement);

            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(canonicalJson);
            var hashinput = System.Convert.ToBase64String(plainTextBytes);

            byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(hashinput));

            string digestB64Url = ToBase64Url(digest);

            disp.Digest = digestB64Url;

            // check of hash klopt
            if (sdHashes.Contains(digestB64Url))
                result.RevealedClaims[disp.ClaimName] = disp.Value!;

            result.Disclosures.Add(disp);
        }

        return result;
    }

    private static string DecodeBase64UrlToString(string input)
    {
        string normalized = input.Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');

        return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
    }

    private static string ToBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}