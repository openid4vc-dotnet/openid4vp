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
        // Validate input
        if (string.IsNullOrWhiteSpace(sdJwtCombined))
            return new ParseError("SD-JWT string cannot be null or empty");

        var result = new SdJwtResult();

        // --- 1. Split JWT and disclosures --- //
        var parts = sdJwtCombined.Split('~');
        
        if (parts.Length < 2)
            return new ParseError("SD-JWT must contain at least a JWT and one disclosure (separated by ~)");

        var jwt = parts[0];
        if (string.IsNullOrWhiteSpace(jwt))
            return new ParseError("SD-JWT JWT part cannot be empty");

        var disclosures = parts.Skip(1).Take(2).ToList();

        // --- 2. Decode JWT --- //
        var jwtParts = jwt.Split('.');
        
        if (jwtParts.Length != 3)
            return new ParseError("JWT must have exactly 3 parts separated by dots (header.payload.signature)");

        // Decode header
        var headerDecodeResult = DecodeBase64Url(jwtParts[0]);
        if (!headerDecodeResult.IsSuccess)
            return headerDecodeResult.Errors[0]; // Return error directly
        result.HeaderJson = headerDecodeResult.Value!;

        // Decode payload
        var payloadDecodeResult = DecodeBase64Url(jwtParts[1]);
        if (!payloadDecodeResult.IsSuccess)
            return payloadDecodeResult.Errors[0]; // Return error directly
        result.PayloadJson = payloadDecodeResult.Value!;

        // Parse payload JSON
        JsonDocument? payloadDoc;
        try
        {
            payloadDoc = JsonDocument.Parse(result.PayloadJson);
        }
        catch (JsonException ex)
        {
            return new ParseError($"Failed to parse JWT payload as JSON: {ex.Message}");
        }

        using (payloadDoc)
        {
            var payload = payloadDoc.RootElement;

            // Check for required _sd property
            if (!payload.TryGetProperty("_sd", out var sdNode))
                return new ParseError("JWT payload must contain '_sd' property with array of disclosure hashes");

            if (sdNode.ValueKind != JsonValueKind.Array)
                return new ParseError("'_sd' property must be a JSON array");

            // Check for required _sd_alg property
            if (!payload.TryGetProperty("_sd_alg", out var sdAlgProp))
                return new ParseError("JWT payload must contain '_sd_alg' property specifying the hash algorithm");

            var sdHashes = new HashSet<string>();
            try
            {
                foreach (var hashElement in sdNode.EnumerateArray())
                {
                    var hashValue = hashElement.GetString();
                    if (!string.IsNullOrEmpty(hashValue))
                        sdHashes.Add(hashValue);
                }
            }
            catch (InvalidOperationException ex)
            {
                return new ParseError($"Failed to extract hashes from '_sd' array: {ex.Message}");
            }

            // --- 3. Decode & validate disclosures --- //
            foreach (var disclosureEncoded in disclosures)
            {
                if (string.IsNullOrWhiteSpace(disclosureEncoded))
                    continue; // Skip empty disclosures

                // Decode disclosure
                var disclosureDecodeResult = DecodeBase64Url(disclosureEncoded);
                if (!disclosureDecodeResult.IsSuccess)
                    return disclosureDecodeResult.Errors[0]; // Return error directly

                var disclosureJson = disclosureDecodeResult.Value!;

                // Parse disclosure JSON
                JsonDocument? disclosureDoc;
                try
                {
                    disclosureDoc = JsonDocument.Parse(disclosureJson);
                }
                catch (JsonException ex)
                {
                    return new ParseError($"Failed to parse disclosure as JSON: {ex.Message}");
                }

                using (disclosureDoc)
                {
                    // Validate disclosure is an array
                    if (disclosureDoc.RootElement.ValueKind != JsonValueKind.Array)
                        return new ParseError("Each disclosure must be a JSON array [salt, claim_name, claim_value]");

                    var arr = disclosureDoc.RootElement.EnumerateArray().ToList();

                    // Validate array has 3 elements
                    if (arr.Count != 3)
                        return new ParseError($"Disclosure array must have exactly 3 elements [salt, claim_name, claim_value], got {arr.Count}");

                    // Extract salt, claim name, and value
                    var saltValue = arr[0].GetString();
                    if (string.IsNullOrEmpty(saltValue))
                        return new ParseError("Disclosure salt (first element) cannot be null or empty");

                    var claimName = arr[1].GetString();
                    if (string.IsNullOrEmpty(claimName))
                        return new ParseError("Disclosure claim name (second element) cannot be null or empty");

                    object? claimValue;
                    try
                    {
                        claimValue = JsonSerializer.Deserialize<object>(arr[2].GetRawText());
                    }
                    catch (JsonException ex)
                    {
                        return new ParseError($"Failed to deserialize claim value from disclosure: {ex.Message}");
                    }

                    var disp = new Disclosure
                    {
                        RawJson = disclosureJson,
                        ClaimName = claimName,
                        Value = claimValue,
                        Salt = saltValue,
                    };

                    // Calculate hash of disclosure
                    try
                    {
                        string canonicalJson = JsonSerializer.Serialize(disclosureDoc.RootElement);
                        var plainTextBytes = Encoding.UTF8.GetBytes(canonicalJson);
                        var hashInput = Convert.ToBase64String(plainTextBytes);
                        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(hashInput));
                        string digestB64Url = ToBase64Url(digest);
                        disp.Digest = digestB64Url;

                        // Add to revealed claims if hash matches
                        if (sdHashes.Contains(digestB64Url))
                            result.RevealedClaims[claimName] = claimValue!;
                    }
                    catch (Exception ex)
                    {
                        return new ParseError($"Failed to compute disclosure hash: {ex.Message}");
                    }

                    result.Disclosures.Add(disp);
                }
            }
        }

        return result;
    }

    private static Result<string> DecodeBase64Url(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new ParseError("Base64URL input cannot be null or empty");

        try
        {
            string normalized = input.Replace('-', '+').Replace('_', '/');
            normalized = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');
            return Encoding.UTF8.GetString(Convert.FromBase64String(normalized));
        }
        catch (FormatException ex)
        {
            return new ParseError($"Invalid Base64URL encoding: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ParseError($"Failed to decode Base64URL: {ex.Message}");
        }
    }

    private static string ToBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
