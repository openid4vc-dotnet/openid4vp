using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Builders;

/// <summary>
/// Static factory for creating JSON Web Key Sets (JWKS) with public keys.
/// 
/// This builder helps users safely extract public keys from private keys
/// and assemble them into a JWKS that can be included in Authorization Requests.
/// 
/// IMPORTANT: JWKS must contain ONLY public keys. Private keys are never included.
/// This class enforces that requirement.
/// </summary>
public static class JwksBuilder
{
    private static readonly Random _random = new Random();

    /// <summary>
    /// Creates a JWKS containing a single public key extracted from an RSA private key.
    /// </summary>
    /// <param name="rsaPrivateKey">The RSA private key. Only the public component is extracted.</param>
    /// <param name="keyId">Optional key ID. If not provided, uses the key's existing KeyId or generates a random one.</param>
    /// <param name="keyUsage">Key usage (e.g., "sig" for signature, "enc" for encryption). Defaults to "sig".</param>
    /// <returns>A Result containing the JWKS with the public key, or an error if extraction fails.</returns>
    public static Result<JsonWebKeySet> CreatePublicKeySet(
        RsaSecurityKey rsaPrivateKey,
        string? keyId = null,
        string keyUsage = "sig")
    {
        if (rsaPrivateKey == null)
            return new ValidationError("RSA private key cannot be null", "null_key");

        try
        {
            // Export ONLY the public key (false = don't include private components)
            var rsaParameters = rsaPrivateKey.Rsa.ExportParameters(includePrivateParameters: false);
            var publicKey = new RsaSecurityKey(rsaParameters)
            {
                KeyId = keyId ?? rsaPrivateKey.KeyId ?? GenerateKeyId()
            };

            // Create JWKS with the public key
            var jwks = new JsonWebKeySet();
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);
            jwk.Use = keyUsage;
            jwks.Keys.Add(jwk);

            return jwks;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to extract public key from RSA key: {ex.Message}",
                "rsa_key_extraction_error");
        }
    }

    /// <summary>
    /// Creates a JWKS containing a single public key extracted from an ECDSA private key.
    /// </summary>
    /// <param name="ecdsaPrivateKey">The ECDSA private key. Only the public component is extracted.</param>
    /// <param name="keyId">Optional key ID. If not provided, uses the key's existing KeyId or generates a random one.</param>
    /// <param name="keyUsage">Key usage (e.g., "sig" for signature, "enc" for encryption). Defaults to "sig".</param>
    /// <returns>A Result containing the JWKS with the public key, or an error if extraction fails.</returns>
    public static Result<JsonWebKeySet> CreatePublicKeySet(
        ECDsaSecurityKey ecdsaPrivateKey,
        string? keyId = null,
        string keyUsage = "sig")
    {
        if (ecdsaPrivateKey == null)
            return new ValidationError("ECDSA private key cannot be null", "null_key");

        try
        {
            // Export ONLY the public key parameters
            var ecdsaParameters = ecdsaPrivateKey.ECDsa.ExportParameters(includePrivateParameters: false);
            
            // Create a new ECDsa with only public parameters
            var publicEcdsa = ECDsa.Create(ecdsaParameters);
            var publicKey = new ECDsaSecurityKey(publicEcdsa)
            {
                KeyId = keyId ?? ecdsaPrivateKey.KeyId ?? GenerateKeyId()
            };

            // Create JWKS with the public key
            var jwks = new JsonWebKeySet();
            var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(publicKey);
            jwk.Use = keyUsage;
            jwks.Keys.Add(jwk);

            return jwks;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to extract public key from ECDSA key: {ex.Message}",
                "ecdsa_key_extraction_error");
        }
    }

    /// <summary>
    /// Creates a JWKS containing public keys extracted from multiple private keys.
    /// </summary>
    /// <param name="privateKeys">The private keys to extract public keys from.</param>
    /// <param name="keyUsage">Key usage (e.g., "sig" for signature). Defaults to "sig".</param>
    /// <returns>A Result containing the JWKS with all public keys, or an error if any extraction fails.</returns>
    public static Result<JsonWebKeySet> CreatePublicKeySet(
        IEnumerable<SecurityKey> privateKeys,
        string keyUsage = "sig")
    {
        if (privateKeys == null)
            return new ValidationError("Private keys collection cannot be null", "null_keys");

        var keyList = privateKeys.ToList();
        if (!keyList.Any())
            return new ValidationError("Private keys collection cannot be empty", "empty_keys");

        try
        {
            var jwks = new JsonWebKeySet();

            foreach (var key in keyList)
            {
                switch (key)
                {
                    case RsaSecurityKey rsaKey:
                    {
                        var jwkResult = CreatePublicKeySet(rsaKey, keyUsage: keyUsage);
                        if (!jwkResult.IsSuccess)
                            return jwkResult;

                        // Add each key from the result JWKS
                        foreach (var jwk in jwkResult.Value.Keys)
                        {
                            jwks.Keys.Add(jwk);
                        }
                        break;
                    }
                    case ECDsaSecurityKey ecdsaKey:
                    {
                        var jwkResult = CreatePublicKeySet(ecdsaKey, keyUsage: keyUsage);
                        if (!jwkResult.IsSuccess)
                            return jwkResult;

                        foreach (var jwk in jwkResult.Value.Keys)
                        {
                            jwks.Keys.Add(jwk);
                        }
                        break;
                    }
                    default:
                        return new ValidationError(
                            $"Unsupported key type: {key.GetType().Name}. Only RSA and ECDSA keys are supported.",
                            "unsupported_key_type");
                }
            }

            return jwks;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to extract public keys: {ex.Message}",
                "key_extraction_error");
        }
    }

    /// <summary>
    /// Generates a random key ID.
    /// Format: "key-" followed by a random 8-character hex string.
    /// </summary>
    private static string GenerateKeyId()
    {
        var randomBytes = new byte[4];
        _random.NextBytes(randomBytes);
        var hex = BitConverter.ToString(randomBytes).Replace("-", "").ToLower();
        return $"key-{hex}";
    }

    /// <summary>
    /// Converts a JsonWebKeySet to a JsonElement for storage in ClientMetadata.
    /// </summary>
    /// <param name="jwks">The JsonWebKeySet to convert</param>
    /// <returns>A JsonElement representation of the JWKS</returns>
    public static JsonElement ConvertToJsonElement(JsonWebKeySet jwks)
    {
        if (jwks == null)
            throw new ArgumentNullException(nameof(jwks));

        try
        {
            // Serialize JWKS to JSON string
            var jsonString = System.Text.Json.JsonSerializer.Serialize(jwks);
            
            // Parse back to JsonElement
            var doc = System.Text.Json.JsonDocument.Parse(jsonString);
            return doc.RootElement.Clone();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to convert JsonWebKeySet to JsonElement: {ex.Message}", ex);
        }
    }
}
