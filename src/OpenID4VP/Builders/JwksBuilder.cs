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
    /// Extracts a public key from an RSA private key.
    /// The algorithm is automatically set based on the key usage:
    /// - For signature (sig): RS256 (RSA with SHA-256)
    /// - For encryption (enc): RSA-OAEP
    /// </summary>
    /// <param name="rsaPrivateKey">The RSA private key. Only the public component is extracted.</param>
    /// <param name="keyId">Optional key ID. If not provided, uses the key's existing KeyId or generates a random one.</param>
    /// <param name="keyUsage">Key usage (e.g., "sig" for signature, "enc" for encryption). Defaults to "sig".</param>
    /// <returns>A Result containing the public key, or an error if extraction fails.</returns>
    public static Result<JsonWebKey> CreatePublicKey(
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

            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);
            jwk.Use = keyUsage;
            // Set the algorithm based on key usage
            jwk.Alg = keyUsage == "enc" ? "RSA-OAEP" : "RS256";

            return jwk;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to extract public key from RSA key: {ex.Message}",
                "rsa_key_extraction_error");
        }
    }

    /// <summary>
    /// Extracts a public key from an ECDSA private key.
    /// The algorithm is automatically set based on the curve and usage:
    /// - For P-256 curve signature: ES256
    /// - For P-384 curve signature: ES384
    /// - For P-521 curve signature: ES512
    /// - For encryption: ECDH-ES+HKDF-256 (or similar ECDH variant depending on curve)
    /// </summary>
    /// <param name="ecdsaPrivateKey">The ECDSA private key. Only the public component is extracted.</param>
    /// <param name="keyId">Optional key ID. If not provided, uses the key's existing KeyId or generates a random one.</param>
    /// <param name="keyUsage">Key usage (e.g., "sig" for signature, "enc" for encryption). Defaults to "sig".</param>
    /// <returns>A Result containing the public key, or an error if extraction fails.</returns>
    public static Result<JsonWebKey> CreatePublicKey(
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

            var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(publicKey);
            jwk.Use = keyUsage;
            // Determine algorithm based on curve size
            jwk.Alg = DeriveEcdsaAlgorithm(ecdsaParameters.Curve, keyUsage);

            return jwk;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to extract public key from ECDSA key: {ex.Message}",
                "ecdsa_key_extraction_error");
        }
    }

    /// <summary>
    /// Determines the appropriate JOSE algorithm for an ECDSA key based on its curve and usage.
    /// </summary>
    /// <param name="curve">The ECCurve of the ECDSA key</param>
    /// <param name="keyUsage">Key usage ("sig" for signature, "enc" for encryption)</param>
    /// <returns>The appropriate JOSE algorithm identifier</returns>
    private static string DeriveEcdsaAlgorithm(ECCurve curve, string keyUsage)
    {
        if (keyUsage == "enc")
        {
            // For encryption, ECDH is used
            return "ECDH-ES+HKDF-256";
        }

        // For signature, determine based on curve name
        return curve.Oid.FriendlyName switch
        {
            "nistP256" or "prime256v1" => "ES256",
            "nistP384" => "ES384",
            "nistP521" => "ES512",
            _ => "ES256" // Default to ES256 for unknown curves
        };
    }

    /// <summary>
    /// Determines a recommended JWE "enc" (content encryption) algorithm based on the key type and size.
    /// The "enc" algorithm specifies the symmetric cipher used to encrypt the payload after key encryption.
    /// 
    /// Note: This provides a reasonable default. The actual enc algorithm should match the capabilities
    /// of the wallet and the security requirements of the application.
    /// </summary>
    /// <param name="securityKey">The security key (RSA or ECDSA)</param>
    /// <returns>A recommended JWE enc algorithm identifier, or "A128GCM" as default</returns>
    public static string DeriveRecommendedEncAlgorithm(SecurityKey? securityKey)
    {
        if (securityKey == null)
            return "A128GCM"; // Safe default

        switch (securityKey)
        {
            case RsaSecurityKey rsaKey:
                // For RSA keys, recommend based on key size
                // RSA 2048: A128GCM (128-bit AES-GCM)
                // RSA 3072: A192GCM (192-bit AES-GCM)
                // RSA 4096: A256GCM (256-bit AES-GCM)
                if (rsaKey.KeySize >= 4096)
                    return "A256GCM";
                if (rsaKey.KeySize >= 3072)
                    return "A192GCM";
                return "A128GCM";

            case ECDsaSecurityKey ecdsaKey:
                // For ECDSA keys, recommend based on curve size
                // P-256 (256-bit): A128GCM (128-bit AES-GCM)
                // P-384 (384-bit): A192GCM (192-bit AES-GCM)
                // P-521 (521-bit): A256GCM (256-bit AES-GCM)
                try
                {
                    var ecdsaParams = ecdsaKey.ECDsa.ExportParameters(false);
                    return ecdsaParams.Curve.Oid.FriendlyName switch
                    {
                        "nistP521" => "A256GCM",
                        "nistP384" => "A192GCM",
                        _ => "A128GCM"
                    };
                }
                catch
                {
                    return "A128GCM";
                }

            default:
                // Unknown key type, use safe default
                return "A128GCM";
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
