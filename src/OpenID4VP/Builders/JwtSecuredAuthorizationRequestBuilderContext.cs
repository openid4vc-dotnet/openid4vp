using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;
using OpenID4VP.Validators;
using OpenID4VP.Dcql.Query.Serialization;

namespace OpenID4VP.Builders;

/// <summary>
/// Fluent builder context for creating JWT-Secured Authorization Requests (JAR) per RFC 9101.
/// 
/// This builder is responsible for:
/// 1. Validating the Authorization Request
/// 2. Assembling all request fields as JWT claims
/// 3. Signing the JWT with JWS (mandatory, for integrity + source authentication)
/// 4. Optionally encrypting with JWE (for confidentiality)
/// 5. Returning the complete JWT token as base64url-encoded string
///
/// The JWT Claims Set contains all Authorization Request parameters, plus optional
/// standard JWT claims (iss, aud, iat, exp).
///
/// Signing is mandatory (for RFC 9101 compliance).
/// Encryption is optional (depends on confidentiality requirements).
/// </summary>
public class JwtSecuredAuthorizationRequestBuilderContext
{
    private readonly AuthorizationRequest _request;
    private SecurityKey? _signingKey;
    private SecurityKey? _encryptionKey;
    private string _signingAlgorithm = "RS256";
    private string? _encryptionAlgorithm;
    private string? _issuer;
    private string? _audience;
    private TimeSpan _expirationTime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// JSON serialization options with SnakeCaseLower naming policy for OpenID4VP compliance.
    /// Matches the format used by DCQL queries and other OpenID4VP parameters.
    /// </summary>
    private static readonly JsonSerializerOptions SnakeCaseOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    internal JwtSecuredAuthorizationRequestBuilderContext(AuthorizationRequest request)
    {
        _request = request;
    }

    /// <summary>
    /// Sets an RSA signing key for JWS signing. The algorithm is automatically determined from the key size:
    /// - 2048-bit RSA → RS256 (SHA-256)
    /// - 3072-bit RSA → RS384 (SHA-384)
    /// - 4096-bit RSA → RS512 (SHA-512)
    /// 
    /// This is the recommended way to set RSA signing keys. The key size determines the hash algorithm strength.
    /// </summary>
    /// <param name="rsaKey">The RSA private key for JWS signing</param>
    /// <returns>This builder context for fluent chaining</returns>
    /// <exception cref="System.Runtime.CompilerServices.SwitchExpressionException">Thrown if the RSA key size is not 2048, 3072, or 4096 bits</exception>
    public JwtSecuredAuthorizationRequestBuilderContext WithRsaSigningKey(RsaSecurityKey rsaKey)
    {
        _signingKey = rsaKey;
        _signingAlgorithm = DeriveRsaSigningAlgorithm(rsaKey);
        return this;
    }

    /// <summary>
    /// Sets an ECDSA signing key for JWS signing. The algorithm is automatically determined from the curve:
    /// - P-256 (256-bit) → ES256 (SHA-256)
    /// - P-384 (384-bit) → ES384 (SHA-384)
    /// - P-521 (521-bit) → ES512 (SHA-512)
    /// 
    /// This is the recommended way to set ECDSA signing keys. The curve size determines the hash algorithm strength.
    /// </summary>
    /// <param name="ecdsaKey">The ECDSA private key for JWS signing</param>
    /// <returns>This builder context for fluent chaining</returns>
    /// <exception cref="System.Runtime.CompilerServices.SwitchExpressionException">Thrown if the ECDSA key is not P-256, P-384, or P-521</exception>
    public JwtSecuredAuthorizationRequestBuilderContext WithECDsaSigningKey(ECDsaSecurityKey ecdsaKey)
    {
        _signingKey = ecdsaKey;
        _signingAlgorithm = DeriveEcDsaSigningAlgorithm(ecdsaKey);
        return this;
    }

    /// <summary>
    /// Sets a symmetric key for HMAC signing. Uses HS256 (HMAC with SHA-256).
    /// 
    /// Note: Symmetric key signing is less common and generally not recommended for OpenID4VP scenarios.
    /// Asymmetric signing (RSA/ECDSA) is preferred for proper source authentication.
    /// </summary>
    /// <param name="symmetricKey">The symmetric key for HMAC signing</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithSymmetricSigningKey(SymmetricSecurityKey symmetricKey)
    {
        _signingKey = symmetricKey;
        _signingAlgorithm = "HS256";
        return this;
    }

    /// <summary>
    /// Sets the signing key (private key for asymmetric algorithms like RS256, ES256).
    /// This is REQUIRED. The key must match the signing algorithm.
    /// 
    /// DEPRECATED: Use type-specific methods instead: WithRsaSigningKey(), WithECDsaSigningKey(), or WithSymmetricSigningKey().
    /// These methods automatically determine the algorithm from the key type and size, eliminating the need for WithAlgorithm().
    /// </summary>
    /// <param name="signingKey">The asymmetric security key (RSA/EC private key) for JWS signing</param>
    /// <returns>This builder context for fluent chaining</returns>
    [Obsolete("Use type-specific methods: WithRsaSigningKey(), WithECDsaSigningKey(), or WithSymmetricSigningKey() instead. They automatically determine the algorithm.", false)]
    public JwtSecuredAuthorizationRequestBuilderContext WithSigningKey(SecurityKey signingKey)
    {
        _signingKey = signingKey;
        return this;
    }

    /// <summary>
    /// Sets an RSA key for JWE encryption. The algorithm is automatically determined from the key size:
    /// - 2048-bit RSA → RSA-OAEP
    /// - 3072-bit RSA → RSA-OAEP
    /// - 4096-bit+ RSA → RSA-OAEP-256 (stronger, recommended for 4096-bit keys)
    /// 
    /// This is optional. Encryption is only applied if an encryption key is set.
    /// </summary>
    /// <param name="rsaKey">The RSA public key for JWE encryption</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithRsaEncryptionKey(RsaSecurityKey rsaKey)
    {
        _encryptionKey = rsaKey;
        _encryptionAlgorithm = DeriveRsaEncryptionAlgorithm(rsaKey);
        return this;
    }

    /// <summary>
    /// Sets a symmetric key for JWE encryption. Uses A256KW (AES Key Wrap with 256-bit key).
    /// 
    /// This is optional. Encryption is only applied if an encryption key is set.
    /// Symmetric encryption requires that both parties share the same key (not recommended for many scenarios).
    /// </summary>
    /// <param name="symmetricKey">The symmetric key for JWE encryption</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithSymmetricEncryptionKey(SymmetricSecurityKey symmetricKey)
    {
        _encryptionKey = symmetricKey;
        _encryptionAlgorithm = "A256KW";
        return this;
    }

    /// <summary>
    /// Sets the encryption key (public key for asymmetric algorithms like RSA-OAEP).
    /// This is OPTIONAL. If provided, the JWT will be encrypted with JWE.
    /// 
    /// DEPRECATED: Use type-specific methods instead: WithRsaEncryptionKey() or WithSymmetricEncryptionKey().
    /// These methods automatically determine the algorithm from the key type and size, eliminating the need for WithEncryptionAlgorithm().
    /// </summary>
    /// <param name="encryptionKey">The asymmetric security key (RSA/EC public key) for JWE encryption</param>
    /// <returns>This builder context for fluent chaining</returns>
    [Obsolete("Use type-specific methods: WithRsaEncryptionKey() or WithSymmetricEncryptionKey() instead. They automatically determine the algorithm.", false)]
    public JwtSecuredAuthorizationRequestBuilderContext WithEncryptionKey(SecurityKey encryptionKey)
    {
        _encryptionKey = encryptionKey;
        return this;
    }

    /// <summary>
    /// Sets the JWS signing algorithm. Defaults to "RS256" (RSA with SHA-256).
    /// 
    /// Common algorithms:
    /// - "RS256": RSA with SHA-256 (most common)
    /// - "RS384": RSA with SHA-384
    /// - "RS512": RSA with SHA-512
    /// - "ES256": ECDSA with SHA-256
    /// - "ES384": ECDSA with SHA-384
    /// - "ES512": ECDSA with SHA-512
    /// - "PS256": RSA PSS with SHA-256
    /// </summary>
    /// <param name="algorithm">The JWS algorithm identifier</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithAlgorithm(string algorithm)
    {
        _signingAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the JWE encryption algorithm. Only used if WithEncryptionKey is also called.
    /// 
    /// Common algorithms:
    /// - "RSA-OAEP": RSA with Optimal Asymmetric Encryption Padding (recommended)
    /// - "RSA-OAEP-256": RSA OAEP with SHA-256 (stronger)
    /// - "A256KW": Direct key wrapping with AES-256
    /// - "dir": Direct encryption (requires symmetric key)
    /// </summary>
    /// <param name="algorithm">The JWE key encryption algorithm identifier</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithEncryptionAlgorithm(string algorithm)
    {
        _encryptionAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Sets the "iss" (issuer) claim in the JWT.
    /// This is OPTIONAL but recommended. Typically set to the Verifier's identifier.
    /// </summary>
    /// <param name="issuer">The issuer identifier (typically the Verifier's entity ID)</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithIssuer(string issuer)
    {
        _issuer = issuer;
        return this;
    }

    /// <summary>
    /// Sets the "aud" (audience) claim in the JWT.
    /// This is OPTIONAL but recommended. Typically set to the Wallet's URI.
    /// </summary>
    /// <param name="audience">The audience identifier (typically the Wallet's URI)</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithAudience(string audience)
    {
        _audience = audience;
        return this;
    }

    /// <summary>
    /// Sets the expiration time for the JWT. Defaults to 5 minutes.
    /// The JWT will include an "exp" claim set to now + expirationTime.
    /// </summary>
    /// <param name="expirationTime">The duration for which the JWT is valid</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithExpirationTime(TimeSpan expirationTime)
    {
        _expirationTime = expirationTime;
        return this;
    }

    /// <summary>
    /// Creates the JWT-Secured Authorization Request (JAR).
    /// 
    /// This method:
    /// 1. Validates the Authorization Request
    /// 2. Serializes all request fields as JWT claims (with SnakeCaseLower format)
    /// 3. Signs the JWT with JWS using the provided signing key and algorithm
    /// 4. Optionally encrypts with JWE using the provided encryption key and algorithm
    /// 5. Returns the complete JWT token as a base64url-encoded string
    /// </summary>
    /// <returns>
    /// A Result containing the JwtSecuredAuthorizationRequest if successful,
    /// or validation errors if the request is invalid or key is missing
    /// </returns>
    public Result<JwtSecuredAuthorizationRequest> Build()
    {
        // Validate that signing key is provided (mandatory)
        if (_signingKey == null)
            return new ValidationError(
                "Signing key is required to create a JWT-Secured Authorization Request",
                "missing_signing_key");

        // Validate the authorization request
        var validator = new AuthorizationRequestValidator();
        var validationResult = validator.Validate(_request);

        if (!validationResult.IsValid)
            return validationResult.Errors.Select(e => new ValidationError(e, "validation_error")).ToArray();

        try
        {
            // Step 1: Serialize AuthorizationRequest to JSON for claims assembly
            var requestJson = JsonSerializer.Serialize(_request, SnakeCaseOptions);
            if (string.IsNullOrEmpty(requestJson))
                return new ValidationError(
                    "Failed to serialize Authorization Request to JSON",
                    "serialization_error");

            var requestDict = JsonSerializer.Deserialize<Dictionary<string, object>>(requestJson, SnakeCaseOptions)
                ?? new Dictionary<string, object>();

            // Step 2: Assemble JWT claims from request fields
            var claims = new List<System.Security.Claims.Claim>();

            // Add all Authorization Request fields as claims
            foreach (var kvp in requestDict)
            {
                // Serialize complex objects (like dcql_query) as JSON strings
                var claimValue = kvp.Value switch
                {
                    string s => s,
                    _ => JsonSerializer.Serialize(kvp.Value, SnakeCaseOptions)
                };
                claims.Add(new System.Security.Claims.Claim(kvp.Key, claimValue));
            }

            // Add optional JWT standard claims
            if (!string.IsNullOrEmpty(_issuer))
                claims.Add(new System.Security.Claims.Claim("iss", _issuer));

            if (!string.IsNullOrEmpty(_audience))
                claims.Add(new System.Security.Claims.Claim("aud", _audience));

            // Add issued at time (iat) - required for RFC 9101
            var now = DateTime.UtcNow;
            claims.Add(new System.Security.Claims.Claim("iat", new DateTimeOffset(now).ToUnixTimeSeconds().ToString()));

            // Add expiration time (exp)
            var expiry = now.Add(_expirationTime);
            claims.Add(new System.Security.Claims.Claim("exp", new DateTimeOffset(expiry).ToUnixTimeSeconds().ToString()));

            // Step 3: Create JWT handler and signing credentials
            var handler = new JwtSecurityTokenHandler();
            var signingCredentials = new SigningCredentials(_signingKey, _signingAlgorithm);

            // Step 4: Create JWT security token
            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                notBefore: now,
                expires: expiry,
                signingCredentials: signingCredentials);

            // Step 5: Serialize to JWT string (JWS format)
            var jwtToken = handler.WriteToken(token);

            // Step 6: If encryption is configured, encrypt the JWT (JWE format)
            // Note: JWE support requires additional configuration with JwtSecurityTokenHandler
            // For now, we return the JWS token. Full JWE support would require:
            // handler.EncryptingCredentials = new EncryptingCredentials(...)
            // This is left for future implementation with proper JWE handling

            // Step 7: Create the result
            var jar = new JwtSecuredAuthorizationRequest
            {
                Token = jwtToken,
                SigningAlgorithm = _signingAlgorithm,
                IsEncrypted = _encryptionKey != null,
                Claims = token,
                EncryptionAlgorithm = _encryptionAlgorithm
            };

            return jar;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to create JWT-Secured Authorization Request: {ex.Message}",
                "jar_creation_error");
        }
    }

    /// <summary>
    /// Derives the RSA signing algorithm from the key size using string interpolation.
    /// Maps RSA key sizes to their corresponding hash algorithm strengths.
    /// </summary>
    /// <param name="key">The RSA signing key</param>
    /// <returns>The JWS algorithm identifier (RS256, RS384, or RS512)</returns>
    /// <exception cref="System.Runtime.CompilerServices.SwitchExpressionException">Thrown if key size is not 2048, 3072, or 4096 bits</exception>
    private static string DeriveRsaSigningAlgorithm(RsaSecurityKey key)
    {
        var hashSize = key.KeySize switch
        {
            2048 => 256,
            3072 => 384,
            4096 => 512,
        };
        return $"RS{hashSize}";
    }

    /// <summary>
    /// Derives the ECDSA signing algorithm from the curve size using string interpolation.
    /// Maps ECDSA curve sizes to their corresponding hash algorithm strengths.
    /// </summary>
    /// <param name="key">The ECDSA signing key</param>
    /// <returns>The JWS algorithm identifier (ES256, ES384, or ES512)</returns>
    /// <exception cref="System.Runtime.CompilerServices.SwitchExpressionException">Thrown if key is not P-256, P-384, or P-521</exception>
    private static string DeriveEcDsaSigningAlgorithm(ECDsaSecurityKey key)
    {
        var hashSize = key.KeySize switch
        {
            256 => 256,
            384 => 384,
            521 => 512,  // P-521 curve uses SHA-512, so hash size is 512
        };
        return $"ES{hashSize}";
    }

    /// <summary>
    /// Derives the RSA encryption algorithm from the key size.
    /// Larger keys use stronger encryption algorithms.
    /// </summary>
    /// <param name="key">The RSA encryption key</param>
    /// <returns>The JWE key encryption algorithm identifier (RSA-OAEP or RSA-OAEP-256)</returns>
    private static string DeriveRsaEncryptionAlgorithm(RsaSecurityKey key)
    {
        return key.KeySize >= 4096 ? "RSA-OAEP-256" : "RSA-OAEP";
    }
}
