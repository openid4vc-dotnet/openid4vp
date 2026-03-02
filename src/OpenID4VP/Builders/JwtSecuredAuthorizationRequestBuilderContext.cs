using Microsoft.IdentityModel.Tokens;
using OpenID4VC.Core.Results;
using OpenID4VP.Dcql.Query.Serialization;
using OpenID4VP.Models;
using OpenID4VP.Validators;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

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
    private X509Certificate2[]? _certificateChain;

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
    /// Sets the expiration time for the JWT (exp claim).
    /// This is OPTIONAL. Defaults to 5 minutes.
    /// </summary>
    /// <param name="expirationTime">The expiration duration from now</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithExpirationTime(TimeSpan expirationTime)
    {
        _expirationTime = expirationTime;
        return this;
    }

    /// <summary>
    /// Sets the X.509 certificate chain to be included in the JWT header (x5c parameter) per RFC 7515.
    /// 
    /// Used for Client Identifiers with x509_san_dns prefix to:
    /// 1. Add certificate chain to JWT x5c header
    /// 2. Validate DNS name matches a dNSName SAN in the leaf certificate
    /// 3. Validate signing key corresponds to certificate public key
    /// 
    /// Per OpenID4VP and RFC 5280, when using x509_san_dns prefix:
    /// - The DNS name must match a dNSName entry in the leaf certificate's SAN
    /// - The request must be signed with the private key corresponding to the certificate
    /// </summary>
    /// <param name="certificateChain">X.509 certificate chain (leaf certificate first)</param>
    /// <returns>This builder context for fluent chaining</returns>
    public JwtSecuredAuthorizationRequestBuilderContext WithX509CertificateChain(X509Certificate2[] certificateChain)
    {
        if (certificateChain == null || certificateChain.Length == 0)
            throw new ArgumentException("Certificate chain cannot be null or empty", nameof(certificateChain));

        _certificateChain = certificateChain;
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
            // We need to build the JWT payload manually to preserve object types for complex fields like dcql_query
            var payloadDict = new Dictionary<string, object>();

            // Add all Authorization Request fields to the payload dict
            foreach (var kvp in requestDict)
            {
                // Keep JsonElements as-is to preserve their original structure (objects remain objects, arrays remain arrays)
                // This ensures dcql_query remains an object instead of being stringified
                payloadDict[kvp.Key] = kvp.Value;
            }

            // Add optional JWT standard claims
            if (!string.IsNullOrEmpty(_issuer))
                payloadDict["iss"] = _issuer;

            if (!string.IsNullOrEmpty(_audience))
                payloadDict["aud"] = _audience;

            // Add issued at time (iat) - required for RFC 9101
            var now = DateTime.UtcNow;
            payloadDict["iat"] = new DateTimeOffset(now).ToUnixTimeSeconds();

            // Add expiration time (exp)
            var expiry = now.Add(_expirationTime);
            payloadDict["exp"] = new DateTimeOffset(expiry).ToUnixTimeSeconds();

            // Step 3: Create JWT handler and signing credentials
            var handler = new JwtSecurityTokenHandler();
            var signingCredentials = new SigningCredentials(_signingKey, _signingAlgorithm);

            // Step 4: Manually serialize the payload dict to JSON to preserve object types
            var payloadJson = JsonSerializer.Serialize(payloadDict);

            // Create a custom JWT token with the full payload
            // We need to create the JWT manually because JwtSecurityToken requires string claims
            // but we need to preserve object types in the payload (like dcql_query being an object, not a string)
            
            // Create the JWT header
            var headerDict = new Dictionary<string, object>
            {
                { "typ", "oauth-authz-req+jwt" },
                { "alg", _signingAlgorithm }
            };
            
            // Add x5c header if certificate chain provided
            if (_certificateChain != null && _certificateChain.Length > 0)
            {
                // Validate x509_san_dns requirements if Client Identifier uses that prefix
                var x509ValidationResult = ValidateX509SanDnsRequirements(_request, _certificateChain, _signingKey);
                if (!x509ValidationResult.IsSuccess)
                    return Result<JwtSecuredAuthorizationRequest>.Failure(x509ValidationResult.Errors.ToArray());

                // Add x5c header: array of base64-encoded (not base64url) DER certificates per RFC 7515 Section 4.1.6
                var x5cArray = _certificateChain
                    .Select(cert => Convert.ToBase64String(cert.RawData))
                    .ToList();

                headerDict["x5c"] = x5cArray;
            }

            var headerJson = JsonSerializer.Serialize(headerDict);
            
            // Create the JWT token manually using the JwtPayload structure
            var jwtToken = CreateSignedJwt(handler, headerJson, payloadJson, signingCredentials);

            // Create a JwtSecurityToken for the Claims property (used for validation/inspection)
            // Build claims list for the token info object
            var tokenInfoClaims = new List<System.Security.Claims.Claim>();
            foreach (var kvp in payloadDict)
            {
                var claimValue = kvp.Value switch
                {
                    string s => s,
                    long l => l.ToString(),
                    int i => i.ToString(),
                    JsonElement je when je.ValueKind == JsonValueKind.String => je.GetString() ?? "",
                    _ => JsonSerializer.Serialize(kvp.Value, SnakeCaseOptions)
                };
                tokenInfoClaims.Add(new System.Security.Claims.Claim(kvp.Key, claimValue));
            }

            var tokenInfo = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: tokenInfoClaims,
                notBefore: now,
                expires: expiry,
                signingCredentials: signingCredentials);

            tokenInfo.Header["typ"] = "oauth-authz-req+jwt";
            
            // Step 8: Create the result
            var jar = new JwtSecuredAuthorizationRequest
            {
                Token = jwtToken,
                SigningAlgorithm = _signingAlgorithm,
                IsEncrypted = _encryptionKey != null,
                Claims = tokenInfo,
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
    /// Creates a signed JWT with custom payload that preserves object types (like dcql_query being an object, not a string).
    /// </summary>
    private static string CreateSignedJwt(JwtSecurityTokenHandler handler, string headerJson, string payloadJson, SigningCredentials signingCredentials)
    {
        // Encode header and payload
        var headerBytes = System.Text.Encoding.UTF8.GetBytes(headerJson);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payloadJson);
        
        var headerEncoded = Base64UrlEncode(headerBytes);
        var payloadEncoded = Base64UrlEncode(payloadBytes);
        
        var signatureInput = $"{headerEncoded}.{payloadEncoded}";
        var signatureInputBytes = System.Text.Encoding.UTF8.GetBytes(signatureInput);
        
        // Get the crypto object
        System.Security.Cryptography.AsymmetricAlgorithm crypto;
        if (signingCredentials.Key is RsaSecurityKey rsaKey)
        {
            // Use the underlying RSA object if available, otherwise create from parameters
            crypto = rsaKey.Rsa ?? System.Security.Cryptography.RSA.Create(rsaKey.Parameters);
        }
        else if (signingCredentials.Key is ECDsaSecurityKey ecdsaKey)
        {
            // Use the underlying ECDsa object if available
            crypto = ecdsaKey.ECDsa ?? System.Security.Cryptography.ECDsa.Create(ecdsaKey.ECDsa!.ExportParameters(false));
        }
        else if (signingCredentials.Key is SymmetricSecurityKey)
        {
            crypto = null!; // Will handle separately
        }
        else
        {
            throw new InvalidOperationException("Unsupported key type");
        }

        byte[] signatureBytes;
        
        try
        {
            if (signingCredentials.Algorithm.StartsWith("RS"))
            {
                // RSA signature
                var padding = System.Security.Cryptography.RSASignaturePadding.Pkcs1;
                var hashAlg = signingCredentials.Algorithm switch
                {
                    "RS256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
                    "RS384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
                    "RS512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
                    _ => throw new InvalidOperationException($"Unsupported algorithm: {signingCredentials.Algorithm}")
                };
                
                signatureBytes = ((System.Security.Cryptography.RSA)crypto).SignData(signatureInputBytes, hashAlg, padding);
            }
            else if (signingCredentials.Algorithm.StartsWith("ES"))
            {
                // ECDSA signature
                var hashAlg = signingCredentials.Algorithm switch
                {
                    "ES256" => System.Security.Cryptography.HashAlgorithmName.SHA256,
                    "ES384" => System.Security.Cryptography.HashAlgorithmName.SHA384,
                    "ES512" => System.Security.Cryptography.HashAlgorithmName.SHA512,
                    _ => throw new InvalidOperationException($"Unsupported algorithm: {signingCredentials.Algorithm}")
                };
                
                signatureBytes = ((System.Security.Cryptography.ECDsa)crypto).SignData(signatureInputBytes, hashAlg);
            }
            else if (signingCredentials.Algorithm == "HS256" && signingCredentials.Key is SymmetricSecurityKey symKey)
            {
                // HMAC signature
                using (var hmac = new System.Security.Cryptography.HMACSHA256(symKey.Key))
                {
                    signatureBytes = hmac.ComputeHash(signatureInputBytes);
                }
            }
            else
            {
                throw new InvalidOperationException($"Unsupported algorithm: {signingCredentials.Algorithm}");
            }
        }
        finally
        {
            crypto?.Dispose();
        }
        
        var signatureEncoded = Base64UrlEncode(signatureBytes);
        return $"{signatureInput}.{signatureEncoded}";
    }

    private static string Base64UrlEncode(byte[] data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
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

    /// <summary>
    /// Validates x509_san_dns requirements per OpenID4VP and RFC 5280:
    /// 1. DNS name matches a dNSName in leaf certificate's SAN
    /// 2. Signing key corresponds to certificate's public key
    /// </summary>
    private Result<bool> ValidateX509SanDnsRequirements(
        AuthorizationRequest request,
        X509Certificate2[] certificateChain,
        SecurityKey? signingKey)
    {
        if (certificateChain.Length == 0)
            return new ValidationError("Certificate chain is empty", "x509_chain_empty");

        var errors = new List<ValidationError>();
        
        // Check if Client Identifier uses x509_san_dns prefix
        if (!string.IsNullOrEmpty(request.ClientId) && request.ClientId.StartsWith("x509_san_dns:"))
        {
            var dnsName = request.ClientId.Substring("x509_san_dns:".Length);
            var leafCert = certificateChain[0];

            // Validate DNS name matches SAN
            var dnsValidation = ValidateDnsNameInSan(dnsName, leafCert);
            if (!dnsValidation)
                errors.Add(new ValidationError(
                    $"DNS name '{dnsName}' does not match any dNSName in certificate SAN",
                    "x509_dns_mismatch"));

            // Validate key correspondence
            if (signingKey != null)
            {
                var keyValidation = ValidateKeyCorrespondence(signingKey, leafCert);
                if (!keyValidation)
                    errors.Add(new ValidationError(
                        "Signing key does not correspond to certificate public key",
                        "x509_key_mismatch"));
            }
        }

        if (errors.Count > 0)
            return errors.ToArray();

        return true;
    }

    /// <summary>
    /// Validates that the DNS name matches a dNSName entry in the certificate's SAN.
    /// Per RFC 5280, compares case-insensitively and supports wildcard patterns.
    /// </summary>
    private static bool ValidateDnsNameInSan(string dnsName, X509Certificate2 certificate)
    {
        // Extract dNSName values from Subject Alternative Name extension
        var sanDnsNames = ExtractDnsNamesFromSan(certificate);
        
        if (sanDnsNames.Count == 0)
            return false;

        // Compare case-insensitively (DNS names are case-insensitive per RFC)
        var dnsNameLower = dnsName.ToLowerInvariant();
        
        foreach (var sanName in sanDnsNames)
        {
            if (sanName.Equals(dnsNameLower, StringComparison.OrdinalIgnoreCase))
                return true;

            // Support wildcard matching (e.g., *.example.com matches foo.example.com)
            if (IsWildcardMatch(dnsNameLower, sanName))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Extracts dNSName values from certificate's Subject Alternative Name extension.
    /// </summary>
    private static List<string> ExtractDnsNamesFromSan(X509Certificate2 certificate)
    {
        var dnsNames = new List<string>();

        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509SubjectAlternativeNameExtension subjectAlternativeNameExtension)
            {
                foreach(var dns in subjectAlternativeNameExtension.EnumerateDnsNames())
                {
                    dnsNames.Add(dns.ToLowerInvariant());
                }
            }
        }

        return dnsNames;
    }

    /// <summary>
    /// Checks if a DNS name matches a wildcard pattern.
    /// E.g., "foo.example.com" matches "*.example.com"
    /// </summary>
    private static bool IsWildcardMatch(string dnsName, string pattern)
    {
        if (!pattern.StartsWith("*.", StringComparison.Ordinal))
            return false;

        // Extract the suffix (without the *)
        var suffix = pattern.Substring(1); // Remove * but keep the .
        return dnsName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates that the signing key corresponds to the certificate's public key.
    /// Supports RSA and ECDSA keys.
    /// </summary>
    private static bool ValidateKeyCorrespondence(SecurityKey signingKey, X509Certificate2 certificate)
    {
        return signingKey switch
        {
            RsaSecurityKey rsaKey => ValidateRsaKeyCorrespondence(rsaKey, certificate.GetRSAPublicKey()),
            ECDsaSecurityKey ecdsaKey => ValidateEcdsaKeyCorrespondence(ecdsaKey, certificate.GetECDsaPublicKey()),
            _ => false // Unsupported key type
        };
    }

    /// <summary>
    /// Validates RSA key correspondence by comparing modulus and exponent.
    /// </summary>
    private static bool ValidateRsaKeyCorrespondence(RsaSecurityKey signingKey, AsymmetricAlgorithm? certPublicKey)
    {
        if (certPublicKey is not RSA certRsa)
            return false;

        try
        {
            var signingRsa = signingKey.Rsa;
            if (signingRsa == null)
                return false;

            var signingRsaParams = signingRsa.ExportParameters(false);
            var certRsaParams = certRsa.ExportParameters(false);

            // Compare modulus and exponent
            return (signingRsaParams.Modulus?.SequenceEqual(certRsaParams.Modulus ?? Array.Empty<byte>()) ?? false) &&
                   (signingRsaParams.Exponent?.SequenceEqual(certRsaParams.Exponent ?? Array.Empty<byte>()) ?? false);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates ECDSA key correspondence by comparing curve and public point.
    /// </summary>
    private static bool ValidateEcdsaKeyCorrespondence(ECDsaSecurityKey signingKey, AsymmetricAlgorithm? certPublicKey)
    {
        if (certPublicKey is not ECDsa certEcdsa)
            return false;

        try
        {
            var signingEcdsa = signingKey.ECDsa;
            if (signingEcdsa == null)
                return false;

            var signingEcdsaParams = signingEcdsa.ExportParameters(false);
            var certEcdsaParams = certEcdsa.ExportParameters(false);

            // Compare Q (public point) - X and Y coordinates
            return (signingEcdsaParams.Q.X?.SequenceEqual(certEcdsaParams.Q.X ?? Array.Empty<byte>()) ?? false) &&
                   (signingEcdsaParams.Q.Y?.SequenceEqual(certEcdsaParams.Q.Y ?? Array.Empty<byte>()) ?? false);
        }
        catch
        {
            return false;
        }
    }
}
