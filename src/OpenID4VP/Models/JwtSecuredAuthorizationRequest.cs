using System.IdentityModel.Tokens.Jwt;

namespace OpenID4VP.Models;

/// <summary>
/// Represents a JWT-Secured Authorization Request (JAR) as specified in RFC 9101.
/// 
/// The JAR is created by signing (and optionally encrypting) an Authorization Request
/// as a JSON Web Token (JWT). This provides integrity protection, source authentication,
/// and optionally confidentiality for the authorization request.
///
/// Specification: RFC 9101 (OAuth 2.0 JWT-Secured Authorization Request Assertion Format)
/// https://www.rfc-editor.org/rfc/rfc9101.html
/// 
/// Usage:
/// <code>
/// // Build authorization request
/// var authRequest = AuthorizationRequestBuilder.Create()
///     .WithClientId("verifier-1")
///     .WithNonce("abc123")
///     .Build();
///
/// // Create JAR with signing
/// var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(authRequest.Value)
///     .WithSigningKey(privateKey)
///     .WithAlgorithm("RS256")
///     .WithIssuer("verifier-1")
///     .WithAudience("https://wallet.example.com")
///     .Build();
///
/// // Use JAR token for transmission
/// // Option B: By value in request parameter
/// var jar = jarResult.Value;
/// var uriB = AuthorizationRequestUriBuilder.Create(authRequest.Value)
///     .AsRequestObjectByValue(baseUri, jar.Token);
///
/// // Option C: By reference (wallet fetches request_uri)
/// var bodyResult = AuthorizationRequestBodyBuilder.Create(authRequest.Value)
///     .AsJar(jar);
/// // HTTP response: Content-Type: application/jwt, Body: jar.Token
/// </code>
/// </summary>
public sealed class JwtSecuredAuthorizationRequest
{
    /// <summary>
    /// The complete JWT token as a base64url-encoded string.
    /// This includes header, claims set, and signature (and encryption if applied).
    /// 
    /// Format when using JWS only: header.payload.signature
    /// Format when using JWE: header.encrypted_key.iv.ciphertext.auth_tag
    /// </summary>
    public required string Token { get; init; }

    /// <summary>
    /// The cryptographic algorithm used for signing the JWT.
    /// Common values: "RS256", "ES256", "PS256"
    /// </summary>
    public required string SigningAlgorithm { get; init; }

    /// <summary>
    /// Whether the JWT was encrypted with JWE for confidentiality.
    /// If true, the Token should only be decryptable by the intended recipient.
    /// </summary>
    public required bool IsEncrypted { get; init; }

    /// <summary>
    /// The JWT claims set as a JwtSecurityToken for easy inspection/validation.
    /// This is the decoded version of the Token (without encryption if JWE was used).
    /// 
    /// Typically includes:
    /// - All AuthorizationRequest fields (client_id, nonce, response_type, etc.)
    /// - "iss" claim (issuer, if provided)
    /// - "aud" claim (audience, if provided)
    /// - "iat" claim (issued at, auto-added)
    /// - "exp" claim (expiration, if configured)
    /// </summary>
    public required JwtSecurityToken Claims { get; init; }

    /// <summary>
    /// The encryption algorithm used, if the JWT was encrypted with JWE.
    /// Common values: "RSA-OAEP", "A256KW", "dir"
    /// Null if IsEncrypted is false.
    /// </summary>
    public string? EncryptionAlgorithm { get; init; }
}
