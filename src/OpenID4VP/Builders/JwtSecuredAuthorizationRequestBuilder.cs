using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Static factory for creating JWT-Secured Authorization Requests (JAR) as specified in RFC 9101.
/// 
/// The JAR builder creates a signed (and optionally encrypted) JWT containing the entire
/// Authorization Request. This is used for secure transmission of authorization requests,
/// providing integrity protection, source authentication, and optional confidentiality.
///
/// RFC 9101: https://www.rfc-editor.org/rfc/rfc9101.html
/// OpenID4VP Spec: Section 5.4 (Request Object Options)
///
/// The JAR is used with:
/// - **Option B (Request by Value)**: The JAR token is embedded in the "request" parameter
/// - **Option C (Request by Reference)**: The JAR token is returned from the request_uri endpoint
///
/// Usage:
/// <code>
/// var authRequest = AuthorizationRequestBuilder.Create()
///     .WithClientId("verifier-1")
///     .WithNonce("abc123")
///     .WithResponseType("vp_token")
///     .Build();
///
/// var signingKey = LoadRsaPrivateKey("path/to/private.key");
/// var encryptionKey = LoadRsaPublicKey("path/to/wallet-public.key"); // Optional
///
/// var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(authRequest.Value)
///     .WithSigningKey(signingKey)
///     .WithEncryptionKey(encryptionKey)               // Optional
///     .WithAlgorithm("RS256")                         // Signing algorithm
///     .WithEncryptionAlgorithm("RSA-OAEP")           // Optional
///     .WithIssuer("verifier-1")                       // Optional iss claim
///     .WithAudience("https://wallet.example.com")    // Optional aud claim
///     .Build();
///
/// if (jarResult.IsSuccess)
/// {
///     var jar = jarResult.Value;
///     // Use jar.Token for transmission
/// }
/// </code>
/// </summary>
public static class JwtSecuredAuthorizationRequestBuilder
{
    /// <summary>
    /// Creates a new JWT-Secured Authorization Request builder for the given authorization request.
    /// 
    /// The builder will create a signed JWT containing all fields from the authorization request.
    /// Optionally, the JWT can also be encrypted for confidentiality.
    /// </summary>
    /// <param name="authorizationRequest">The Authorization Request to secure with JWT signing/encryption</param>
    /// <returns>A fluent builder context for configuring signing and encryption parameters</returns>
    public static JwtSecuredAuthorizationRequestBuilderContext Create(AuthorizationRequest authorizationRequest)
    {
        return new JwtSecuredAuthorizationRequestBuilderContext(authorizationRequest);
    }
}
