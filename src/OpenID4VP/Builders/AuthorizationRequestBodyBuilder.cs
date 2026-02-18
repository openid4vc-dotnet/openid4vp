using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Static factory for creating Authorization Request response bodies.
/// 
/// Used for Option C (Request Object by Reference) where the verifier responds
/// to wallet's request_uri fetch with the full Authorization Request.
/// 
/// Per OpenID4VP Spec Section 5.4.3:
/// When wallet fetches request_uri, the response contains the full Authorization Request.
/// The response can be:
/// - Plain JSON (application/json) - unencrypted
/// - JWT-Secured (application/jwt) - signed per RFC 9101
///
/// For Options B and C that require JWT-Secured Authorization Request (JAR):
/// First create a JAR using JwtSecuredAuthorizationRequestBuilder, then pass it here.
/// 
/// Usage:
/// <code>
/// var request = AuthorizationRequestBuilder.Create()
///     .WithClientId("verifier-1")
///     .WithNonce("abc123")
///     .WithResponseType("vp_token")
///     .Build();
/// 
/// // Plain JSON response (Option C, no security)
/// var jsonBody = AuthorizationRequestBodyBuilder.Create(request.Value)
///     .AsJson();
/// // HTTP: Content-Type: application/json
/// 
/// // JWT-Secured response (Option C, with security per RFC 9101)
/// var jar = JwtSecuredAuthorizationRequestBuilder.Create(request.Value)
///     .WithSigningKey(signingKey)
///     .Build();
/// var jarBody = AuthorizationRequestBodyBuilder.Create(request.Value)
///     .AsJar(jar.Value);
/// // HTTP: Content-Type: application/jwt
/// </code>
/// </summary>
public static class AuthorizationRequestBodyBuilder
{
    /// <summary>
    /// Creates a new Authorization Request response body builder for the given authorization request.
    /// 
    /// The builder supports multiple serialization formats:
    /// - AsJson(): Plain JSON (no encryption/signature)
    /// - AsJar(): JWT-Secured per RFC 9101 (signed, optionally encrypted)
    /// </summary>
    /// <param name="authorizationRequest">The Authorization Request to serialize for HTTP response</param>
    /// <returns>A fluent builder context for selecting the serialization format</returns>
    public static AuthorizationRequestBodyBuilderContext Create(AuthorizationRequest authorizationRequest)
    {
        return new AuthorizationRequestBodyBuilderContext(authorizationRequest);
    }
}
