using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Static factory for creating authorization request URIs.
/// 
/// Supports all three OpenID4VP transport mechanisms per Spec Section 5.4:
/// 
/// Option A: Direct URL with all parameters encoded as query string
/// - Usage: Same-device flow with direct user interaction
/// - Parameters: All AuthorizationRequest fields in query string
/// - Example: https://wallet.example.com/auth?client_id=...&nonce=...&response_type=...&dcql_query=...
/// 
/// Option B: Request object as JWT value in 'request' parameter  
/// - Usage: Same-device flow with protected request (signed/encrypted)
/// - Parameters: Only 'request' query parameter containing base64url-encoded JWT
/// - Example: https://wallet.example.com/auth?request=eyJhbGciOiJSUzI1NiIs...
/// 
/// Option C: Request object by reference via request_uri
/// - Usage: Cross-device flow (QR codes, out-of-band)
/// - Parameters: Minimal request (client_id + request_uri + nonce + state)
/// - Example: https://qr.example.com?client_id=verifier-1&request_uri=https%3A%2F%2F...&nonce=abc123
/// 
/// Usage:
/// <code>
/// // Option A: Direct URL
/// var request = AuthorizationRequestBuilder.Create()
///     .WithClientId("verifier-1")
///     .WithNonce("abc123")
///     .WithResponseType("vp_token")
///     .WithResponseMode("query")
///     .WithDcql(q => q.Add(...))
///     .Build();
/// 
/// var uri = AuthorizationRequestUriBuilder.Create(request.Value)
///     .AsDirectUrl("https://wallet.example.com/auth");
/// 
/// // Option B: Request as JWT
/// var jwt = JwtSigner.SignRequest(request.Value);  // Pre-signed by caller
/// var uri = AuthorizationRequestUriBuilder.Create(request.Value)
///     .AsRequestObjectByValue("https://wallet.example.com/auth", jwt);
/// 
/// // Option C: Request by reference (cross-device)
/// var request = AuthorizationRequestBuilder.Create()
///     .WithClientId("verifier-1")
///     .WithNonce("abc123")
///     .WithRequestUri("https://verifier.example.com/request")
///     .Build();
/// 
/// var qrUri = AuthorizationRequestUriBuilder.Create(request.Value)
///     .AsRequestObjectByReference("openid4vp://");
/// </code>
/// </summary>
public static class AuthorizationRequestUriBuilder
{
    /// <summary>
    /// Creates a new authorization request URI builder for the given authorization request.
    /// </summary>
    /// <param name="authorizationRequest">The authorization request to encode as URI</param>
    /// <returns>A fluent builder context for selecting the transport mechanism</returns>
    public static AuthorizationRequestUriBuilderContext Create(AuthorizationRequest authorizationRequest)
    {
        return new AuthorizationRequestUriBuilderContext(authorizationRequest);
    }
}
