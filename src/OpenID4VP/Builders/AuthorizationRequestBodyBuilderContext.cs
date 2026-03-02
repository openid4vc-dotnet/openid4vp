using OpenID4VC.Core.Results;
using OpenID4VP.Models;
using OpenID4VP.Validators;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Builders;

/// <summary>
/// Fluent builder context for serializing AuthorizationRequest for HTTP response body.
/// 
/// Used for Option C (Request Object by Reference) where wallet fetches the full
/// Authorization Request from the request_uri endpoint.
/// 
/// Supports two serialization formats:
/// - AsJson(): Plain JSON (application/json) - no security/encryption
/// - AsJar(): JWT-Secured per RFC 9101 (application/jwt) - signed, optionally encrypted
/// 
/// Per OpenID4VP Spec Section 5.4.3:
/// "The Authorization Request MAY be returned as a JWT or other format as defined by
/// the Presentation Exchange specification"
/// </summary>
public class AuthorizationRequestBodyBuilderContext
{
    private readonly AuthorizationRequest _request;

    /// <summary>
    /// JSON serialization options with SnakeCaseLower naming policy for OpenID4VP compliance.
    /// Matches the format used by DCQL queries and other OpenID4VP parameters.
    /// </summary>
    private static readonly JsonSerializerOptions SnakeCaseOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    internal AuthorizationRequestBodyBuilderContext(AuthorizationRequest request)
    {
        _request = request;
    }

    /// <summary>
    /// Serializes the Authorization Request as plain JSON for HTTP response.
    /// 
    /// Per OpenID4VP Spec, this is the basic format option when wallet fetches request_uri.
    /// Note: This provides NO security (no signature, no encryption). Use AsJar() for secure transmission.
    /// 
    /// HTTP Response Header:
    /// Content-Type: application/json
    /// 
    /// Response Body:
    /// { "client_id": "verifier-1", "nonce": "abc123", "response_type": "vp_token", ... }
    /// </summary>
    /// <returns>A Result containing the JSON string if successful, or validation errors if failed</returns>
    public Result<string> AsJson()
    {
        // Validate the authorization request
        var validator = new AuthorizationRequestValidator();
        var validationResult = validator.Validate(_request);

        if (!validationResult.IsValid)
            return validationResult.Errors.Select(e => new ValidationError(e, "validation_error")).ToArray();

        try
        {
            var json = JsonSerializer.Serialize(_request, SnakeCaseOptions);
            return json;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to serialize Authorization Request to JSON: {ex.Message}", 
                "serialization_error");
        }
    }

    /// <summary>
    /// Serializes the Authorization Request as a JWT-Secured Authorization Request (JAR) for HTTP response.
    /// 
    /// Per RFC 9101, this creates a signed (and optionally encrypted) JWT containing the entire
    /// Authorization Request. This is the secure format for Option C (Request Object by Reference).
    /// 
    /// The JAR should be created using JwtSecuredAuthorizationRequestBuilder:
    /// <code>
    /// var jar = JwtSecuredAuthorizationRequestBuilder.Create(request)
    ///     .WithSigningKey(privateKey)
    ///     .WithEncryptionKey(walletPublicKey)  // Optional
    ///     .Build();
    /// 
    /// var bodyResult = AuthorizationRequestBodyBuilder.Create(request)
    ///     .AsJar(jar.Value);
    /// </code>
    /// 
    /// HTTP Response Header:
    /// Content-Type: application/jwt
    /// 
    /// Response Body:
    /// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJ2ZXJpZmllci0xIiwibm9uY2UiOiJhYmMxMjMifQ.signature...
    /// </summary>
    /// <param name="jar">The JWT-Secured Authorization Request created by JwtSecuredAuthorizationRequestBuilder</param>
    /// <returns>A Result containing the JWT token string if successful, or validation errors if failed</returns>
    public Result<string> AsJar(JwtSecuredAuthorizationRequest jar)
    {
        if (jar == null)
            return new ValidationError(
                "JWT-Secured Authorization Request cannot be null", 
                "jar_required");

        if (string.IsNullOrEmpty(jar.Token))
            return new ValidationError(
                "JAR token cannot be null or empty", 
                "jar_token_required");

        try
        {
            // Return the complete JWT token as-is
            // This is already signed (and optionally encrypted) by the JAR builder
            return jar.Token;
        }
        catch (Exception ex)
        {
            return new ValidationError(
                $"Failed to serialize JAR for HTTP response: {ex.Message}", 
                "jar_serialization_error");
        }
    }
}
