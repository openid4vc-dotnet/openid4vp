using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Validators;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for cross-device mode authorization requests (Section 3.2 of OpenID4VP spec).
/// 
/// Cross-device mode uses direct_post or direct_post.jwt response modes with a minimal request
/// (client_id + request_uri) that is encoded in a QR code or similar transport mechanism.
/// 
/// Usage:
/// <code>
/// var request = CrossDeviceAuthorizationRequest.Build(builder =>
///     builder
///         .WithClientId("verifier-1")
///         .WithResponseMode(ResponseModes.DirectPost)
///         .WithRequestUri("https://verifier.example.com/request")
/// );
/// </code>
/// </summary>
public static class CrossDeviceAuthorizationRequest
{
    /// <summary>
    /// Builds and validates a cross-device mode authorization request.
    /// </summary>
    /// <param name="configure">Action to configure the builder</param>
    /// <returns>A validated AuthorizationRequest suitable for cross-device mode</returns>
    /// <exception cref="ValidationException">If the request does not meet cross-device mode requirements</exception>
    public static AuthorizationRequest Build(Action<AuthorizationRequestBuilder> configure)
    {
        if (configure == null)
            throw new ArgumentNullException(nameof(configure));

        var builder = AuthorizationRequestBuilder.Create();
        configure(builder);
        
        AuthorizationRequest request;
        try
        {
            request = builder.Build();
        }
        catch (InvalidOperationException ex)
        {
            // Convert builder validation errors to ValidationException for consistency
            throw new ValidationException(new ValidationResult { IsValid = false, Errors = new[] { ex.Message } });
        }

        var validator = new CrossDeviceAuthorizationRequestValidator();
        var result = validator.Validate(request);

        if (!result.IsValid)
            throw new ValidationException(result);

        return request;
    }
}
