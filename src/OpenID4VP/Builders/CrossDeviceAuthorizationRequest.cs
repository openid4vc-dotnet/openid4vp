using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Validators;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for cross-device mode authorization requests (Section 3.2 of OpenID4VP spec).
/// 
/// Cross-device mode uses direct_post or direct_post.jwt response modes with a minimal request
/// (client_id + request_uri) that is encoded in a QR code or similar transport mechanism.
/// 
/// Usage:
/// <code>
/// var result = CrossDeviceAuthorizationRequest.Build(builder =>
///     builder
///         .WithClientId("verifier-1")
///         .WithResponseMode(ResponseModes.DirectPost)
///         .WithRequestUri("https://verifier.example.com/request")
/// );
/// 
/// if (result.IsSuccess)
///     ProcessRequest(result.Value);
/// else
///     LogErrors(result.Errors);
/// </code>
/// </summary>
public static class CrossDeviceAuthorizationRequest
{
    /// <summary>
    /// Builds and validates a cross-device mode authorization request.
    /// </summary>
    /// <param name="configure">Action to configure the builder</param>
    /// <returns>A Result containing the validated AuthorizationRequest if successful, or errors if validation failed</returns>
    public static Result<AuthorizationRequest> Build(Action<AuthorizationRequestBuilder> configure)
    {
        if (configure == null)
            throw new ArgumentNullException(nameof(configure));

        var builder = AuthorizationRequestBuilder.Create();
        configure(builder);
        
        // Build request and stop if structural validation fails
        var buildResult = builder.Build();
        if (!buildResult.IsSuccess)
            return buildResult;

        // Now validate for cross-device scenario requirements
        var validator = new CrossDeviceAuthorizationRequestValidator();
        var result = validator.Validate(buildResult.Value!);

        if (!result.IsValid)
        {
            return result.Errors
                .Select(e => new ValidationError(e))
                .ToArray();
        }

        return buildResult;
    }
}
