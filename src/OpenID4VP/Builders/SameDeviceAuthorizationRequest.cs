using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Validators;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for same-device mode authorization requests (Section 3.1 of OpenID4VP spec).
/// 
/// Same-device mode uses fragment or query response modes with redirect_uri for response delivery.
/// 
/// Usage:
/// <code>
/// var result = SameDeviceAuthorizationRequest.Build(builder =>
///     builder
///         .WithResponseType(ResponseTypes.VpToken)
///         .WithClientId("verifier-1")
///         .WithNonce("nonce-123")
///         .WithResponseMode(ResponseModes.Fragment)
///         .WithRedirectUri("https://verifier.example.com/callback")
///         .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")))
/// );
/// 
/// if (result.IsSuccess)
///     ProcessRequest(result.Value);
/// else
///     LogErrors(result.Errors);
/// </code>
/// </summary>
public static class SameDeviceAuthorizationRequest
{
    /// <summary>
    /// Builds and validates a same-device mode authorization request.
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

        // Now validate for same-device scenario requirements
        var validator = new SameDeviceAuthorizationRequestValidator();
        var validationResult = validator.Validate(buildResult.Value!);

        if (!validationResult.IsValid)
            return validationResult.Errors
                .Select(e => new ValidationError(e))
                .ToArray();

        return buildResult.Value!;
    }
}
