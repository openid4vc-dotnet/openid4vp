using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Validators;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for same-device mode authorization requests (Section 3.1 of OpenID4VP spec).
/// 
/// Same-device mode uses fragment or query response modes with redirect_uri for response delivery.
/// 
/// Usage:
/// <code>
/// var request = SameDeviceAuthorizationRequest.Build(builder =>
///     builder
///         .WithResponseType(ResponseTypes.VpToken)
///         .WithClientId("verifier-1")
///         .WithNonce("nonce-123")
///         .WithResponseMode(ResponseModes.Fragment)
///         .WithRedirectUri("https://verifier.example.com/callback")
///         .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")))
/// );
/// </code>
/// </summary>
public static class SameDeviceAuthorizationRequest
{
    /// <summary>
    /// Builds and validates a same-device mode authorization request.
    /// </summary>
    /// <param name="configure">Action to configure the builder</param>
    /// <returns>A validated AuthorizationRequest suitable for same-device mode</returns>
    /// <exception cref="ValidationException">If the request does not meet same-device mode requirements</exception>
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

        var validator = new SameDeviceAuthorizationRequestValidator();
        var result = validator.Validate(request);

        if (!result.IsValid)
            throw new ValidationException(result);

        return request;
    }
}
