using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Validators;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for Request Object authorization requests (Section 3.2 & 6 of OpenID4VP spec).
/// 
/// Request Object contains the full authorization parameters and is returned when the wallet
/// fetches from the request_uri endpoint specified in a cross-device mode request.
/// 
/// Per spec: "The HTTP GET response returns the Request Object containing Authorization Request parameters"
/// 
/// Usage:
/// <code>
/// var requestObject = RequestObjectAuthorizationRequest.Build(builder =>
///     builder
///         .WithResponseType(ResponseTypes.VpToken)
///         .WithClientId("verifier-1")
///         .WithNonce("nonce-123")
///         .WithResponseUri("https://verifier.example.com/response")
///         .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")))
/// );
/// </code>
/// </summary>
public static class RequestObjectAuthorizationRequest
{
    /// <summary>
    /// Builds and validates a Request Object authorization request.
    /// </summary>
    /// <param name="configure">Action to configure the builder</param>
    /// <returns>A validated AuthorizationRequest suitable for Request Object</returns>
    /// <exception cref="ValidationException">If the request does not meet Request Object requirements</exception>
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

        var validator = new RequestObjectAuthorizationRequestValidator();
        var result = validator.Validate(request);

        if (!result.IsValid)
            throw new ValidationException(result);

        return request;
    }
}
