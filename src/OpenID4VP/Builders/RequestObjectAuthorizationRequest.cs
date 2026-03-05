using OpenID4VP.Models;
using OpenID4VP.Validators;
using OpenID4VC.Core.Results;

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
/// var result = RequestObjectAuthorizationRequest.Build(builder =>
///     builder
///         .WithResponseType(ResponseTypes.VpToken)
///         .WithClientId("verifier-1")
///         .WithNonce("nonce-123")
///         .WithResponseUri("https://verifier.example.com/response")
///         .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")))
/// );
/// 
/// if (result.IsSuccess)
///     ProcessRequest(result.Value);
/// else
///     LogErrors(result.Errors);
/// </code>
/// </summary>
public static class RequestObjectAuthorizationRequest
{
    /// <summary>
    /// Builds and validates a Request Object authorization request.
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

        // Now validate for Request Object scenario requirements
        var validator = new RequestObjectAuthorizationRequestValidator();
        var result = validator.Validate(buildResult.Value!);

        if (!result.IsSuccess)
            return result.Errors.ToArray();

        return buildResult.Value!;
    }
}
