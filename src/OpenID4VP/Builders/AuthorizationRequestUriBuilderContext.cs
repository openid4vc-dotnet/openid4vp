using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;
using OpenID4VP.Validators;

namespace OpenID4VP.Builders;

/// <summary>
/// Fluent builder context for converting AuthorizationRequest to transport URIs.
/// Supports all three OpenID4VP transport mechanisms:
/// 
/// Option A: Direct URL with all parameters encoded as query string (same-device)
/// Option B: Request object as JWT value in 'request' parameter (same-device, encrypted/signed)
/// Option C: Request object by reference via request_uri (cross-device, QR code)
/// 
/// Per OpenID4VP Spec Section 5.4 Examples:
/// 1) Passing request as URL parameters (Option A)
/// 2) Passing request object as value (Option B)
/// 3) Passing request object by reference (Option C)
/// </summary>
public class AuthorizationRequestUriBuilderContext
{
    private readonly AuthorizationRequest _request;

    internal AuthorizationRequestUriBuilderContext(AuthorizationRequest request)
    {
        _request = request;
    }

    /// <summary>
    /// Option A: Encodes the full authorization request as query parameters in the URI.
    /// Used for same-device flow with direct user interaction.
    /// 
    /// All request parameters are URL-encoded and appended to the base URI:
    /// https://wallet.example.com/auth?client_id=...&nonce=...&response_type=...&dcql_query=...
    /// 
    /// Includes all fields from the AuthorizationRequest (client_id, nonce, response_type, dcql_query, etc.)
    /// </summary>
    /// <param name="baseUri">The base URI to which query parameters will be appended (e.g., "https://wallet.example.com/auth")</param>
    /// <returns>A Result containing the complete URI if successful, or validation errors if failed</returns>
    public Result<string> AsDirectUrl(string baseUri)
    {
        if (string.IsNullOrEmpty(baseUri))
            return Result<string>.Failure(new ValidationError("Base URI cannot be null or empty", "baseUri"));

        // Validate the authorization request
        var validator = new AuthorizationRequestValidator();
        var validationErrors = validator.ValidateForDirectUrl(_request).ToList();

        if (validationErrors.Any())
            return Result<string>.Failure(validationErrors);

        var queryParams = new Dictionary<string, string>();

        // REQUIRED parameters
        if (!string.IsNullOrEmpty(_request.ClientId))
            queryParams["client_id"] = _request.ClientId;

        if (!string.IsNullOrEmpty(_request.Nonce))
            queryParams["nonce"] = _request.Nonce;

        if (!string.IsNullOrEmpty(_request.ResponseType))
            queryParams["response_type"] = _request.ResponseType;

        // OPTIONAL parameters
        if (!string.IsNullOrEmpty(_request.ResponseMode))
            queryParams["response_mode"] = _request.ResponseMode;

        if (!string.IsNullOrEmpty(_request.State))
            queryParams["state"] = _request.State;

        if (!string.IsNullOrEmpty(_request.RedirectUri))
            queryParams["redirect_uri"] = _request.RedirectUri;

        if (!string.IsNullOrEmpty(_request.ResponseUri))
            queryParams["response_uri"] = _request.ResponseUri;

        if (_request.DcqlQuery != null)
            queryParams["dcql_query"] = JsonSerializer.Serialize(_request.DcqlQuery);

        if (_request.ClientMetadata != null)
            queryParams["client_metadata"] = JsonSerializer.Serialize(_request.ClientMetadata);

        var uri = BuildUriWithQueryParameters(baseUri, queryParams);
        return Result<string>.Success(uri);
    }

    /// <summary>
    /// Option B: Embeds a signed/encrypted Request Object as the value of the 'request' parameter.
    /// Used for same-device flow with request object protection.
    /// 
    /// The authorization request is signed/encrypted by the verifier and embedded:
    /// https://wallet.example.com/auth?request=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
    /// 
    /// The JWT must be created and signed by the caller (this builder only adds it to the URI).
    /// The 'request' parameter must contain a base64url-encoded and signed Request Object.
    /// 
    /// Per Spec Section 5.4.2: "request value MUST be a Request Object"
    /// </summary>
    /// <param name="baseUri">The base URI to which the request parameter will be appended</param>
    /// <param name="requestObjectJwt">A base64url-encoded and signed Request Object JWT (pre-signed by caller)</param>
    /// <returns>A Result containing the complete URI if successful, or validation errors if failed</returns>
    public Result<string> AsRequestObjectByValue(string baseUri, string requestObjectJwt)
    {
        if (string.IsNullOrEmpty(baseUri))
            return Result<string>.Failure(new ValidationError("Base URI cannot be null or empty", "baseUri"));

        if (string.IsNullOrEmpty(requestObjectJwt))
            return Result<string>.Failure(new ValidationError("Request Object JWT cannot be null or empty", "requestObjectJwt"));

        // For Option B, the JWT itself is the "request" - just add it to URI
        var queryParams = new Dictionary<string, string>
        {
            { "request", requestObjectJwt }
        };

        var uri = BuildUriWithQueryParameters(baseUri, queryParams);
        return Result<string>.Success(uri);
    }

    /// <summary>
    /// Option C: Generates a minimal request URI with request_uri pointing to the full authorization request.
    /// Used for cross-device flow (QR codes, out-of-band).
    /// 
    /// Only includes minimal parameters:
    /// - client_id (REQUIRED)
    /// - request_uri (REQUIRED) - endpoint where full request is fetched
    /// - nonce (REQUIRED per spec)
    /// - state (OPTIONAL)
    /// - request_uri_method (OPTIONAL) - "get" or "post"
    /// 
    /// The full authorization request (with response_mode, response_type, dcql_query, etc.) 
    /// is fetched from the request_uri endpoint by the wallet.
    /// 
    /// Per Spec Section 3.2 and Section 5.4.3:
    /// Wallet scans QR code → minimal request → fetches full request from request_uri → processes
    /// </summary>
    /// <param name="baseUri">The base URI for the QR code (e.g., "openid4vp://" or "https://verifier.example.com/auth")</param>
    /// <returns>A Result containing the minimal URI suitable for QR encoding if successful, or validation errors if failed</returns>
    public Result<string> AsRequestObjectByReference(string baseUri)
    {
        if (string.IsNullOrEmpty(baseUri))
            return Result<string>.Failure(new ValidationError("Base URI cannot be null or empty", "baseUri"));

        // For cross-device, validate minimal required fields
        var errors = ValidateForRequestByReference().ToList();
        if (errors.Any())
            return Result<string>.Failure(errors);

        var queryParams = new Dictionary<string, string>();

        // REQUIRED minimal parameters
        queryParams["client_id"] = _request.ClientId!;
        queryParams["request_uri"] = _request.RequestUri!;
        queryParams["nonce"] = _request.Nonce!;

        // OPTIONAL parameters
        if (!string.IsNullOrEmpty(_request.State))
            queryParams["state"] = _request.State;

        // OPTIONAL: request_uri_method (normalize to lowercase if provided)
        if (!string.IsNullOrEmpty(_request.RequestUriMethod))
            queryParams["request_uri_method"] = _request.RequestUriMethod.ToLowerInvariant();

        var uri = BuildUriWithQueryParameters(baseUri, queryParams);
        return Result<string>.Success(uri);
    }

    /// <summary>
    /// Validates the request for cross-device transport (Option C).
    /// Checks that minimal required fields are present.
    /// </summary>
    private IEnumerable<ValidationError> ValidateForRequestByReference()
    {
        if (string.IsNullOrEmpty(_request.ClientId))
            yield return new ValidationError("client_id is required for request object by reference", "ClientId");

        if (string.IsNullOrEmpty(_request.RequestUri))
            yield return new ValidationError("request_uri is required for request object by reference", "RequestUri");

        if (string.IsNullOrEmpty(_request.Nonce))
            yield return new ValidationError("nonce is required per OpenID4VP Spec Section 5.2", "Nonce");
    }

    /// <summary>
    /// Builds a complete URI by appending encoded query parameters to a base URI.
    /// </summary>
    private static string BuildUriWithQueryParameters(string baseUri, Dictionary<string, string> parameters)
    {
        if (parameters.Count == 0)
            return baseUri;

        var encodedParams = parameters
            .Where(kvp => !string.IsNullOrEmpty(kvp.Value))
            .Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}")
            .ToList();

        if (encodedParams.Count == 0)
            return baseUri;

        var queryString = string.Join("&", encodedParams);
        var separator = baseUri.Contains("?") ? "&" : "?";

        return $"{baseUri}{separator}{queryString}";
    }
}
