using System.Text.RegularExpressions;
using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Validators;

/// <summary>
/// Validator for AuthorizationRequest objects.
/// Validates spec compliance and business logic constraints.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5
/// </summary>
public sealed class AuthorizationRequestValidator : IValidator<AuthorizationRequest>
{
    private static readonly Regex UrlSafeCharacters = new(@"^[A-Za-z0-9\-._~]*$");
    private const string VpToken = "vp_token";
    private const string VpTokenIdToken = "vp_token id_token";

    /// <summary>
    /// Validates the AuthorizationRequest for spec compliance.
    /// </summary>
    public ValidationResult Validate(AuthorizationRequest request)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var errors = new List<string>();

        ValidateResponseType(request.ResponseType, errors);
        ValidateClientId(request.ClientId, errors);
        ValidateNonce(request.Nonce, errors);
        ValidateResponseMode(request.ResponseMode, errors);
        ValidateDcqlAndScope(request.DcqlQuery, request.Scope, errors);
        ValidateRedirectUri(request.ResponseMode, request.RedirectUri, errors);
        ValidateResponseUri(request.ResponseMode, request.ResponseUri, errors);
        ValidateState(request.State, errors);
        ValidateRequestUriMethod(request.RequestUriMethod, errors);

        return errors.Count > 0 
            ? ValidationResult.Failure(errors) 
            : ValidationResult.Success();
    }

    private static void ValidateResponseType(string responseType, List<string> errors)
    {
        if (string.IsNullOrEmpty(responseType))
        {
            errors.Add("Response type is required");
            return;
        }

        if (responseType != VpToken && responseType != VpTokenIdToken)
            errors.Add($"Response type must be '{VpToken}' or '{VpTokenIdToken}', got: {responseType}");
    }

    private static void ValidateClientId(string clientId, List<string> errors)
    {
        if (string.IsNullOrEmpty(clientId))
            errors.Add("Client ID is required");
    }

    private static void ValidateNonce(string nonce, List<string> errors)
    {
        if (string.IsNullOrEmpty(nonce))
        {
            errors.Add("Nonce is required");
            return;
        }

        if (!UrlSafeCharacters.IsMatch(nonce))
            errors.Add("Nonce must contain only ASCII URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)");
    }

    private static void ValidateResponseMode(string responseMode, List<string> errors)
    {
        if (string.IsNullOrEmpty(responseMode))
        {
            errors.Add("Response mode is required");
            return;
        }

        var validModes = new[] { "fragment", "query", "direct_post", "direct_post.jwt" };
        if (!validModes.Contains(responseMode))
            errors.Add($"Response mode must be one of: {string.Join(", ", validModes)}, got: {responseMode}");
    }

    private static void ValidateDcqlAndScope(object? dcqlQuery, string? scope, List<string> errors)
    {
        var hasDcql = dcqlQuery != null;
        var hasScope = !string.IsNullOrEmpty(scope);

        if (!hasDcql && !hasScope)
            errors.Add("Either dcql_query or scope must be present");

        if (hasDcql && hasScope)
            errors.Add("Only one of dcql_query or scope can be present, not both");
    }

    private static void ValidateRedirectUri(string responseMode, string? redirectUri, List<string> errors)
    {
        // redirect_uri is not always required based on response_mode
        // Only validate if present in direct_post tests
        // For other modes, it's optional per OAuth 2.0
    }

    private static void ValidateResponseUri(string responseMode, string? responseUri, List<string> errors)
    {
        // Response URI is required ONLY for direct_post modes
        if (responseMode == "direct_post" || responseMode == "direct_post.jwt")
        {
            if (string.IsNullOrEmpty(responseUri))
                errors.Add($"Response URI is required for response mode '{responseMode}'");
        }
    }

    private static void ValidateState(string? state, List<string> errors)
    {
        if (state != null && !UrlSafeCharacters.IsMatch(state))
            errors.Add("State must contain only ASCII URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)");
    }

    private static void ValidateRequestUriMethod(string? requestUriMethod, List<string> errors)
    {
        if (string.IsNullOrEmpty(requestUriMethod))
            return;

        if (requestUriMethod != "get" && requestUriMethod != "post")
            errors.Add($"Request URI method must be 'get' or 'post', got: {requestUriMethod}");
    }

    /// <summary>
    /// Validates AuthorizationRequest for Option A transport (Direct URL with all parameters).
    /// Requires: client_id, nonce, response_type, response_mode
    /// Optional: state, dcql_query or scope, redirect_uri, response_uri
    /// </summary>
    public IEnumerable<ValidationError> ValidateForDirectUrl(AuthorizationRequest request)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        if (string.IsNullOrEmpty(request.ClientId))
            yield return new ValidationError("client_id is required", "ClientId");

        if (string.IsNullOrEmpty(request.Nonce))
            yield return new ValidationError("nonce is required per OpenID4VP Spec Section 5.2", "Nonce");
        else if (!UrlSafeCharacters.IsMatch(request.Nonce))
            yield return new ValidationError("nonce must contain only ASCII URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)", "Nonce");

        if (string.IsNullOrEmpty(request.ResponseType))
            yield return new ValidationError("response_type is required", "ResponseType");
        else if (request.ResponseType != VpToken && request.ResponseType != VpTokenIdToken)
            yield return new ValidationError($"response_type must be '{VpToken}' or '{VpTokenIdToken}'", "ResponseType");

        if (string.IsNullOrEmpty(request.ResponseMode))
            yield return new ValidationError("response_mode is required for direct URL transport", "ResponseMode");
        else
        {
            var validModes = new[] { "fragment", "query", "direct_post", "direct_post.jwt" };
            if (!validModes.Contains(request.ResponseMode))
                yield return new ValidationError($"response_mode must be one of: {string.Join(", ", validModes)}", "ResponseMode");
        }

        // Validate DCQL XOR Scope (at least one, not both)
        var hasDcql = request.DcqlQuery != null;
        var hasScope = !string.IsNullOrEmpty(request.Scope);
        if (!hasDcql && !hasScope)
            yield return new ValidationError("Either dcql_query or scope must be present", "DcqlQuery");
        if (hasDcql && hasScope)
            yield return new ValidationError("Only one of dcql_query or scope can be present, not both", "DcqlQuery");

        // Validate state if present
        if (!string.IsNullOrEmpty(request.State) && !UrlSafeCharacters.IsMatch(request.State))
            yield return new ValidationError("state must contain only ASCII URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)", "State");

        // Validate response_uri if needed
        if (request.ResponseMode == "direct_post" || request.ResponseMode == "direct_post.jwt")
        {
            if (string.IsNullOrEmpty(request.ResponseUri))
                yield return new ValidationError($"response_uri is required for response_mode '{request.ResponseMode}'", "ResponseUri");
        }

        // Validate request_uri_method if present
        if (!string.IsNullOrEmpty(request.RequestUriMethod))
        {
            if (request.RequestUriMethod != "get" && request.RequestUriMethod != "post")
                yield return new ValidationError("request_uri_method must be 'get' or 'post'", "RequestUriMethod");
        }
    }
}
