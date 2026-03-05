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
    public Result Validate(AuthorizationRequest request)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        var errors = new List<ValidationError>();

        ValidateResponseType(request.ResponseType, errors);
        ValidateClientId(request.ClientId, errors);
        ValidateNonce(request.Nonce, errors);
        ValidateResponseMode(request.ResponseMode, errors);
        ValidateDcqlAndScope(request.DcqlQuery, request.Scope, errors);
        ValidateRedirectUri(request.ResponseMode, request.RedirectUri, errors);
        ValidateResponseUri(request.ResponseMode, request.ResponseUri, errors);
        ValidateEncryptedResponseEncValues(request.ResponseMode, request.ClientMetadata, errors);
        ValidateState(request.State, errors);
        ValidateRequestUriMethod(request.RequestUriMethod, errors);

        return errors.Count > 0 
            ? errors.Cast<Error>().ToArray()
            : Result.Success();
    }

    private static void ValidateResponseType(string responseType, List<ValidationError> errors)
    {
        if (string.IsNullOrEmpty(responseType))
        {
            errors.Add(new ValidationError("Response type is required", "response_type"));
            return;
        }

        if (responseType != VpToken && responseType != VpTokenIdToken)
            errors.Add(new ValidationError($"Response type must be '{VpToken}' or '{VpTokenIdToken}', got: {responseType}", "response_type"));
    }

    private static void ValidateClientId(string clientId, List<ValidationError> errors)
    {
        if (string.IsNullOrEmpty(clientId))
            errors.Add(new ValidationError("Client ID is required", "client_id"));
    }

    private static void ValidateNonce(string nonce, List<ValidationError> errors)
    {
        if (string.IsNullOrEmpty(nonce))
        {
            errors.Add(new ValidationError("Nonce is required", "nonce"));
            return;
        }

        if (!UrlSafeCharacters.IsMatch(nonce))
            errors.Add(new ValidationError("Nonce must contain only ASCII URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)", "nonce"));
    }

    private static void ValidateResponseMode(string responseMode, List<ValidationError> errors)
    {
        if (string.IsNullOrEmpty(responseMode))
        {
            errors.Add(new ValidationError("Response mode is required", "response_mode"));
            return;
        }

        var validModes = new[] { "fragment", "query", "direct_post", "direct_post.jwt", "dc_api.jwt" };
        if (!validModes.Contains(responseMode))
            errors.Add(new ValidationError($"Response mode must be one of: {string.Join(", ", validModes)}, got: {responseMode}", "response_mode"));
    }

    private static void ValidateDcqlAndScope(object? dcqlQuery, string? scope, List<ValidationError> errors)
    {
        var hasDcql = dcqlQuery != null;
        var hasScope = !string.IsNullOrEmpty(scope);

        if (!hasDcql && !hasScope)
            errors.Add(new ValidationError("Either dcql_query or scope must be present", "dcql_query"));

        if (hasDcql && hasScope)
            errors.Add(new ValidationError("Only one of dcql_query or scope can be present, not both", "dcql_query"));
    }

    private static void ValidateRedirectUri(string responseMode, string? redirectUri, List<ValidationError> errors)
    {
        // redirect_uri is not always required based on response_mode
        // Only validate if present in direct_post tests
        // For other modes, it's optional per OAuth 2.0
    }

    private static void ValidateResponseUri(string responseMode, string? responseUri, List<ValidationError> errors)
    {
        // Response URI is required for modes that use response_uri
        if (responseMode == "direct_post" || responseMode == "direct_post.jwt" || responseMode == "dc_api.jwt")
        {
            if (string.IsNullOrEmpty(responseUri))
                errors.Add(new ValidationError($"Response URI is required for response mode '{responseMode}'", "response_uri"));
        }
    }

    private static void ValidateState(string? state, List<ValidationError> errors)
    {
        if (state != null && !UrlSafeCharacters.IsMatch(state))
            errors.Add(new ValidationError("State must contain only ASCII URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)", "state"));
    }

    private static void ValidateRequestUriMethod(string? requestUriMethod, List<ValidationError> errors)
    {
        if (string.IsNullOrEmpty(requestUriMethod))
            return;

        if (requestUriMethod != "get" && requestUriMethod != "post")
            errors.Add(new ValidationError($"Request URI method must be 'get' or 'post', got: {requestUriMethod}", "request_uri_method"));
    }

    private static void ValidateEncryptedResponseEncValues(string? responseMode, ClientMetadata? clientMetadata, List<ValidationError> errors)
    {
        // Per OpenID4VP spec Section 5.1:
        // "encrypted_response_enc_values_supported: OPTIONAL. Non-empty array of strings, where each string is a 
        // JWE enc algorithm that can be used as the content encryption algorithm for encrypting the Response. 
        // When a response_mode requiring encryption of the Response (such as dc_api.jwt or direct_post.jwt) is specified, 
        // this MUST be present for anything other than the default single value of A128GCM. Otherwise, this SHOULD be absent."
        
        if (string.IsNullOrEmpty(responseMode))
            return;

        var encryptedModes = new[] { "direct_post.jwt", "dc_api.jwt" };
        if (encryptedModes.Contains(responseMode))
        {
            // For encrypted response modes with non-default enc values:
            // - If enc values are null/missing: OK (use default A128GCM, SHOULD be absent)
            // - If enc values are [A128GCM] only: OK (that's the default, but SHOULD be absent per spec)
            // - If enc values contain other algorithms: MUST be present and non-empty
            // - If enc values are empty array: ERROR (must be non-empty if present)
            
            if (clientMetadata?.EncryptedResponseEncValuesSupported != null && 
                clientMetadata.EncryptedResponseEncValuesSupported.Count == 0)
            {
                errors.Add(new ValidationError($"encrypted_response_enc_values_supported must be a non-empty array for response mode '{responseMode}'. Specify at least one JWE enc algorithm (e.g., A128GCM, A192GCM, A256GCM).", "encrypted_response_enc_values_supported"));
            }
        }
    }
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
