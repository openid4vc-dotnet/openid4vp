using System;
using System.Collections.Generic;
using System.Linq;
using OpenID4VC.Core.Results;
using OpenID4VC.Core.Validation;

namespace OpenID4VP.Validators;

/// <summary>
/// Validates cross-device request URI parameters per OpenID4VP Spec Section 3.2.
/// 
/// Cross-device minimal request contains:
/// - client_id (REQUIRED)
/// - request_uri (REQUIRED)
/// - nonce (REQUIRED per Section 5.2)
/// - state (OPTIONAL, ASCII URL-safe if provided)
/// - request_uri_method (OPTIONAL, must be "get" or "post")
/// - custom parameters (OPTIONAL via .WithParameter())
/// </summary>
public class CrossDeviceRequestUriBuilderValidator
{
    /// <summary>
    /// Validates all required and optional parameters for URI construction.
    /// </summary>
    public IEnumerable<Error> ValidateForUriConstruction(
        string? clientId,
        string? requestUri,
        string? nonce,
        string? state,
        string? requestUriMethod)
    {
        var errors = new List<Error>();

        // REQUIRED: client_id
        if (string.IsNullOrWhiteSpace(clientId))
            errors.Add(new ValidationError("client_id is required", "client_id"));

        // REQUIRED: request_uri
        if (string.IsNullOrWhiteSpace(requestUri))
            errors.Add(new ValidationError("request_uri is required", "request_uri"));
        else if (!IsValidUri(requestUri))
            errors.Add(new ValidationError("request_uri must be a valid URI", "request_uri"));

        // REQUIRED: nonce (per spec Section 5.2)
        if (string.IsNullOrWhiteSpace(nonce))
            errors.Add(new ValidationError("nonce is required (per OpenID4VP Spec Section 5.2)", "nonce"));
        else if (!ValidationPatterns.IsValidNonce(nonce))
            errors.Add(new ValidationError("nonce contains invalid characters. Must only contain ASCII URL-safe characters (RFC 3986: A-Z, a-z, 0-9, -, ., _, ~)", "nonce"));

        // OPTIONAL: state
        if (!string.IsNullOrWhiteSpace(state) && !ValidationPatterns.IsValidState(state))
            errors.Add(new ValidationError("state contains invalid characters. Must only contain ASCII URL-safe characters (RFC 3986: A-Z, a-z, 0-9, -, ., _, ~)", "state"));

        // OPTIONAL: request_uri_method (per spec Section 5.1)
        if (!string.IsNullOrWhiteSpace(requestUriMethod))
        {
            var lowerMethod = requestUriMethod.ToLowerInvariant();
            if (lowerMethod != "get" && lowerMethod != "post")
                errors.Add(new ValidationError("request_uri_method must be either 'get' or 'post' (case-insensitive)", "request_uri_method"));
        }

        return errors;
    }

    /// <summary>
    /// Checks if a string is a valid URI by attempting to parse it.
    /// </summary>
    private static bool IsValidUri(string uriString)
    {
        try
        {
            _ = new Uri(uriString, UriKind.Absolute);
            return true;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }
}
