using OpenID4VC.Core.Results;
using OpenID4VP.Validators;

namespace OpenID4VP.Builders;

/// <summary>
/// Fluent builder context for cross-device request URIs.
/// Accumulates parameters and generates a complete query string URI suitable for QR codes.
/// </summary>
public class CrossDeviceRequestUriBuilderContext
{
    private string? _clientId;
    private string? _requestUri;
    private string? _nonce;
    private string? _state;
    private string? _requestUriMethod;
    private readonly Dictionary<string, string> _customParameters = new();

    /// <summary>
    /// Sets the client_id (REQUIRED).
    /// </summary>
    public CrossDeviceRequestUriBuilderContext WithClientId(string clientId)
    {
        _clientId = clientId;
        return this;
    }

    public CrossDeviceRequestUriBuilderContext WithClientId(string? prefix, string? value)
    {
        // All prefixes use colon separator: prefix:value
        _clientId = $"{prefix}:{value}";
        return this;
    }


    /// <summary>
    /// Sets the request_uri (REQUIRED).
    /// </summary>
    public CrossDeviceRequestUriBuilderContext WithRequestUri(string requestUri)
    {
        _requestUri = requestUri;
        return this;
    }

    /// <summary>
    /// Sets the nonce (REQUIRED per OpenID4VP Spec Section 5.2).
    /// Must contain only ASCII URL-safe characters (RFC 3986: A-Z, a-z, 0-9, -, ., _, ~).
    /// </summary>
    public CrossDeviceRequestUriBuilderContext WithNonce(string nonce)
    {
        _nonce = nonce;
        return this;
    }

    /// <summary>
    /// Sets the optional state parameter.
    /// Must contain only ASCII URL-safe characters if provided.
    /// </summary>
    public CrossDeviceRequestUriBuilderContext WithState(string state)
    {
        _state = state;
        return this;
    }

    /// <summary>
    /// Sets the optional request_uri_method parameter (per OpenID4VP Spec Section 5.1).
    /// Determines the HTTP method used to fetch the authorization request from request_uri.
    /// Valid values: "get" (default) or "post" (case-insensitive).
    /// Only included in query string if explicitly provided.
    /// </summary>
    public CrossDeviceRequestUriBuilderContext WithRequestUriMethod(string method)
    {
        _requestUriMethod = method;
        return this;
    }

    /// <summary>
    /// Adds a custom parameter to the query string.
    /// If called multiple times with the same key, the last value wins.
    /// </summary>
    public CrossDeviceRequestUriBuilderContext WithParameter(string key, string value)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentException("Parameter key cannot be null or whitespace", nameof(key));
        
        _customParameters[key] = value ?? string.Empty;
        return this;
    }

    /// <summary>
    /// Builds the complete cross-device request URI with all parameters.
    /// </summary>
    /// <param name="baseUri">The base URI to which query parameters will be appended (e.g., "https://verifier.example.com/auth")</param>
    /// <returns>A Result containing the complete URI if successful, or validation errors if failed</returns>
    public Result<string> Build(string baseUri)
    {
        if (string.IsNullOrEmpty(baseUri))
            return Result<string>.Failure(new ValidationError("Base URI cannot be null or empty", "baseUri"));

        // Validate parameters
        var validator = new CrossDeviceRequestUriBuilderValidator();
        var validationErrors = validator.ValidateForUriConstruction(_clientId, _requestUri, _nonce, _state, _requestUriMethod).ToList();
        
        if (validationErrors.Any())
            return Result<string>.Failure(validationErrors);

        // Build URI with query parameters
        var queryParams = new Dictionary<string, string>();

        // REQUIRED parameters
        queryParams["client_id"] = _clientId!;
        queryParams["request_uri"] = _requestUri!;
        queryParams["nonce"] = _nonce!;

        // OPTIONAL parameters
        if (!string.IsNullOrEmpty(_state))
            queryParams["state"] = _state;

        // OPTIONAL: request_uri_method (normalize to lowercase if provided)
        if (!string.IsNullOrEmpty(_requestUriMethod))
            queryParams["request_uri_method"] = _requestUriMethod.ToLowerInvariant();

        // Custom parameters (overwrite standard params if keys conflict)
        foreach (var kvp in _customParameters)
            queryParams[kvp.Key] = kvp.Value;

        var uri = BuildUriWithQueryParameters(baseUri, queryParams);
        return Result<string>.Success(uri);
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
