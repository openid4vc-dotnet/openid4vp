using OpenID4VP.Common;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Models;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for creating AuthorizationRequest objects.
/// 
/// This builder enforces the SOLID principle of encapsulation: AuthorizationRequest objects
/// cannot be instantiated directly - they can only be created through this builder.
/// 
/// The builder implements a fluent API for configuration and ensures all required fields are set
/// before Build() is called.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5
/// </summary>
public sealed class AuthorizationRequestBuilder
{
    private string? _responseType;
    private string? _clientId;
    private string? _nonce;
    private string? _responseMode;
    private DcqlQueryBuilder? _dcqlBuilder;
    private string? _redirectUri;
    private string? _responseUri;
    private string? _requestUri;
    private string? _state;
    private string? _scope;
    private string? _requestUriMethod;
    private VerifierMetadata? _clientMetadata;
    private List<VerifierAttestation>? _verifierInfo;
    private List<string>? _transactionData;

    /// <summary>
    /// Creates a new AuthorizationRequestBuilder instance.
    /// </summary>
    public static AuthorizationRequestBuilder Create() => new();

    /// <summary>
    /// Sets the response type. REQUIRED.
    /// Valid values: "vp_token" or "vp_token id_token"
    /// </summary>
    public AuthorizationRequestBuilder WithResponseType(string responseType)
    {
        if (string.IsNullOrWhiteSpace(responseType))
            throw new ArgumentException("Response type cannot be null or empty", nameof(responseType));

        _responseType = responseType;
        return this;
    }

    /// <summary>
    /// Sets the Client Identifier of the Verifier. REQUIRED.
    /// </summary>
    public AuthorizationRequestBuilder WithClientId(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            throw new ArgumentException("Client ID cannot be null or empty", nameof(clientId));

        _clientId = clientId;
        return this;
    }

    /// <summary>
    /// Sets the nonce value. REQUIRED.
    /// Must contain only ASCII URL-safe characters (uppercase/lowercase letters, decimal digits, hyphen, period, underscore, tilde).
    /// </summary>
    public AuthorizationRequestBuilder WithNonce(string nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
            throw new ArgumentException("Nonce cannot be null or empty", nameof(nonce));

        _nonce = nonce;
        return this;
    }

    /// <summary>
    /// Sets the response mode. REQUIRED.
    /// Valid values: "fragment", "query", "direct_post", "direct_post.jwt"
    /// </summary>
    public AuthorizationRequestBuilder WithResponseMode(string responseMode)
    {
        if (string.IsNullOrWhiteSpace(responseMode))
            throw new ArgumentException("Response mode cannot be null or empty", nameof(responseMode));

        _responseMode = responseMode;
        return this;
    }

    /// <summary>
    /// Sets the DCQL query. REQUIRED. Callable only once.
    /// The builder creates a DcqlQueryBuilder internally and passes it to the configure action.
    /// </summary>
    public AuthorizationRequestBuilder WithDcql(Action<DcqlQueryBuilder> configure)
    {
        if (_dcqlBuilder != null)
            throw new InvalidOperationException("DCQL query can only be set once");

        if (configure == null)
            throw new ArgumentNullException(nameof(configure));

        _dcqlBuilder = DcqlQueryBuilder.Create();
        configure(_dcqlBuilder);
        return this;
    }

    /// <summary>
    /// Sets the redirect URI where the response will be sent.
    /// OPTIONAL when response_mode is "fragment", REQUIRED otherwise.
    /// </summary>
    public AuthorizationRequestBuilder WithRedirectUri(string? redirectUri)
    {
        _redirectUri = redirectUri;
        return this;
    }

    /// <summary>
    /// Sets the response URI where the response will be sent (for direct_post modes).
    /// REQUIRED when response_mode is "direct_post" or "direct_post.jwt".
    /// </summary>
    public AuthorizationRequestBuilder WithResponseUri(string? responseUri)
    {
        _responseUri = responseUri;
        return this;
    }

    /// <summary>
    /// Sets the request URI where the wallet fetches the full Request Object.
    /// REQUIRED for cross-device mode. Points to endpoint with full authorization parameters.
    /// </summary>
    public AuthorizationRequestBuilder WithRequestUri(string requestUri)
    {
        _requestUri = requestUri;
        return this;
    }

    /// <summary>
    /// Sets the state value for maintaining state between request and response.
    /// REQUIRED for requests where at least one Presentation without Holder Binding is requested.
    /// Must contain only ASCII URL-safe characters.
    /// </summary>
    public AuthorizationRequestBuilder WithState(string? state)
    {
        _state = state;
        return this;
    }

    /// <summary>
    /// Sets the scope value as an alternative to DCQL query.
    /// Either scope or dcql_query MUST be present, but not both.
    /// </summary>
    public AuthorizationRequestBuilder WithScope(string? scope)
    {
        _scope = scope;
        return this;
    }

    /// <summary>
    /// Sets the request URI method for retrieving the Request Object.
    /// Valid values: "get" or "post". Defaults to "get".
    /// MUST NOT be present if request_uri is not present.
    /// </summary>
    public AuthorizationRequestBuilder WithRequestUriMethod(string? requestUriMethod)
    {
        _requestUriMethod = requestUriMethod;
        return this;
    }

    /// <summary>
    /// Sets the Verifier metadata (client_metadata parameter).
    /// </summary>
    public AuthorizationRequestBuilder WithClientMetadata(VerifierMetadata? clientMetadata)
    {
        _clientMetadata = clientMetadata;
        return this;
    }

    /// <summary>
    /// Adds a Verifier attestation to the verifier_info array.
    /// </summary>
    public AuthorizationRequestBuilder AddVerifierAttestation(VerifierAttestation attestation)
    {
        if (attestation == null)
            throw new ArgumentNullException(nameof(attestation));

        _verifierInfo ??= [];
        _verifierInfo.Add(attestation);
        return this;
    }

    /// <summary>
    /// Adds transaction data (base64url-encoded JSON string).
    /// </summary>
    public AuthorizationRequestBuilder AddTransactionData(string transactionData)
    {
        if (string.IsNullOrWhiteSpace(transactionData))
            throw new ArgumentException("Transaction data cannot be null or empty", nameof(transactionData));

        _transactionData ??= [];
        _transactionData.Add(transactionData);
        return this;
    }

    /// <summary>
    /// Builds the AuthorizationRequest object.
    /// Automatically builds the DCQL query builder if one was configured.
    /// 
    /// This method performs device-mode-aware validation based on response_mode:
    /// 
    /// 
    /// </summary>
    public AuthorizationRequest Build()
    {
        if (_requestUri != null)
        {
            return BuildCrossDeviceMode();
        }

        return BuildSameDeviceMode();
    }

    /// <summary>
    /// Validates and builds a same-device mode request.
    /// Same-device: redirect_uri for fragment/query response delivery with full inline parameters.
    /// 
    /// SAME DEVICE MODE (response_mode: "fragment" or "query"):
    ///   - REQUIRED: response_type, client_id, nonce, response_mode, redirect_uri, dcql_query OR scope
    ///   - FORBIDDEN: request_uri, response_uri
    ///   - Spec: Section 3.1 - Same Device Mode
    /// 
    /// </summary>
    private AuthorizationRequest BuildSameDeviceMode()
    {
        var errors = new List<string>();

        // Required fields for same-device
        if (string.IsNullOrEmpty(_responseType))
            errors.Add("response_type is REQUIRED for same-device mode");
        if (string.IsNullOrEmpty(_clientId))
            errors.Add("client_id is REQUIRED");
        if (string.IsNullOrEmpty(_nonce))
            errors.Add("nonce is REQUIRED for same-device mode");
        if (string.IsNullOrEmpty(_redirectUri))
            errors.Add("redirect_uri is REQUIRED for same-device mode (fragment/query response delivery)");

        // DCQL or scope required
        if (_dcqlBuilder == null && string.IsNullOrEmpty(_scope))
            errors.Add("Either dcql_query or scope must be set");

        // DCQL and scope cannot both be set
        if (_dcqlBuilder != null && !string.IsNullOrEmpty(_scope))
            errors.Add("Only one of dcql_query or scope can be set");

        // Forbidden: request_uri in same-device
        if (!string.IsNullOrEmpty(_requestUri))
            errors.Add(
                "request_uri MUST NOT be set in same-device mode. " +
                "Same-device sends full parameters inline via redirect_uri. " +
                "request_uri is used only in cross-device mode (direct_post).");

        // Problematic: response_uri in same-device
        if (!string.IsNullOrEmpty(_responseUri))
            errors.Add(
                "response_uri SHOULD NOT be set in same-device mode. " +
                "Same-device uses redirect_uri for response delivery.");

        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"Cannot build AuthorizationRequest:\n  - {string.Join("\n  - ", errors)}");

        var dcqlQuery = _dcqlBuilder?.Build();

        if (dcqlQuery == null && string.IsNullOrEmpty(_scope))
            throw new InvalidOperationException("DCQL query must be set via WithDcql() or scope via WithScope()");

        return new AuthorizationRequest
        {
            ResponseType = _responseType!,
            ClientId = _clientId!,
            Nonce = _nonce!,
            ResponseMode = _responseMode!,
            DcqlQuery = dcqlQuery!,
            RedirectUri = _redirectUri,
            ResponseUri = _responseUri,
            State = _state,
            Scope = _scope,
            RequestUriMethod = _requestUriMethod,
            ClientMetadata = _clientMetadata,
            VerifierInfo = _verifierInfo?.AsReadOnly(),
            TransactionData = _transactionData?.AsReadOnly()
        };
    }

    /// <summary>
    /// Validates and builds a cross-device mode request.
    /// Cross-device: minimal request (client_id + request_uri) encoded in QR code.
    /// Full parameters sent in RequestObject retrieved from request_uri endpoint.
    /// 
    /// CROSS DEVICE MODE (response_mode: "direct_post" or "direct_post.jwt"):
    ///   - REQUIRED: client_id, request_uri
    ///   - OPTIONAL: state
    ///   - FORBIDDEN: response_type, nonce, dcql_query, scope, redirect_uri, response_uri
    ///   - Spec: Section 3.2 - Cross Device Mode
    ///   - Note: Full request parameters go in RequestObject fetched from request_uri
    /// 
    /// Note: This returns an AuthorizationRequest object but only with the minimal
    /// cross-device fields populated. Other fields contain placeholder values that
    /// should not be used. In production, handle cross-device requests separately.
    /// </summary>
    private AuthorizationRequest BuildCrossDeviceMode()
    {
        var errors = new List<string>();

        // Required: Only client_id and request_uri for minimal cross-device request
        if (string.IsNullOrEmpty(_clientId))
            errors.Add("client_id is REQUIRED");

        if (string.IsNullOrEmpty(_requestUri))
            errors.Add(
                "request_uri is REQUIRED for cross-device mode. " +
                "It points to the endpoint where the wallet fetches the full RequestObject.");

        // Forbidden: Full request parameters in minimal request
        if (!string.IsNullOrEmpty(_responseType))
            errors.Add(
                "response_type MUST NOT be set in cross-device mode minimal request. " +
                "Include it in the RequestObject on the request_uri endpoint instead. " +
                "Spec: Section 3.2 - 'Authorization Request contains only the Client Identifier and Request URI'");

        if (!string.IsNullOrEmpty(_nonce))
            errors.Add(
                "nonce MUST NOT be set in cross-device mode minimal request. " +
                "Include it in the RequestObject on the request_uri endpoint instead.");

        if (_dcqlBuilder != null)
            errors.Add(
                "dcql_query MUST NOT be set in cross-device mode minimal request. " +
                "Include it in the RequestObject on the request_uri endpoint instead.");

        if (!string.IsNullOrEmpty(_scope))
            errors.Add(
                "scope MUST NOT be set in cross-device mode minimal request. " +
                "Include it in the RequestObject on the request_uri endpoint instead.");

        if (string.IsNullOrEmpty(_responseMode))
        {
            // Cross-device doesn't need response_mode in minimal request
            // But if we got here, we detected it's cross-device, so this shouldn't happen
        }
        else if (!IsCrossDeviceMode(_responseMode))
        {
            errors.Add($"response_mode '{_responseMode}' does not match cross-device mode");
        }

        // Forbidden: redirect_uri in cross-device (uses response_uri from RequestObject)
        if (!string.IsNullOrEmpty(_redirectUri))
            errors.Add(
                "redirect_uri MUST NOT be set in cross-device mode. " +
                "Cross-device uses response_uri from the RequestObject for response delivery.");

        // Forbidden: response_uri in minimal request (comes from RequestObject)
        if (!string.IsNullOrEmpty(_responseUri))
            errors.Add(
                "response_uri MUST NOT be set in cross-device mode minimal request. " +
                "It comes from the RequestObject retrieved from request_uri.");

        if (errors.Count > 0)
            throw new InvalidOperationException(
                $"Cannot build cross-device AuthorizationRequest:\n  - {string.Join("\n  - ", errors)}");

        // Build a minimal request - the fields that actually matter for cross-device are:
        // client_id, request_uri, and state (optional)
        // All other fields are filled with placeholders and shouldn't be used
        var builder = DcqlQueryBuilder.Create();
        builder.AddW3cVcCredential("placeholder", b => b.AddTypeValues("placeholder"));
        
        return new AuthorizationRequest
        {
            ResponseType = "vp_token",  // Placeholder - comes from RequestObject
            ClientId = _clientId!,       // Real value
            Nonce = "placeholder",       // Placeholder - comes from RequestObject
            ResponseMode = _responseMode ?? "direct_post",  // Placeholder - comes from RequestObject
            DcqlQuery = builder.Build(), // Placeholder - comes from RequestObject
            RedirectUri = null,
            ResponseUri = null,          // Placeholder - comes from RequestObject
            State = _state,              // Real value if set
            Scope = null,                // Placeholder - comes from RequestObject
            RequestUriMethod = _requestUriMethod,
            ClientMetadata = null,
            VerifierInfo = null,
            TransactionData = null
        };
    }

    /// <summary>
    /// Determines if the response mode indicates same-device mode.
    /// Same-device modes: "fragment", "query"
    /// </summary>
    private static bool IsSameDeviceMode(string? responseMode) =>
        !string.IsNullOrEmpty(responseMode) && 
        (responseMode == "fragment" || responseMode == "query");

    /// <summary>
    /// Determines if the response mode indicates cross-device mode.
    /// Cross-device modes: "direct_post", "direct_post.jwt"
    /// </summary>
    private static bool IsCrossDeviceMode(string? responseMode) =>
        !string.IsNullOrEmpty(responseMode) && 
        (responseMode == "direct_post" || responseMode == "direct_post.jwt");
}
