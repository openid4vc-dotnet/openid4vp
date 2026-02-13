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
    /// This builder is intentionally permissive - it allows any combination of fields.
    /// Scenario-specific validators should be used to validate the request for a specific use case:
    /// - SameDeviceAuthorizationRequestValidator: Complete request for same-device flow
    /// - CrossDeviceAuthorizationRequestValidator: Minimal request for cross-device flow
    /// - RequestObjectAuthorizationRequestValidator: Request Object for cross-device (from request_uri)
    /// </summary>
    public AuthorizationRequest Build()
    {
        // Minimal validation: only enforce absolutely required fields
        if (string.IsNullOrEmpty(_clientId))
            throw new InvalidOperationException("client_id is required");

        if (string.IsNullOrEmpty(_responseMode))
            throw new InvalidOperationException("response_mode is required");

        // Build DCQL if configured
        var dcqlQuery = _dcqlBuilder?.Build();

        // Return the request - let scenario-specific validators check if it's suitable for the intended use
        return new AuthorizationRequest
        {
            ResponseType = _responseType ?? "vp_token",
            ClientId = _clientId!,
            Nonce = _nonce ?? "nonce",
            ResponseMode = _responseMode!,
            DcqlQuery = dcqlQuery,
            RedirectUri = _redirectUri,
            ResponseUri = _responseUri,
            State = _state,
            Scope = _scope,
            RequestUri = _requestUri,
            RequestUriMethod = _requestUriMethod,
            ClientMetadata = _clientMetadata,
            VerifierInfo = _verifierInfo?.AsReadOnly(),
            TransactionData = _transactionData?.AsReadOnly()
        };
    }
}
