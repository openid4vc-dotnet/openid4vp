using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;
using OpenID4VC.Core.Validation;

namespace OpenID4VP.Builders;

/// <summary>
/// Builder for creating AuthorizationRequest objects.
/// 
/// This builder enforces the SOLID principle of encapsulation: AuthorizationRequest objects
/// cannot be instantiated directly - they can only be created through this builder.
/// 
/// The builder implements a fluent API for configuration and accumulates validation errors
/// which are all returned together when Build() is called, enabling users to see all
/// validation issues at once rather than failing on the first error.
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
    private ClientMetadata? _clientMetadata;
    private List<VerifierAttestation>? _verifierInfo;
    private List<string>? _transactionData;
    private readonly List<Error> _errors = [];
    private bool _dcqlAlreadySet = false;

    /// <summary>
    /// Creates a new AuthorizationRequestBuilder instance.
    /// </summary>
    public static AuthorizationRequestBuilder Create() => new();

    /// <summary>
    /// Sets the response type. REQUIRED.
    /// Valid values: "vp_token" or "vp_token id_token"
    /// </summary>
    public AuthorizationRequestBuilder WithResponseType(string? responseType)
    {
        if (string.IsNullOrWhiteSpace(responseType))
            _errors.Add(BuilderErrors.ResponseTypeIsRequired());

        _responseType = responseType;
        return this;
    }

    /// <summary>
    /// Sets the Client Identifier of the Verifier. REQUIRED.
    /// 
    /// The client_id can be:
    /// - A direct HTTPS URL: "https://verifier.example.org"
    /// - A prefixed identifier: "redirect_uri:https://verifier.example.com/callback"
    /// 
    /// Use the WithClientId(prefix, value) overload for type-safe construction with a prefix.
    /// </summary>
    public AuthorizationRequestBuilder WithClientId(string? clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            _errors.Add(BuilderErrors.ClientIdIsRequired());
        }

        _clientId = clientId;
        return this;
    }

    /// <summary>
    /// Sets the Client Identifier of the Verifier using a prefix constant and value. REQUIRED.
    /// 
    /// This overload provides a type-safe, fluent way to build client identifiers by separating
    /// the prefix from the value. The method constructs the full client identifier as: prefix:value
    /// 
    /// Example: WithClientId(ClientIdentifierPrefix.X509SanDns, "client.example.org")
    ///          → Constructs: "x509_san_dns:client.example.org"
    /// 
    /// Note: Only the 6 real prefixes from the OpenID4VP specification are supported here.
    /// For direct HTTPS URLs, use the WithClientId(string) overload instead.
    /// </summary>
    /// <param name="prefix">The prefix constant (e.g., ClientIdentifierPrefix.X509SanDns)</param>
    /// <param name="value">The value portion of the client identifier</param>
    public AuthorizationRequestBuilder WithClientId(string? prefix, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            _errors.Add(BuilderErrors.ClientIdIsRequired());
            _clientId = null;
            return this;
        }

        if (string.IsNullOrWhiteSpace(prefix))
        {
            _errors.Add(BuilderErrors.ClientIdIsRequired());
            _clientId = null;
            return this;
        }

        // All prefixes use colon separator: prefix:value
        _clientId = $"{prefix}:{value}";
        return this;
    }

    /// <summary>
    /// Sets the nonce value. REQUIRED.
    /// Per OpenID4VP Spec Section 5.2: "Values MUST only contain ASCII URL safe characters."
    /// Valid characters: A-Z, a-z, 0-9, hyphen (-), period (.), underscore (_), tilde (~)
    /// </summary>
    public AuthorizationRequestBuilder WithNonce(string? nonce)
    {
        if (string.IsNullOrWhiteSpace(nonce))
        {
            _errors.Add(BuilderErrors.NonceIsRequired());
        }
        else if (!ValidationPatterns.IsValidNonce(nonce))
        {
            _errors.Add(BuilderErrors.InvalidNonceCharacters());
        }

        _nonce = nonce;
        return this;
    }

    /// <summary>
    /// Sets the response mode. REQUIRED.
    /// Valid values: "fragment", "query", "direct_post", "direct_post.jwt", "dc_api.jwt"
    /// </summary>
    public AuthorizationRequestBuilder WithResponseMode(string? responseMode)
    {
        if (string.IsNullOrWhiteSpace(responseMode))
            _errors.Add(BuilderErrors.ResponseModeIsRequired());

        _responseMode = responseMode;
        return this;
    }

    /// <summary>
    /// Sets the DCQL query. REQUIRED. Callable only once.
    /// The builder creates a DcqlQueryBuilder internally and passes it to the configure action.
    /// </summary>
    public AuthorizationRequestBuilder WithDcql(Action<DcqlQueryBuilder>? configure)
    {
        if (_dcqlAlreadySet)
            _errors.Add(BuilderErrors.DcqlCanOnlyBeSetOnce());

        if (configure == null)
        {
            _errors.Add(BuilderErrors.DcqlConfigureCannotBeNull());
            return this;
        }

        _dcqlBuilder = DcqlQueryBuilder.Create();
        configure(_dcqlBuilder);
        _dcqlAlreadySet = true;
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
    public AuthorizationRequestBuilder WithRequestUri(string? requestUri)
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
    /// Sets the Verifier metadata (client_metadata parameter) using a fluent context builder.
    /// 
    /// This is the recommended way to configure metadata, providing a clean fluent API for all options.
    /// 
    /// Example:
    /// <code>
    /// .WithClientMetadata(metadata => metadata
    ///     .WithName("MyVerifier")
    ///     .WithLogoUri("https://example.com/logo.png")
    ///     .WithJwksUri("https://example.com/jwks.json")
    ///     .WithPublicKeyFromRsaPrivateKey(rsaKey))
    /// </code>
    /// </summary>
    /// <param name="configure">Callback to configure the ClientMetadata context</param>
    /// <returns>This builder for fluent chaining</returns>
    public AuthorizationRequestBuilder WithClientMetadata(Action<ClientMetadataBuilderContext>? configure)
    {
        if (configure == null)
        {
            _errors.Add(new ValidationError("ClientMetadata configure callback cannot be null", "validation_error"));
            return this;
        }

        var context = ClientMetadataBuilderContext.Create();
        configure(context);
        var result = context.Build();

        if (!result.IsSuccess)
        {
            _errors.AddRange(result.Errors);
            return this;
        }

        _clientMetadata = result.Value;
        return this;
    }

    /// <summary>
    /// Adds a Verifier attestation to the verifier_info array.
    /// </summary>
    public AuthorizationRequestBuilder AddVerifierAttestation(VerifierAttestation? attestation)
    {
        if (attestation == null)
            _errors.Add(BuilderErrors.VerifierAttestationCannotBeNull());

        if (attestation != null)
        {
            _verifierInfo ??= [];
            _verifierInfo.Add(attestation);
        }

        return this;
    }

    /// <summary>
    /// Adds transaction data (base64url-encoded JSON string).
    /// </summary>
    public AuthorizationRequestBuilder AddTransactionData(string? transactionData)
    {
        if (string.IsNullOrWhiteSpace(transactionData))
            _errors.Add(BuilderErrors.TransactionDataCannotBeNull());

        if (!string.IsNullOrWhiteSpace(transactionData))
        {
            _transactionData ??= [];
            _transactionData.Add(transactionData);
        }

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
    public Result<AuthorizationRequest> Build()
    {
        // Return all accumulated errors if any exist
        if (_errors.Any())
            return _errors.ToArray();

        // Minimal validation: only enforce absolutely required fields
        if (string.IsNullOrEmpty(_clientId))
            return BuilderErrors.ClientIdIsRequired();

        // response_mode: Not required at build time - scenario-specific validators 
        // will enforce requirements based on flow type (same-device, cross-device, etc.)
        // Some flows like cross-device may not need response_mode in the minimal request
        
        // Build DCQL if configured
        var dcqlQuery = _dcqlBuilder?.Build();

        // Return the request - let scenario-specific validators check if it's suitable for the intended use
        var request = new AuthorizationRequest
        {
            ResponseType = _responseType,
            ClientId = _clientId!,
            Nonce = _nonce,
            ResponseMode = _responseMode,  // Can be null - validators will enforce if needed
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

        return request;
    }
}
