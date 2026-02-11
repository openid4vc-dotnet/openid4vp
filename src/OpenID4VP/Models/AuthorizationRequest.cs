using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Models;

/// <summary>
/// Represents an OpenID4VP Authorization Request.
/// 
/// The Authorization Request is sent by the Verifier to the Wallet to request a Presentation.
/// It includes a DCQL query that specifies which Credentials and Claims are requested.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5
/// </summary>
public sealed record AuthorizationRequest
{
    [JsonConstructor]
    internal AuthorizationRequest() { }

    /// <summary>
    /// REQUIRED. The response type. MUST be set to "vp_token" or "vp_token id_token" (when combined with SIOPv2).
    /// Specification: Section 5.6
    /// </summary>
    [JsonPropertyName("response_type")]
    public required string ResponseType { get; init; }

    /// <summary>
    /// REQUIRED. The Client Identifier of the Verifier.
    /// Specification: Section 5.2
    /// </summary>
    [JsonPropertyName("client_id")]
    public required string ClientId { get; init; }

    /// <summary>
    /// REQUIRED. A case-sensitive string representing a value to securely bind Verifiable Presentation(s) 
    /// provided by the Wallet to the particular transaction.
    /// 
    /// Values MUST only contain ASCII URL safe characters (uppercase and lowercase letters, decimal digits, 
    /// hyphen, period, underscore, and tilde).
    /// Specification: Section 5.2
    /// </summary>
    [JsonPropertyName("nonce")]
    public required string Nonce { get; init; }

    /// <summary>
    /// REQUIRED. A JSON object containing a DCQL query as defined in Section 6.
    /// Either dcql_query or scope parameter (representing a DCQL Query) MUST be present, but not both.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("dcql_query")]
    public required DcqlQuery DcqlQuery { get; init; }

    /// <summary>
    /// REQUIRED. This parameter determines how the response will be sent.
    /// Valid values are: "fragment", "query", "direct_post", "direct_post.jwt"
    /// Specification: Section 5.2
    /// </summary>
    [JsonPropertyName("response_mode")]
    public required string ResponseMode { get; init; }

    /// <summary>
    /// OPTIONAL. The URI where the response will be sent.
    /// REQUIRED when response_mode is "direct_post" or "direct_post.jwt".
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("response_uri")]
    public string? ResponseUri { get; init; }

    /// <summary>
    /// OPTIONAL. Used to maintain state between request and response.
    /// REQUIRED for requests where at least one Presentation without Holder Binding is requested (unless using Digital Credentials API).
    /// Values MUST only contain ASCII URL safe characters.
    /// Specification: Section 5.2
    /// </summary>
    [JsonPropertyName("state")]
    public string? State { get; init; }

    /// <summary>
    /// OPTIONAL. The URI to which the Authorization Response will be sent.
    /// OPTIONAL when response_mode is "fragment", REQUIRED otherwise.
    /// Specification: OAuth 2.0 Core
    /// </summary>
    [JsonPropertyName("redirect_uri")]
    public string? RedirectUri { get; init; }

    /// <summary>
    /// OPTIONAL. A space-delimited list of scopes.
    /// Either dcql_query or scope MUST be present, but not both.
    /// Specification: Section 5.5
    /// </summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    /// <summary>
    /// OPTIONAL. A string determining the HTTP method to be used when the request_uri parameter is included.
    /// Valid values: "get" or "post". Defaults to "get".
    /// MUST NOT be present if request_uri is not present.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("request_uri_method")]
    public string? RequestUriMethod { get; init; }

    /// <summary>
    /// OPTIONAL. A JSON object containing the Verifier metadata values.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("client_metadata")]
    public VerifierMetadata? ClientMetadata { get; init; }

    /// <summary>
    /// OPTIONAL. Non-empty array of attestations about the Verifier relevant to the Credential Request.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("verifier_info")]
    public IReadOnlyList<VerifierAttestation>? VerifierInfo { get; init; }

    /// <summary>
    /// OPTIONAL. Non-empty array of base64url-encoded JSON objects containing transaction details.
    /// Specification: Section 5.1
    /// </summary>
    [JsonPropertyName("transaction_data")]
    public IReadOnlyList<string>? TransactionData { get; init; }
}
