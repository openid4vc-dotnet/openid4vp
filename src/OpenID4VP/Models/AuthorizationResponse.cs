using System.Text.Json.Serialization;

namespace OpenID4VP.Models;

/// <summary>
/// Represents an OpenID4VP Authorization Response.
/// 
/// The Authorization Response is sent by the Wallet to the Verifier with the requested Presentations.
/// It includes the VP Token containing one or more Verifiable Presentations.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8
/// </summary>
public sealed record AuthorizationResponse
{
    [JsonConstructor]
    internal AuthorizationResponse() { }

    /// <summary>
    /// REQUIRED. The VP Token containing one or more Verifiable Presentations.
    /// 
    /// The structure depends on the response_mode used in the Authorization Request:
    /// - For "fragment" or "query" modes: sent as URL parameter
    /// - For "direct_post" or "direct_post.jwt" modes: sent in request body
    /// 
    /// Specification: Section 8.1
    /// </summary>
    [JsonPropertyName("vp_token")]
    public required VpToken VpToken { get; init; }

    /// <summary>
    /// OPTIONAL. The state value from the Authorization Request.
    /// 
    /// REQUIRED for requests where at least one Presentation without Holder Binding was requested (unless using Digital Credentials API).
    /// MUST match exactly the state value sent in the Authorization Request to prevent CSRF attacks.
    /// 
    /// Specification: Section 8.1, OAuth 2.0 Core
    /// </summary>
    [JsonPropertyName("state")]
    public string? State { get; init; }

    /// <summary>
    /// OPTIONAL. The ID Token when OpenID4VP is combined with SIOPv2.
    /// 
    /// This is only present when the Authorization Request had response_type "vp_token id_token".
    /// Contains the subject identifier and other identity information.
    /// 
    /// Specification: Appendix C - Combining with SIOPv2
    /// </summary>
    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }
}
