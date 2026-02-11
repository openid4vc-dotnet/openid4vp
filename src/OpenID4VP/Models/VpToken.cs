using System.Text.Json.Serialization;

namespace OpenID4VP.Models;

/// <summary>
/// Represents a VP Token - a container for one or more Verifiable Presentations.
/// 
/// The VP Token contains presentations in one or more formats (W3C VC, mdoc, SD-JWT, etc.).
/// The internal structure is format-agnostic and stores the raw presentations.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.1
/// </summary>
public sealed record VpToken
{
    [JsonConstructor]
    internal VpToken() { }

    /// <summary>
    /// REQUIRED. One or more Verifiable Presentations or Presentations.
    /// 
    /// This can be:
    /// - A single string (JWT format presentation)
    /// - A JSON array of presentations
    /// - A nested JSON object containing presentations
    /// 
    /// The exact structure depends on the credential format(s) used.
    /// Specification: Section 8.1
    /// </summary>
    [JsonPropertyName("vp_token")]
    public required object Presentations { get; init; }
}
