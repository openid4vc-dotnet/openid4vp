using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Presentation;

namespace OpenID4VP.Models;

/// <summary>
/// Represents a VP Token - a container for one or more Verifiable Presentations.
/// 
/// The VP Token is always a JSON object (dictionary) where:
/// - Key: presentation ID
/// - Value: array of one or more Presentations (each Presentation is string or object)
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.1
/// </summary>
public sealed record VpToken
{
    [JsonConstructor]
    internal VpToken() { }

    /// <summary>
    /// REQUIRED. Presentations keyed by presentation ID.
    /// 
    /// Each entry contains one or more presentations (string or JSON object) for that presentation ID.
    /// This is always a JSON object (dictionary), never a string or array.
    /// 
    /// Specification: Section 8.1
    /// </summary>
    [JsonPropertyName("vp_token")]
    public required Dictionary<string, PresentationEntry> Presentations { get; init; }
}
