using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Presentation;

/// <summary>
/// DCQL Presentation structure (VP Token).
/// 
/// This is a JSON-encoded object containing entries where the key is the id value used for
/// a Credential Query in the DCQL query and the value is an array of one or more Presentations
/// that match the respective Credential Query.
/// 
/// Pure Data Model - validation logic is delegated to PresentationValidator.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.1
/// </summary>
public sealed record DcqlPresentation
{
    /// <summary>
    /// Presentations keyed by credential query ID.
    /// Each entry contains one or more presentations (string or JSON object) for that credential.
    /// 
    /// When 'multiple' is false, the array MUST contain only one Presentation.
    /// When 'multiple' is true, the array MAY contain multiple Presentations.
    /// </summary>
    [JsonExtensionData]
    public required Dictionary<string, PresentationEntry> Presentations { get; init; }

    /// <summary>
    /// Gets the presentation(s) for a specific credential query ID.
    /// </summary>
    public PresentationEntry? this[string credentialId] =>
        Presentations.TryGetValue(credentialId, out var entry) ? entry : null;
}
