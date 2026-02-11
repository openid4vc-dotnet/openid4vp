using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Metadata for mdoc credential queries.
/// </summary>
public sealed record MdocMeta : ICredentialMeta
{
    [JsonConstructor]
    internal MdocMeta() { }

    /// <summary>
    /// OPTIONAL. String that specifies an allowed value for the doctype of the requested Verifiable Credential.
    /// </summary>
    [JsonPropertyName("doctype_value")]
    public string? DoctypeValue { get; init; }
}
