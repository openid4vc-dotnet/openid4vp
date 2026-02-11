using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Metadata for W3C VC credential queries.
/// </summary>
public sealed record W3cVcMeta : ICredentialMeta
{
    [JsonConstructor]
    internal W3cVcMeta() { }

    /// <summary>
    /// REQUIRED. An array of string arrays that specifies the fully expanded types (IRIs) after
    /// the @context was applied that the Verifier accepts to be presented in the Presentation.
    /// </summary>
    [JsonPropertyName("type_values")]
    public required NonEmptyArray<NonEmptyArray<string>> TypeValues { get; init; }
}
