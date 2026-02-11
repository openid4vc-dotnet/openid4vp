using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Metadata for SD-JWT VC credential queries.
/// </summary>
public sealed record SdJwtVcMeta : ICredentialMeta
{
    [JsonConstructor]
    internal SdJwtVcMeta() { }

    /// <summary>
    /// OPTIONAL. An array of strings that specifies allowed values for the type (vct) of the requested Verifiable Credential.
    /// </summary>
    [JsonPropertyName("vct_values")]
    public string[]? VctValues { get; init; }
}
