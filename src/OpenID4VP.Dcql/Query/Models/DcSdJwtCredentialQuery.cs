using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Credential Query for Decentralized Credentials SD-JWT format (dc+sd-jwt).
/// Specification: OpenID for Verifiable Presentations 1.0, Appendix B.2
/// </summary>
public sealed record DcSdJwtCredentialQuery : DcqlCredentialQuery
{
    [JsonConstructor]
    internal DcSdJwtCredentialQuery() { }

    [JsonIgnore]
    public override string Format => CredentialFormats.DcSdJwt;

    public override IEnumerable<string>? GetClaimIds() => 
        Claims?.Where(c => c.Id != null).Select(c => c.Id!);

    public override ICredentialMeta? GetMetadata() => Meta;

    /// <summary>
    /// OPTIONAL. A non-empty array of objects that specifies claims in the requested Credential.
    /// </summary>
    [JsonPropertyName("claims")]
    [JsonPropertyOrder(10)]
    public NonEmptyArray<JsonClaimQuery>? Claims { get; init; }

    /// <summary>
    /// OPTIONAL. An object defining additional properties requested by the Verifier that apply
    /// to the metadata and validity data of the Credential.
    /// </summary>
    [JsonPropertyName("meta")]
    [JsonPropertyOrder(11)]
    public SdJwtVcMeta? Meta { get; init; }
}
