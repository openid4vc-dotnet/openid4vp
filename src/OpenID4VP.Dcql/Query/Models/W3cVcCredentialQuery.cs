using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Credential Query for W3C Verifiable Credentials (jwt_vc_json, ldp_vc).
/// Specification: OpenID for Verifiable Presentations 1.0, Appendix B.1
/// </summary>
public sealed record W3cVcCredentialQuery : DcqlCredentialQuery
{
    [JsonConstructor]
    internal W3cVcCredentialQuery() { }

    [JsonIgnore]
    public override string Format => CredentialFormats.JwtVcJson;

    public override IEnumerable<string>? GetClaimIds() => 
        Claims?.Where(c => c.Id != null).Select(c => c.Id!);

    public override ICredentialMeta? GetMetadata() => Meta;

    /// <summary>
    /// OPTIONAL. A non-empty array of objects that specifies claims in the requested Credential.
    /// </summary>
    [JsonPropertyName("claims")]
    public NonEmptyArray<JsonClaimQuery>? Claims { get; init; }

    /// <summary>
    /// REQUIRED. An object defining additional properties requested by the Verifier that apply
    /// to the metadata and validity data of the Credential.
    /// </summary>
    [JsonPropertyName("meta")]
    public required W3cVcMeta Meta { get; init; }
}
