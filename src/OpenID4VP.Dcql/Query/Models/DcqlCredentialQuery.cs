using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Base class for all credential query types.
/// A Credential Query is an object representing a request for a presentation of one Credential.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.1
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "format")]
[JsonDerivedType(typeof(MdocCredentialQuery), CredentialFormats.MsoMdoc)]
[JsonDerivedType(typeof(W3cVcCredentialQuery), CredentialFormats.JwtVcJson)]
[JsonDerivedType(typeof(LdpVcCredentialQuery), CredentialFormats.LdpVc)]
[JsonDerivedType(typeof(SdJwtVcCredentialQuery), CredentialFormats.VcSdJwt)]
[JsonDerivedType(typeof(DcSdJwtCredentialQuery), CredentialFormats.DcSdJwt)]
public abstract record DcqlCredentialQuery : IClaimsProvider
{
    /// <summary>
    /// REQUIRED. A string identifying the Credential in the response and, if provided,
    /// the constraints in 'credential_sets'. The value MUST be a non-empty string consisting 
    /// of alphanumeric, underscore (_), or hyphen (-) characters.
    /// </summary>
    [JsonPropertyName("id")]
    [JsonPropertyOrder(1)]
    public required string Id { get; init; }

    /// <summary>
    /// REQUIRED. A string that specifies the format of the requested Verifiable Credential.
    /// This value is automatically determined by the derived type and serves as the discriminator
    /// for polymorphic serialization. It should not be set manually.
    /// </summary>
    [JsonIgnore]
    [JsonPropertyOrder(order: 2)]
    public abstract string Format { get; }

    /// <summary>
    /// OPTIONAL. A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof.
    /// The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required.
    /// If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
    /// </summary>
    [JsonPropertyName("require_cryptographic_holder_binding")]
    public bool RequireCryptographicHolderBinding { get; init; } = true;

    /// <summary>
    /// OPTIONAL. A boolean which indicates whether multiple Credentials can be returned for this Credential Query.
    /// If omitted, the default value is false.
    /// </summary>
    [JsonPropertyName("multiple")]
    public bool Multiple { get; init; } = false;

    /// <summary>
    /// OPTIONAL. A non-empty array containing arrays of identifiers for elements in 'claims' that specifies
    /// which combinations of 'claims' for the Credential are requested.
    /// </summary>
    [JsonPropertyName("claim_sets")]
    public NonEmptyArray<NonEmptyArray<string>>? ClaimSets { get; init; }

    /// <summary>
    /// OPTIONAL. A non-empty array of objects that specifies expected authorities or trust frameworks
    /// that certify Issuers, that the Verifier will accept.
    /// </summary>
    [JsonPropertyName("trusted_authorities")]
    public NonEmptyArray<TrustedAuthority>? TrustedAuthorities { get; init; }

    /// <summary>
    /// Gets the claim IDs defined in this credential query.
    /// Each derived type implements this based on its claims structure.
    /// </summary>
    public abstract IEnumerable<string>? GetClaimIds();

    /// <summary>
    /// Gets the metadata for this credential query as an abstraction.
    /// Derived types implement this to return their specific metadata type.
    /// </summary>
    public abstract ICredentialMeta? GetMetadata();
}
