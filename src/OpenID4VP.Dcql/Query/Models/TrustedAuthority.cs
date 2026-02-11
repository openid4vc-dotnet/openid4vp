using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Specifies trusted authorities within a requested Credential.
/// A Trusted Authorities Query is an object representing information that helps to identify
/// an authority or the trust framework that certifies Issuers.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.1.1
/// </summary>
[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(AuthorityKeyIdentifierTrustAuthority), "aki")]
[JsonDerivedType(typeof(EtsiTrustedListAuthority), "etsi_tl")]
[JsonDerivedType(typeof(OpenIdFederationAuthority), "openid_federation")]
public abstract record TrustedAuthority
{
    /// <summary>
    /// REQUIRED. A string uniquely identifying the type of information about the issuer trust framework.
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    /// <summary>
    /// REQUIRED. A non-empty array of strings, where each string (value) contains information specific
    /// to the used Trusted Authorities Query type that allows to identify an issuer, trust framework,
    /// or a federation that an issuer belongs to.
    /// </summary>
    [JsonPropertyName("values")]
    public required virtual NonEmptyArray<string> Values { get; init; }
}

/// <summary>
/// Authority Key Identifier (AKI) trust authority.
/// Type: "aki"
/// 
/// Value: Contains the KeyIdentifier of the AuthorityKeyIdentifier as defined in Section 4.2.1.1
/// of RFC5280, encoded as base64url. The raw byte representation of this element MUST match with
/// the AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain present in
/// the Credential.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.1.1.1
/// </summary>
public sealed record AuthorityKeyIdentifierTrustAuthority : TrustedAuthority
{
    public AuthorityKeyIdentifierTrustAuthority()
    {
        Type = "aki";
    }

    public override required NonEmptyArray<string> Values
    {
        get => base.Values;
        init
        {
            // Validate base64url encoding
            foreach (var val in value)
            {
                if (!ValidationPatterns.IsValidBase64Url(val))
                {
                    throw new ArgumentException($"AKI value must be valid base64url: {val}", nameof(value));
                }
            }
            base.Values = value;
        }
    }
}

/// <summary>
/// ETSI Trusted List authority.
/// Type: "etsi_tl"
/// 
/// Value: The identifier of a Trusted List as specified in ETSI TS 119 612. An ETSI Trusted List
/// contains references to other Trusted Lists, creating a list of trusted lists, or entries for
/// Trust Service Providers with corresponding service description and X.509 Certificates.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.1.1.2
/// </summary>
public sealed record EtsiTrustedListAuthority : TrustedAuthority
{
    public EtsiTrustedListAuthority()
    {
        Type = "etsi_tl";
    }

    public override required NonEmptyArray<string> Values
    {
        get => base.Values;
        init
        {
            // Validate URLs
            foreach (var val in value)
            {
                if (!Uri.TryCreate(val, UriKind.Absolute, out var uri) ||
                    (uri.Scheme != "http" && uri.Scheme != "https"))
                {
                    throw new ArgumentException($"ETSI TL value must be a valid HTTP/HTTPS URL: {val}", nameof(value));
                }
            }
            base.Values = value;
        }
    }
}

/// <summary>
/// OpenID Federation authority.
/// Type: "openid_federation"
/// 
/// Value: The Entity Identifier as defined in Section 1 of OpenID.Federation that is bound to an
/// entity in a federation. While this Entity Identifier could be any entity in that ecosystem,
/// this entity would usually have the Entity Configuration of a Trust Anchor.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.1.1.3
/// </summary>
public sealed record OpenIdFederationAuthority : TrustedAuthority
{
    public OpenIdFederationAuthority()
    {
        Type = "openid_federation";
    }

    public override required NonEmptyArray<string> Values
    {
        get => base.Values;
        init
        {
            // Validate URLs
            foreach (var val in value)
            {
                if (!Uri.TryCreate(val, UriKind.Absolute, out var uri) ||
                    (uri.Scheme != "http" && uri.Scheme != "https"))
                {
                    throw new ArgumentException($"OpenID Federation value must be a valid HTTP/HTTPS URL: {val}", nameof(value));
                }
            }
            base.Values = value;
        }
    }
}
