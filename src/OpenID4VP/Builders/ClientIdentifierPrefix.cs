namespace OpenID4VP.Builders;

/// <summary>
/// Defined Client Identifier Prefixes for fluent API construction.
/// 
/// Use these constants with the WithClientId(prefix, value) overload to build client identifiers
/// in a type-safe, self-documenting way. The method will automatically construct the full
/// client identifier by combining the prefix and value with a colon separator (prefix:value).
/// 
/// Note: These are the 6 real prefixes defined in the OpenID4VP specification.
/// Direct HTTPS URLs (without a prefix) can be passed via the WithClientId(string) overload.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5.9.3
/// </summary>
public static class ClientIdentifierPrefix
{
    /// <summary>
    /// Redirect URI based Client Identifier.
    /// 
    /// Format: prefix + ":" + value becomes "redirect_uri:value"
    /// Example: WithClientId(RedirectUri, "https://verifier.example.com/callback")
    ///          → "redirect_uri:https://verifier.example.com/callback"
    /// 
    /// The value is the redirect_uri where the Wallet sends the response.
    /// Uses colon separator between prefix and value.
    /// </summary>
    public const string RedirectUri = "redirect_uri";

    /// <summary>
    /// X.509 DNS Subject Alternative Name.
    /// 
    /// Format: prefix + ":" + value becomes "x509_san_dns:value"
    /// Example: WithClientId(X509SanDns, "client.example.org")
    ///          → "x509_san_dns:client.example.org"
    /// 
    /// The value must match a DNS SAN in the Verifier's X.509 certificate.
    /// Uses colon separator between prefix and value.
    /// </summary>
    public const string X509SanDns = "x509_san_dns";

    /// <summary>
    /// X.509 URI Subject Alternative Name.
    /// 
    /// Format: prefix + ":" + value becomes "x509_san_uri:value"
    /// Example: WithClientId(X509SanUri, "https://example.org")
    ///          → "x509_san_uri:https://example.org"
    /// 
    /// The value must match a URI SAN in the Verifier's X.509 certificate.
    /// Uses colon separator between prefix and value.
    /// </summary>
    public const string X509SanUri = "x509_san_uri";

    /// <summary>
    /// X.509 IP Address Subject Alternative Name.
    /// 
    /// Format: prefix + ":" + value becomes "x509_san_ip_address:value"
    /// Example: WithClientId(X509SanIpAddress, "192.0.2.1")
    ///          → "x509_san_ip_address:192.0.2.1"
    /// 
    /// The value must match an IP Address SAN in the Verifier's X.509 certificate.
    /// Uses colon separator between prefix and value.
    /// </summary>
    public const string X509SanIpAddress = "x509_san_ip_address";

    /// <summary>
    /// Decentralized Identifier (W3C standard).
    /// 
    /// Format: prefix + ":" + value becomes "did:value"
    /// Example: WithClientId(Did, "example:123abc")
    ///          → "did:example:123abc"
    /// 
    /// The value should include the method and method-specific-id as per W3C DID spec.
    /// Uses colon separator between prefix and value.
    /// </summary>
    public const string Did = "did";

    /// <summary>
    /// Uniform Resource Name.
    /// 
    /// Format: prefix + ":" + value becomes "urn:value"
    /// Example: WithClientId(Urn, "verifier:acme:xyz")
    ///          → "urn:verifier:acme:xyz"
    /// 
    /// Used for URN-based identifiers, including legacy and proprietary systems.
    /// Uses colon separator between prefix and value.
    /// </summary>
    public const string Urn = "urn";
}
