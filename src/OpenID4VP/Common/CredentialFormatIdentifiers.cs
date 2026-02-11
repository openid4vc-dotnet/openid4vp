namespace OpenID4VP.Common;

/// <summary>
/// Credential Format Identifiers used in OpenID4VP.
/// These are format identifiers commonly referenced in the protocol.
/// Specification: OpenID for Verifiable Presentations 1.0, throughout and Appendix B
/// </summary>
public static class CredentialFormatIdentifiers
{
    /// <summary>
    /// W3C Verifiable Credentials Data Model format (JWT format)
    /// </summary>
    public const string JwtVcJson = "jwt_vc_json";

    /// <summary>
    /// W3C Verifiable Credentials Data Model format (JWT-LD format)
    /// </summary>
    public const string JwtVcJsonLd = "jwt_vc_json-ld";

    /// <summary>
    /// W3C Linked Data Proofs format
    /// </summary>
    public const string LdpVc = "ldp_vc";

    /// <summary>
    /// ISO/IEC 18013-5 Mobile Document format
    /// </summary>
    public const string MsoMdoc = "mso_mdoc";

    /// <summary>
    /// IETF SD-JWT VC format
    /// </summary>
    public const string VcSdJwt = "vc+sd-jwt";

    /// <summary>
    /// IETF DC-SD-JWT format (Selective Disclosure JWT for Credentials)
    /// </summary>
    public const string DcSdJwt = "dc+sd-jwt";
}
