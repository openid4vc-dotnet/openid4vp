namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Constants for credential format identifiers as specified in OpenID for Verifiable Presentations 1.0.
/// These values are used as the discriminator in polymorphic JSON serialization.
/// 
/// Specification: OpenID4VP 1.0, Appendix B - DCQL Format Identifiers
/// </summary>
public static class CredentialFormats
{
    /// <summary>
    /// ISO/IEC 18013-5:2021 mobile driving license (mDoc) format.
    /// </summary>
    public const string MsoMdoc = "mso_mdoc";

    /// <summary>
    /// W3C Verifiable Credentials in JWT format.
    /// </summary>
    public const string JwtVcJson = "jwt_vc_json";

    /// <summary>
    /// W3C Verifiable Credentials in JSON-LD with external proof format.
    /// </summary>
    public const string LdpVc = "ldp_vc";

    /// <summary>
    /// SD-JWT VC format as specified in SD-JWT VC specification.
    /// </summary>
    public const string VcSdJwt = "vc+sd-jwt";

    /// <summary>
    /// Digital Credentials SD-JWT format.
    /// </summary>
    public const string DcSdJwt = "dc+sd-jwt";
}

/// <summary>
/// Constants for ISO/IEC 18013-5 (mDoc) credential metadata.
/// </summary>
public static class MdocFormats
{
    /// <summary>
    /// ISO/IEC 18013-5:2021 mobile driving license (mDL) doctype.
    /// </summary>
    public const string MDL = "org.iso.18013.5.1.mDL";

    /// <summary>
    /// ISO/IEC 18013-5:2021 mobile driving license namespace.
    /// </summary>
    public const string DefaultNamespace = "org.iso.18013.5.1";
}
