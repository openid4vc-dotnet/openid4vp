namespace OpenID4VP.Common;

/// <summary>
/// OpenID4VP Response Types as defined in the specification.
/// Specification: OpenID for Verifiable Presentations 1.0, Section 5.6
/// </summary>
public static class ResponseTypes
{
    /// <summary>
    /// Response type for returning VP Token only
    /// </summary>
    public const string VpToken = "vp_token";

    /// <summary>
    /// Response type for returning VP Token with ID Token (when combined with SIOPv2)
    /// </summary>
    public const string VpTokenIdToken = "vp_token id_token";
}
