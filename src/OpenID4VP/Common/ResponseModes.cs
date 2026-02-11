namespace OpenID4VP.Common;

/// <summary>
/// OpenID4VP Response Modes as defined in the specification.
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.2-8.3
/// </summary>
public static class ResponseModes
{
    /// <summary>
    /// Response parameters are encoded in the fragment of the redirect URI
    /// </summary>
    public const string Fragment = "fragment";

    /// <summary>
    /// Response parameters are encoded in the query string of the redirect URI
    /// </summary>
    public const string Query = "query";

    /// <summary>
    /// Response parameters are sent as an HTTP POST request to the response_uri
    /// </summary>
    public const string DirectPost = "direct_post";

    /// <summary>
    /// Response parameters are encrypted and sent as an HTTP POST request to the response_uri
    /// </summary>
    public const string DirectPostJwt = "direct_post.jwt";
}
