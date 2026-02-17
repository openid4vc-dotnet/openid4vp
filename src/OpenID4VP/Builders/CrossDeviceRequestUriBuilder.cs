namespace OpenID4VP.Builders;

/// <summary>
/// Static factory for creating cross-device request URIs.
/// 
/// Cross-device mode generates minimal request URIs (containing only client_id + request_uri + nonce + state)
/// suitable for QR code encoding. The minimal request points to a request_uri endpoint where the full
/// authorization request (with response_mode, response_type, dcql_query, etc.) is fetched.
/// 
/// Per OpenID4VP Spec Section 3.2:
/// The cross-device flow is used when the wallet is on a different device than the verifier.
/// The minimal request is encoded in a QR code, scanned by the wallet, and resolves to the request_uri.
/// 
/// Ref 5.4 Examples 3) Passing a request object by reference
/// 
/// Usage:
/// <code>
/// var result = CrossDeviceRequestUriBuilder.Create()
///     .WithClientId("verifier-1")
///     .WithRequestUri("https://verifier.example.com/request-object")
///     .WithNonce("cryptographically-random-value")
///     .WithParameter("custom", "value")  // optional extensibility
///     .Build("openid4vp://");
/// 
/// if (result.IsSuccess)
/// {
///     var qrCodeUri = result.Value;
///     GenerateQrCode(qrCodeUri);
/// }
/// else
/// {
///     foreach (var error in result.Errors)
///         Log.Error(error.Message);
/// }
/// </code>
/// </summary>
public static class CrossDeviceRequestUriBuilder
{
    /// <summary>
    /// Creates a new cross-device request URI builder.
    /// </summary>
    /// <returns>A fluent builder context for configuring parameters</returns>
    public static CrossDeviceRequestUriBuilderContext Create()
    {
        return new CrossDeviceRequestUriBuilderContext();
    }
}
