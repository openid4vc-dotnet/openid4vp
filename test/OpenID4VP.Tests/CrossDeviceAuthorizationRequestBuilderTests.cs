using OpenID4VP.Builders;
using OpenID4VP.Common;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for smart device-mode validation in AuthorizationRequestBuilder.Build()
/// 
/// The OpenID4VP spec requires different request structures for same-device vs cross-device:
/// - Cross Device Mode (Section 3.2): Minimal request with only client_id + request_uri
/// 
/// +--------------+   +--------------+                                    +--------------+
/// |   End-User   |   |   Verifier   |                                    |    Wallet    |
/// |              |   |  (device A)  |                                    |  (device B)  |
/// +--------------+   +--------------+                                    +--------------+
///         |                 |                                                   |
///         |    Interacts    |                                                   |
///         |---------------->|                                                   |
///         |                 |  (1) Authorization Request                        |
///         |                 |      (Request URI)                                |
///         |                 |-------------------------------------------------->|
///         |                 |                                                   |
///         |                 |  (2) Request the Request Object                   |
///         |                 |<--------------------------------------------------|
///         |                 |                                                   |
///         |                 |  (2.5) Respond with the Request Object            |
///         |                 |      (DCQL query)                                 |
///         |                 |-------------------------------------------------->|
///         |                 |                                                   |
///         |   End-User Authentication / Consent                                 |
///         |                 |                                                   |
///         |                 |  (3)   Authorization Response as HTTP POST        |
///         |                 |  (VP Token with Presentation(s))                  |
///         |                 |<--------------------------------------------------|
/// 
/// 
/// The Build() method detects the device mode from response_mode and enforces
/// the appropriate field combinations via strict validation.
/// </summary>
public class CrossDeviceAuthorizationRequestBuilderTests
{
    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithOnlyRequiredFields_Succeeds(string responseMode)
    {
        // Cross-device: Only client_id and request_uri required
        // NO response_type, nonce, dcql_query allowed!
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode)
            .Build();

        Assert.NotNull(request);
        Assert.Equal("verifier-1", request.ClientId);
        // The request object will have placeholder values for other fields
        // because AuthorizationRequest requires them, but they should come from RequestObject
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_MissingClientId_Throws(string responseMode)
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode);

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("client_id is REQUIRED", ex.Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_MissingRequestUri_Throws(string responseMode)
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithResponseMode(responseMode);
            // Note: NOT setting request_uri

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("request_uri is REQUIRED for cross-device mode", ex.Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithResponseType_Throws(string responseMode)
    {
        // response_type FORBIDDEN in minimal cross-device request
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)  // FORBIDDEN!
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode);

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("response_type MUST NOT be set in cross-device mode", ex.Message);
        Assert.Contains("RequestObject", ex.Message);  // Guidance
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithNonce_Throws(string responseMode)
    {
        // nonce FORBIDDEN in minimal cross-device request
        var builder = AuthorizationRequestBuilder.Create()
            .WithNonce("nonce-123")  // FORBIDDEN!
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode);

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("nonce MUST NOT be set in cross-device mode", ex.Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithDcql_Throws(string responseMode)
    {
        // dcql_query FORBIDDEN in minimal cross-device request
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode)
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")));  // FORBIDDEN!

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("dcql_query MUST NOT be set in cross-device mode", ex.Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithRedirectUri_Throws(string responseMode)
    {
        // redirect_uri FORBIDDEN in cross-device
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback");  // FORBIDDEN!

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("redirect_uri MUST NOT be set in cross-device mode", ex.Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithState_Succeeds(string responseMode)
    {
        // state is optional in cross-device
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode)
            .WithState("state-456")
            .Build();

        Assert.NotNull(request);
        Assert.Equal("state-456", request.State);
    }
}


