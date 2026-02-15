using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VC.Core.Tests;

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
        // Cross-device mode: client_id + request_uri + nonce (all REQUIRED per spec)
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-value")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
        );

        // Should SUCCEED - all required fields are present
        var request = result.AssertSuccess();
        Assert.NotNull(request);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_MissingClientId_ReturnsFailure(string responseMode)
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithNonce("test-nonce")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode)
            .Build();

        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("client_id is required", errors[0].Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_MissingRequestUri_ReturnsFailure(string responseMode)
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithResponseMode(responseMode)
                // Note: NOT setting request_uri
        );

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("request_uri is REQUIRED for cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithResponseType_ReturnsFailure(string responseMode)
    {
        // response_type FORBIDDEN in minimal cross-device request
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)  // FORBIDDEN!
                .WithClientId("https://verifier.example.com")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
        );

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("response_type MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithDcql_ReturnsFailure(string responseMode)
    {
        // dcql_query FORBIDDEN in minimal cross-device request
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-value")  // REQUIRED
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")))  // FORBIDDEN!
        );

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("dcql_query MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithRedirectUri_ReturnsFailure(string responseMode)
    {
        // redirect_uri FORBIDDEN in cross-device
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-value")  // REQUIRED
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")  // FORBIDDEN!
        );

        var errors = result.AssertError();
        Assert.Contains(errors, e => e.Message.Contains("redirect_uri MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithState_Succeeds(string responseMode)
    {
        // state is optional in cross-device, along with nonce which is required per spec
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-value")  // REQUIRED per spec
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
                .WithState("state-456")
        );

        // Should SUCCEED - all required fields are present
        var request = result.AssertSuccess();
        Assert.NotNull(request);
    }
}


