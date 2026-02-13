using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Validators;
using OpenID4VC.Core.Results;

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
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("verifier-1")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
        );

        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request);
        Assert.Equal("verifier-1", request.ClientId);
        // The request object will have placeholder values for other fields
        // because AuthorizationRequest requires them, but they should come from RequestObject
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_MissingClientId_ReturnsFailure(string responseMode)
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(responseMode)
            .Build();

        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("client_id is required", result.Errors[0].Message);
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_MissingRequestUri_ReturnsFailure(string responseMode)
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("verifier-1")
                .WithResponseMode(responseMode)
                // Note: NOT setting request_uri
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("request_uri is REQUIRED for cross-device mode"));
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
                .WithClientId("verifier-1")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("response_type MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithNonce_ReturnsFailure(string responseMode)
    {
        // nonce FORBIDDEN in minimal cross-device request
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithNonce("nonce-123")  // FORBIDDEN!
                .WithClientId("verifier-1")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("nonce MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithDcql_ReturnsFailure(string responseMode)
    {
        // dcql_query FORBIDDEN in minimal cross-device request
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("verifier-1")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => b.AddTypeValues("UniversityDegree")))  // FORBIDDEN!
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("dcql_query MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithRedirectUri_ReturnsFailure(string responseMode)
    {
        // redirect_uri FORBIDDEN in cross-device
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("verifier-1")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")  // FORBIDDEN!
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("redirect_uri MUST NOT be set in cross-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.DirectPost)]
    [InlineData(ResponseModes.DirectPostJwt)]
    public void Build_CrossDevice_WithState_Succeeds(string responseMode)
    {
        // state is optional in cross-device
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("verifier-1")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(responseMode)
                .WithState("state-456")
        );

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Equal("state-456", result.Value.State);
    }
}


