using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Validators;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// The OpenID4VP spec requires different request structures for same-device vs cross-device:
/// - Same Device Mode (Section 3.1): Complete request with all parameters inline
/// 
/// +--------------+   +--------------+                                    +--------------+
/// |   End-User   |   |   Verifier   |                                    |    Wallet    |
/// +--------------+   +--------------+                                    +--------------+
///         |                 |                                                   |
///         |    Interacts    |                                                   |
///         |---------------->|                                                   |
///         |                 |  (1) Authorization Request                        |
///         |                 |  (DCQL query)                                     |
///         |                 |-------------------------------------------------->|
///         |                 |                                                   |
///         |                 |                                                   |
///         |   End-User Authentication / Consent                                 |
///         |                 |                                                   |
///         |                 |  (2)   Authorization Response                     |
///         |                 |  (VP Token with Presentation(s))                  |
///         |                 |<--------------------------------------------------|
/// 
/// 
/// 
/// </summary>
public class SameDeviceAuthorizationRequestBuilderTests
{
    private static void ConfigureValidW3cCredential(W3cVcCredentialQueryBuilder builder)
    {
        builder.AddTypeValues("UniversityDegree");
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_WithAllRequiredFields_Succeeds(string responseMode)
    {
        // Same-device: Must have response_type, nonce, redirect_uri, and dcql_query
        var result = SameDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request);
        Assert.Equal(ResponseTypes.VpToken, request.ResponseType);
        Assert.Equal("verifier-1", request.ClientId);
        Assert.Equal("nonce-123", request.Nonce);
        Assert.Equal(responseMode, request.ResponseMode);
        Assert.Equal("https://verifier.example.com/callback", request.RedirectUri);
        Assert.NotNull(request.DcqlQuery);
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_MissingResponseType_ReturnsFailure(string responseMode)
    {
        var result = SameDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("response_type is REQUIRED and must be 'vp_token' for same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_MissingNonce_ReturnsFailure(string responseMode)
    {
        var result = SameDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("nonce is REQUIRED for same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_MissingRedirectUri_ReturnsFailure(string responseMode)
    {
        var result = SameDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(responseMode)
                // Note: NOT setting redirect_uri
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("redirect_uri is REQUIRED for same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_WithRequestUri_ReturnsFailure(string responseMode)
    {
        // request_uri is FORBIDDEN in same-device mode (only in cross-device)
        var result = SameDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")
                .WithRequestUri("https://verifier.example.com/request")  // FORBIDDEN for same-device!
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("request_uri MUST NOT be set in same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_WithDcql_Required_Succeeds(string responseMode)
    {
        // dcql_query is REQUIRED for same-device
        var result = SameDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseType(ResponseTypes.VpToken)
                .WithClientId("verifier-1")
                .WithNonce("nonce-123")
                .WithResponseMode(responseMode)
                .WithRedirectUri("https://verifier.example.com/callback")
                .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
        );

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.NotNull(result.Value.DcqlQuery);
    }
}