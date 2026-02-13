using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Validators;

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
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("verifier-1")
            .WithNonce("nonce-123")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            .Build();

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
    public void Build_SameDevice_MissingResponseType_Throws(string responseMode)
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("nonce-123")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)));

        // Build() succeeds (permissive) - uses default response_type
        var request = builder.Build();
        Assert.NotNull(request);

        // But the validator should fail for same-device mode
        var validator = new SameDeviceAuthorizationRequestValidator();
        var result = validator.Validate(request);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("response_type is REQUIRED for same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_MissingNonce_Throws(string responseMode)
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("verifier-1")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)));

        // Build() succeeds (permissive) - uses default nonce
        var request = builder.Build();
        Assert.NotNull(request);

        // But the validator should fail for same-device mode
        var validator = new SameDeviceAuthorizationRequestValidator();
        var result = validator.Validate(request);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("nonce is REQUIRED for same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_MissingRedirectUri_Throws(string responseMode)
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("verifier-1")
            .WithNonce("nonce-123")
            .WithResponseMode(responseMode)
            // Note: NOT setting redirect_uri
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)));

        // Build() succeeds (permissive)
        var request = builder.Build();
        Assert.NotNull(request);

        // But the validator should fail for same-device mode
        var validator = new SameDeviceAuthorizationRequestValidator();
        var result = validator.Validate(request);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("redirect_uri is REQUIRED for same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_WithRequestUri_Succeeds_ButValidatorFails(string responseMode)
    {
        // request_uri is FORBIDDEN in same-device mode (only in cross-device)
        // Build() is permissive and allows it, but the validator should catch it
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("verifier-1")
            .WithNonce("nonce-123")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithRequestUri("https://verifier.example.com/request")  // FORBIDDEN for same-device!
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build() succeeds (permissive)
        Assert.NotNull(request);
        Assert.Equal("https://verifier.example.com/request", request.RequestUri);

        // But the validator should fail for same-device mode
        var validator = new SameDeviceAuthorizationRequestValidator();
        var result = validator.Validate(request);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.StartsWith("request_uri MUST NOT be set in same-device mode"));
    }

    [Theory]
    [InlineData(ResponseModes.Fragment)]
    [InlineData(ResponseModes.Query)]
    public void Build_SameDevice_WithDcql_Required_Succeeds(string responseMode)
    {
        // dcql_query is REQUIRED for same-device
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("verifier-1")
            .WithNonce("nonce-123")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("cred-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.NotNull(request.DcqlQuery);
    }
}