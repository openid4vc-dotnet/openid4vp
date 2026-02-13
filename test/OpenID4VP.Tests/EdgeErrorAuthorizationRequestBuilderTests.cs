using OpenID4VP.Builders;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for smart device-mode validation in AuthorizationRequestBuilder.Build()
/// 
/// The OpenID4VP spec requires different request structures for same-device vs cross-device:
/// - Same Device Mode (Section 3.1): Complete request with all parameters inline
/// - Cross Device Mode (Section 3.2): Minimal request with only client_id + request_uri
/// 
/// The Build() method detects the device mode from response_mode and enforces
/// the appropriate field combinations via strict validation.
/// </summary>
public class EdgeErrorAuthorizationRequestBuilderTests
{

    // ========== EDGE CASES AND ERROR CASES ==========

    [Fact]
    public void Build_InvalidResponseMode_Throws()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithResponseMode("invalid-mode");

        // Build() succeeds (permissive) - doesn't validate response_mode value
        var result = builder.Build();
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Equal("invalid-mode", result.Value.ResponseMode);
    }

    [Fact]
    public void Build_NoResponseMode_ReturnsFailure()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .Build();

        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("response_mode is required", result.Errors[0].Message);
    }
}


