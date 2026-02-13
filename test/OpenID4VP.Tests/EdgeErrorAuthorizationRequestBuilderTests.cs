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
            .WithResponseMode("invalid-mode");

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Invalid response_mode", ex.Message);
        Assert.Contains("fragment", ex.Message);  // Shows valid options
        Assert.Contains("direct_post", ex.Message);
    }

    [Fact]
    public void Build_NoResponseMode_Throws()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1");

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Response mode is required", ex.Message);
    }
}


