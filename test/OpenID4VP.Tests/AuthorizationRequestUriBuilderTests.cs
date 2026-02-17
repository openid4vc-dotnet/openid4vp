using OpenID4VP.Builders;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;
using OpenID4VC.Core.Tests;
using Xunit;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for AuthorizationRequestUriBuilder - unified URI generation supporting all three transport options.
/// 
/// Per OpenID4VP Spec Section 5.4:
/// - Option A: Direct URL with all parameters encoded as query string (same-device)
/// - Option B: Request object as JWT value in 'request' parameter (same-device, encrypted/signed)
/// - Option C: Request object by reference via request_uri (cross-device, QR code)
/// </summary>
public class AuthorizationRequestUriBuilderTests
{
    #region Option A: AsDirectUrl

    [Fact]
    public void AsDirectUrl_FullRequest_Succeeds()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz_-~.")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithScope("openid")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsDirectUrl("https://wallet.example.com/auth");

        // Assert
        result.AssertSuccess();
        Assert.NotNull(result.Value);
        Assert.Contains("client_id=verifier-1", result.Value);
        Assert.Contains("nonce=abc123xyz_-~.", result.Value);
        Assert.Contains("response_type=vp_token", result.Value);
        Assert.Contains("response_mode=query", result.Value);
    }

    [Fact]
    public void AsDirectUrl_WithRedirectUri_IncludesRedirectUri()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("openid")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsDirectUrl("https://wallet.example.com/auth");

        // Assert
        result.AssertSuccess();
        Assert.Contains("redirect_uri=https%3A%2F%2Fverifier.example.com%2Fcallback", result.Value!);
    }

    [Fact]
    public void AsDirectUrl_NullBaseUri_ReturnsFailure()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsDirectUrl(null!);

        // Assert
        result.AssertError();
        Assert.Contains(result.Errors, e => e.Message.Contains("Base URI"));
    }

    [Fact]
    public void AsDirectUrl_WithState_IncludesState()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithState("state-value-123")
            .WithScope("openid")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsDirectUrl("https://wallet.example.com/auth");

        // Assert
        result.AssertSuccess();
        Assert.Contains("state=state-value-123", result.Value!);
    }

    [Fact]
    public void AsDirectUrl_DirectPost_IncludesResponseUri()
    {
        // Arrange - direct_post requires response_uri
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithResponseType("vp_token")
            .WithResponseMode("direct_post")
            .WithResponseUri("https://verifier.example.com/response")
            .WithScope("openid")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsDirectUrl("https://wallet.example.com/auth");

        // Assert
        result.AssertSuccess();
        Assert.Contains("response_uri=https%3A%2F%2Fverifier.example.com%2Fresponse", result.Value!);
    }

    #endregion

    #region Option B: AsRequestObjectByValue

    [Fact]
    public void AsRequestObjectByValue_WithValidJwt_Succeeds()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithResponseType("vp_token")
            .Build();

        request.AssertSuccess();

        var jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJ2ZXJpZmllci0xIiwibm9uY2UiOiJhYmMxMjMifQ.signature";

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByValue("https://wallet.example.com/auth", jwt);

        // Assert
        result.AssertSuccess();
        Assert.NotNull(result.Value);
        Assert.Contains($"request={Uri.EscapeDataString(jwt)}", result.Value);
    }

    [Fact]
    public void AsRequestObjectByValue_NullJwt_ReturnsFailure()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithResponseType("vp_token")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByValue("https://wallet.example.com/auth", null!);

        // Assert
        result.AssertError();
        Assert.Contains(result.Errors, e => e.Message.Contains("JWT"));
    }

    [Fact]
    public void AsRequestObjectByValue_EmptyJwt_ReturnsFailure()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithResponseType("vp_token")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByValue("https://wallet.example.com/auth", "");

        // Assert
        result.AssertError();
        Assert.Contains(result.Errors, e => e.Message.Contains("JWT"));
    }

    [Fact]
    public void AsRequestObjectByValue_NullBaseUri_ReturnsFailure()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithResponseType("vp_token")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByValue(null!, "jwt-token");

        // Assert
        result.AssertError();
        Assert.Contains(result.Errors, e => e.Message.Contains("Base URI"));
    }

    #endregion

    #region Option C: AsRequestObjectByReference

    [Fact]
    public void AsRequestObjectByReference_MinimalRequest_Succeeds()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithRequestUri("https://verifier.example.com/request")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference("openid4vp://");

        // Assert
        result.AssertSuccess();
        Assert.NotNull(result.Value);
        Assert.Contains("client_id=verifier-1", result.Value);
        Assert.Contains("request_uri=https%3A%2F%2Fverifier.example.com%2Frequest", result.Value);
        Assert.Contains("nonce=abc123xyz", result.Value);
    }

    [Fact]
    public void AsRequestObjectByReference_WithState_IncludesState()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithRequestUri("https://verifier.example.com/request")
            .WithState("state-123")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference("openid4vp://");

        // Assert
        result.AssertSuccess();
        Assert.Contains("state=state-123", result.Value!);
    }

    [Fact]
    public void AsRequestObjectByReference_WithRequestUriMethod_IncludesMethod()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithRequestUri("https://verifier.example.com/request")
            .WithRequestUriMethod("post")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference("openid4vp://");

        // Assert
        result.AssertSuccess();
        Assert.Contains("request_uri_method=post", result.Value!);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("Post")]
    [InlineData("POST")]
    public void AsRequestObjectByReference_RequestUriMethod_NormalizedToLowercase(string method)
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithRequestUri("https://verifier.example.com/request")
            .WithRequestUriMethod(method)
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference("openid4vp://");

        // Assert
        result.AssertSuccess();
        var expected = method.ToLowerInvariant();
        Assert.Contains($"request_uri_method={expected}", result.Value!);
    }

    [Fact]
    public void AsRequestObjectByReference_NullBaseUri_ReturnsFailure()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithRequestUri("https://verifier.example.com/request")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference(null!);

        // Assert
        result.AssertError();
        Assert.Contains(result.Errors, e => e.Message.Contains("Base URI"));
    }

    #endregion

    #region URI Encoding

    [Fact]
    public void AsDirectUrl_UrlEncodesSpecialCharacters()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier@example.com")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithState("state_value123")  // Only URL-safe characters
            .WithScope("openid")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsDirectUrl("https://wallet.example.com/auth");

        // Assert
        result.AssertSuccess();
        // @ should be encoded as %40
        Assert.Contains("client_id=verifier%40example.com", result.Value!);
    }

    [Fact]
    public void AsRequestObjectByReference_UrlEncodesRequestUri()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123")
            .WithRequestUri("https://verifier.example.com/request?code=abc&state=xyz")
            .Build();

        request.AssertSuccess();

        // Act
        var result = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference("openid4vp://");

        // Assert
        result.AssertSuccess();
        // Query string parameters should be URL encoded
        Assert.Contains("request_uri=https%3A%2F%2F", result.Value!);
    }

    #endregion
}
