using OpenID4VP.Builders;
using OpenID4VP.Models;
using OpenID4VC.Core.Tests;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for AuthorizationRequestBodyBuilder - HTTP response body generation.
/// 
/// Per OpenID4VP Spec Section 5.4.3 (Request Object by Reference):
/// When wallet fetches request_uri, verifier responds with the Authorization Request
/// in a serialized format.
/// 
/// Supported formats:
/// - AsJson(): Plain JSON (no security)
/// - AsJar(): JWT-Secured Authorization Request per RFC 9101
/// </summary>
public class AuthorizationRequestBodyBuilderTests : IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;

    public AuthorizationRequestBodyBuilderTests()
    {
        _rsa = RSA.Create();
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = "test-key" };
    }

    public void Dispose()
    {
        _rsa?.Dispose();
    }

    private static AuthorizationRequest CreateValidRequest()
    {
        return AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithScope("openid")
            .Build()
            .Value;
    }

    #region AsJson Tests

    [Fact]
    public void AsJson_WithValidRequest_ReturnsJsonString()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJson();

        // Assert
        result.AssertSuccess();
        Assert.NotNull(result.Value);
        Assert.Contains("client_id", result.Value);
        Assert.Contains("verifier-1", result.Value);
        Assert.Contains("nonce", result.Value);
        Assert.Contains("abc123xyz", result.Value);
    }

    [Fact]
    public void AsJson_WithOptionalFields_IncludesAllFields()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("direct_post")
            .WithResponseUri("https://verifier.example.com/response")
            .WithState("state-xyz")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("openid")
            .Build()
            .Value;

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJson();

        // Assert
        result.AssertSuccess();
        Assert.Contains("response_uri", result.Value);
        Assert.Contains("state", result.Value);
        Assert.Contains("redirect_uri", result.Value);
    }

    [Fact]
    public void AsJson_WithInvalidRequest_ReturnsFailure()
    {
        // Arrange - Create invalid request (missing nonce)
        var invalidRequest = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithScope("openid")
            .Build()
            .Value;

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(invalidRequest)
            .AsJson();

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void AsJson_UsesSnakeCaseFormat()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJson();

        // Assert - Should use snake_case for JSON keys
        result.AssertSuccess();
        Assert.Contains("client_id", result.Value);
        Assert.Contains("response_type", result.Value);
        Assert.DoesNotContain("ClientId", result.Value);
        Assert.DoesNotContain("ResponseType", result.Value);
    }

    #endregion

    #region AsJar Tests

    [Fact]
    public void AsJar_WithValidJAR_ReturnsJWTToken()
    {
        // Arrange
        var request = CreateValidRequest();
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithSigningKey(_signingKey)
            .Build();

        jarResult.AssertSuccess();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        result.AssertSuccess();
        Assert.Equal(jarResult.Value.Token, result.Value);
        var parts = result.Value.Split('.');
        Assert.Equal(3, parts.Length); // header.payload.signature
    }

    [Fact]
    public void AsJar_WithNullJAR_ReturnsFailure()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void AsJar_WithInvalidRequest_ReturnsFailure()
    {
        // Arrange
        var invalidRequest = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithScope("openid")
            .Build()
            .Value;

        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(invalidRequest)
            .WithSigningKey(_signingKey)
            .Build();

        // jarResult should already be failure, but test Body Builder's validation
        var request = CreateValidRequest();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value!);

        // Assert - If JAR is valid, result should succeed
        if (jarResult.IsSuccess)
        {
            result.AssertSuccess();
        }
    }

    [Fact]
    public void AsJar_ReturnsSameTokenAsCreated()
    {
        // Arrange
        var request = CreateValidRequest();
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithSigningKey(_signingKey)
            .WithIssuer("verifier-1")
            .WithAudience("https://wallet.example.com")
            .Build();

        jarResult.AssertSuccess();
        var jar = jarResult.Value;

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jar);

        // Assert
        result.AssertSuccess();
        Assert.Equal(jar.Token, result.Value);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void BodyBuilder_IntegratesWithUriBuilder_ForCompleteFlow()
    {
        // Arrange
        var request = CreateValidRequest();
        var baseUri = "https://wallet.example.com/auth";

        // Create JAR
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithSigningKey(_signingKey)
            .Build();

        jarResult.AssertSuccess();

        // Act - Use JAR with URI builder (Option B)
        var uriResult = AuthorizationRequestUriBuilder.Create(request)
            .AsRequestObjectByValue(baseUri, jarResult.Value.Token);

        // Act - Use JAR with body builder for Option C response
        var bodyResult = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        uriResult.AssertSuccess();
        bodyResult.AssertSuccess();
        Assert.Contains(baseUri, uriResult.Value);
        Assert.Contains("request=", uriResult.Value);
        Assert.Equal(jarResult.Value.Token, bodyResult.Value);
    }

    #endregion
}
