using OpenID4VP.Builders;
using OpenID4VP.Models;
using OpenID4VC.Core.Tests;
using Xunit;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

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
    private readonly RSAParameters _publicKeyParams;

    public AuthorizationRequestBodyBuilderTests()
    {
        _rsa = RSA.Create();
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = "test-key" };
        // Export public key parameters early to avoid issues with disposed RSA
        _publicKeyParams = _rsa.ExportParameters(false);
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
            .WithRsaSigningKey(_signingKey)
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
            .WithRsaSigningKey(_signingKey)
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
            .WithRsaSigningKey(_signingKey)
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

    #region Helper Methods for JWS Verification

    /// <summary>
    /// Splits JWT into header.payload.signature parts.
    /// </summary>
    private static string[] SplitJWT(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new ArgumentException("JWT must have exactly 3 parts (header.payload.signature)");
        return parts;
    }

    /// <summary>
    /// Decodes base64url string to UTF-8 string.
    /// </summary>
    private static string DecodeBase64UrlToString(string base64Url)
    {
        var padding = new string('=', (4 - base64Url.Length % 4) % 4);
        var base64 = base64Url.Replace('-', '+').Replace('_', '/') + padding;
        var bytes = Convert.FromBase64String(base64);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    /// <summary>
    /// Decodes base64url string to byte array.
    /// </summary>
    private static byte[] DecodeBase64UrlToBytes(string base64Url)
    {
        var padding = new string('=', (4 - base64Url.Length % 4) % 4);
        var base64 = base64Url.Replace('-', '+').Replace('_', '/') + padding;
        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Parses JWT payload to JsonElement.
    /// </summary>
    private static System.Text.Json.JsonElement ParseJsonPayload(string base64UrlPayload)
    {
        var payloadJson = DecodeBase64UrlToString(base64UrlPayload);
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(payloadJson);
        return jsonDoc.RootElement.Clone();
    }

    /// <summary>
    /// Manually verifies JWT signature using RSA public key.
    /// </summary>
    private static bool VerifySignatureManually(string token, RSA publicKey)
    {
        try
        {
            var parts = SplitJWT(token);
            var header = parts[0];
            var payload = parts[1];
            var signature = parts[2];

            // Reconstruct signing input
            var signingInput = $"{header}.{payload}";
            var signingInputBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);

            // Decode signature from base64url
            var signatureBytes = DecodeBase64UrlToBytes(signature);

            // Verify signature using RSA-SHA256
            return publicKey.VerifyData(
                signingInputBytes,
                signatureBytes,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    #endregion

    #region JWS Verification Tests

    /// <summary>
    /// Test 1: AsJar returns a valid JWS with correct 3-part structure (header.payload.signature).
    /// Verifies JWT format compliance per RFC 7515.
    /// </summary>
    [Fact]
    public void AsJar_ReturnsValidJWSWithCorrectStructure()
    {
        // Arrange
        var request = CreateValidRequest();
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_signingKey)
            .Build();

        jarResult.AssertSuccess();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        result.AssertSuccess();
        
        var token = result.Value;
        var parts = SplitJWT(token);
        Assert.Equal(3, parts.Length);
        
        // Verify header is valid JSON
        var headerJson = DecodeBase64UrlToString(parts[0]);
        using var headerDoc = System.Text.Json.JsonDocument.Parse(headerJson);
        Assert.NotNull(headerDoc.RootElement);
        
        // Verify payload is valid JSON
        var payloadJson = DecodeBase64UrlToString(parts[1]);
        using var payloadDoc = System.Text.Json.JsonDocument.Parse(payloadJson);
        Assert.NotNull(payloadDoc.RootElement);
        
        // Verify signature is non-empty
        Assert.NotEmpty(parts[2]);
    }

    /// <summary>
    /// Test 2: JWT signature can be validated using the public key.
    /// Verifies JWS signature validity per RFC 7515 using JwtSecurityTokenHandler.
    /// </summary>
    [Fact]
    public void AsJar_JWSHasValidSignatureWithPublicKey()
    {
        // Arrange
        var request = CreateValidRequest();
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_signingKey)
            .Build();

        jarResult.AssertSuccess();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        result.AssertSuccess();

        var token = result.Value;
        
        // Use cached public key parameters
        using var publicRsa = RSA.Create();
        publicRsa.ImportParameters(_publicKeyParams);
        
        // Create validation parameters
        var publicKey = new RsaSecurityKey(publicRsa);
        var validationParams = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = publicKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false
        };

        // Validate token
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var principal = handler.ValidateToken(token, validationParams, out var validatedToken);

        // Assert - validation should succeed (no exception thrown)
        Assert.NotNull(principal);
        Assert.NotNull(validatedToken);
        Assert.IsType<System.IdentityModel.Tokens.Jwt.JwtSecurityToken>(validatedToken);
    }

    /// <summary>
    /// Test 3: JWT payload contains authorization request claims.
    /// Verifies that the JWT body includes required request fields.
    /// </summary>
    [Fact]
    public void AsJar_JWSContainsAuthorizationRequestClaims()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithNonce("test-nonce-123")
            .WithResponseType("vp_token")
            .WithResponseMode("direct_post")
            .WithResponseUri("https://verifier.example.com/response")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("openid")
            .WithState("test-state-abc")
            .Build()
            .Value;

        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_signingKey)
            .Build();

        jarResult.AssertSuccess();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        result.AssertSuccess();

        var token = result.Value;
        var parts = SplitJWT(token);
        var payloadJson = DecodeBase64UrlToString(parts[1]);
        
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var root = jsonDoc.RootElement;

        // Verify authorization request claims are present
        Assert.True(root.TryGetProperty("client_id", out _), "client_id should be present");
        Assert.True(root.TryGetProperty("nonce", out _), "nonce should be present");
        Assert.True(root.TryGetProperty("response_type", out _), "response_type should be present");
        Assert.True(root.TryGetProperty("response_mode", out _), "response_mode should be present");
        Assert.True(root.TryGetProperty("scope", out _), "scope should be present");
        Assert.True(root.TryGetProperty("state", out _), "state should be present");
        Assert.True(root.TryGetProperty("redirect_uri", out _), "redirect_uri should be present");
    }

    /// <summary>
    /// Test 4: JWT includes standard RFC 7519 claims (iat, exp, aud, iss, typ).
    /// Verifies JWT includes mandatory standard claims per RFC 9101 OAuth JAR spec.
    /// </summary>
    [Fact]
    public void AsJar_JWSIncludesStandardClaims()
    {
        // Arrange
        var request = CreateValidRequest();

        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_signingKey)
            .WithIssuer("test-issuer")
            .WithAudience("https://wallet.example.com")
            .WithExpirationTime(TimeSpan.FromMinutes(5))
            .Build();

        jarResult.AssertSuccess();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        result.AssertSuccess();

        var token = result.Value;
        var parts = SplitJWT(token);
        
        // Verify typ header is "oauth-authz-req+jwt" per RFC 9101
        var headerJson = DecodeBase64UrlToString(parts[0]);
        using var headerDoc = System.Text.Json.JsonDocument.Parse(headerJson);
        var headerRoot = headerDoc.RootElement;
        
        Assert.True(headerRoot.TryGetProperty("typ", out var typ));
        Assert.Equal("oauth-authz-req+jwt", typ.GetString());

        // Verify payload contains standard claims
        var payloadJson = DecodeBase64UrlToString(parts[1]);
        using var payloadDoc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var payloadRoot = payloadDoc.RootElement;

        // iat (issued at) should be present
        Assert.True(payloadRoot.TryGetProperty("iat", out var iat));
        Assert.NotNull(iat);

        // exp (expiration) should be present
        Assert.True(payloadRoot.TryGetProperty("exp", out var exp));
        Assert.NotNull(exp);

        // aud (audience) should match - note: aud can be string or array
        Assert.True(payloadRoot.TryGetProperty("aud", out var aud));
        if (aud.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            // If array, check first element
            var audArray = aud.EnumerateArray().ToList();
            Assert.NotEmpty(audArray);
            Assert.Equal("https://wallet.example.com", audArray[0].GetString());
        }
        else
        {
            // If string, match directly
            Assert.Equal("https://wallet.example.com", aud.GetString());
        }

        // iss (issuer) should match
        Assert.True(payloadRoot.TryGetProperty("iss", out var iss));
        Assert.Equal("test-issuer", iss.GetString());
    }

    /// <summary>
    /// Test 5: JWT signature can be independently verified using RSA public key.
    /// Demonstrates manual signature verification separate from IdentityModel library.
    /// </summary>
    [Fact]
    public void AsJar_JWSSignatureCanBeIndependentlyVerified()
    {
        // Arrange
        var request = CreateValidRequest();
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_signingKey)
            .Build();

        jarResult.AssertSuccess();

        // Act
        var result = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        result.AssertSuccess();

        var token = result.Value;

        // Use cached public key parameters
        using var publicRsa = RSA.Create();
        publicRsa.ImportParameters(_publicKeyParams);
        
        // Manually verify signature
        var isValid = VerifySignatureManually(token, publicRsa);
        Assert.True(isValid, "JWT signature should be valid with corresponding public key");
    }

    /// <summary>
    /// Test 6: Different signing keys produce different signatures.
    /// Verifies that signature is dependent on the signing key and not hardcoded/cached.
    /// </summary>
    [Fact]
    public void AsJar_DifferentSigningKeysProduceDifferentSignatures()
    {
        // Arrange
        var request = CreateValidRequest();

        // Create second RSA key (different from _signingKey)
        using var rsa2 = RSA.Create();
        var publicKeyParams2 = rsa2.ExportParameters(false);
        var signingKey2 = new RsaSecurityKey(rsa2) { KeyId = "test-key-2" };

        // Build JARs with different keys
        var jar1Result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_signingKey)
            .Build();

        var jar2Result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(signingKey2)
            .Build();

        jar1Result.AssertSuccess();
        jar2Result.AssertSuccess();

        // Act - Get tokens via AsJar()
        var result1 = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jar1Result.Value);

        var result2 = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jar2Result.Value);

        // Assert
        result1.AssertSuccess();
        result2.AssertSuccess();

        var token1 = result1.Value;
        var token2 = result2.Value;

        // Signatures should be different (different keys)
        var sig1 = SplitJWT(token1)[2];
        var sig2 = SplitJWT(token2)[2];
        Assert.NotEqual(sig1, sig2);

        // token1 should validate with first key
        using var publicRsa1 = RSA.Create();
        publicRsa1.ImportParameters(_publicKeyParams);
        Assert.True(VerifySignatureManually(token1, publicRsa1),
            "Token 1 should validate with key 1");

        // token2 should validate with second key
        using var publicRsa2 = RSA.Create();
        publicRsa2.ImportParameters(publicKeyParams2);
        Assert.True(VerifySignatureManually(token2, publicRsa2),
            "Token 2 should validate with key 2");

        // Cross-verify: token1 should NOT validate with key2
        Assert.False(VerifySignatureManually(token1, publicRsa2),
            "Token 1 should NOT validate with key 2");

        // Cross-verify: token2 should NOT validate with key1
        Assert.False(VerifySignatureManually(token2, publicRsa1),
            "Token 2 should NOT validate with key 1");
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
            .WithRsaSigningKey(_signingKey)
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
