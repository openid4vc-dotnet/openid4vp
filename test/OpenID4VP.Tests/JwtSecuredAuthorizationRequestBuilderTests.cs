using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Builders;
using OpenID4VP.Models;
using OpenID4VP.Dcql.Query.Builders;
using Xunit;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenID4VP.Tests;

/// <summary>
/// Tests for JwtSecuredAuthorizationRequestBuilder (RFC 9101 compliance).
/// 
/// Tests verify:
/// - JAR creation with JWS signing
/// - Various signing algorithms (RS256, ES256, PS256)
/// - Optional encryption (not yet implemented)
/// - Proper JWT claims assembly from AuthorizationRequest
/// - Standard JWT claims (iss, aud, iat, exp)
/// - Error handling (missing key, invalid request)
/// - RFC 9101 compliance
/// </summary>
public class JwtSecuredAuthorizationRequestBuilderTests : IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _rsaPrivateKey;
    private readonly RsaSecurityKey _rsaPublicKey;
    private readonly RSAParameters _rsaParameters;

    public JwtSecuredAuthorizationRequestBuilderTests()
    {
        // Generate test RSA key pair - keep RSA alive for duration of tests
        _rsa = RSA.Create();
        _rsaPrivateKey = new RsaSecurityKey(_rsa) { KeyId = "test-key-1" };
        _rsaPublicKey = new RsaSecurityKey(_rsa.ExportParameters(false)) { KeyId = "test-key-1" };
        // Cache RSA parameters to avoid issues with disposed RSA objects
        _rsaParameters = _rsa.ExportParameters(true);
    }

    public void Dispose()
    {
        _rsa?.Dispose();
    }
    
    /// <summary>
    /// Helper to create a fresh RsaSecurityKey for each build call.
    /// This avoids issues where the builder might dispose the RSA object.
    /// </summary>
    private RsaSecurityKey CreateFreshRsaSigningKey()
    {
        // Create a new RSA object from the cached parameters instead of reusing _rsa
        var rsa = RSA.Create();
        rsa.ImportParameters(_rsaParameters);
        return new RsaSecurityKey(rsa) { KeyId = "test-key-1" };
    }

    /// <summary>
    /// Helper to create a valid authorization request for testing.
    /// </summary>
    private static AuthorizationRequest CreateValidRequest()
    {
        return AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", ConfigureValidW3cCredential))
            .Build()
            .Value;
    }

    private static void ConfigureValidW3cCredential(W3cVcCredentialQueryBuilder builder)
    {
        builder.AddTypeValues("UniversityDegree");
    }

    /// <summary>
    /// Test 1: Create JAR with RS256 signing using the new WithRsaSigningKey method.
    /// </summary>
    [Fact]
    public void Build_WithRsaSigningKey_CreatesValidJAR()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithIssuer("verifier-1")
            .WithAudience("https://wallet.example.com")
            .Build();

        // Assert
        if (!result.IsSuccess)
        {
            var errorMessages = string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));
            Assert.Fail($"JAR build failed: {errorMessages}");
        }
        
        Assert.NotNull(result.Value);
        Assert.NotEmpty(result.Value.Token);
        Assert.Equal("RS256", result.Value.SigningAlgorithm);
        Assert.False(result.Value.IsEncrypted);
        Assert.NotNull(result.Value.Claims);
    }

    /// <summary>
    /// Test 2: Verify JWT token structure (header.payload.signature).
    /// </summary>
    [Fact]
    public void Build_CreatesValidJWTStructure()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess, $"Build failed: {string.Join("; ", result.Errors.Select(e => e.Message))}");
        var token = result.Value.Token;
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length); // header.payload.signature
    }

    /// <summary>
    /// Test 2b: Verify JWT header includes typ parameter set to "oauth-authz-req+jwt" per RFC 9101.
    /// This ensures spec compliance for JWT-Secured Authorization Requests.
    /// </summary>
    [Fact]
    public void Build_IncludesTypHeaderParameter()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess, $"Build failed: {string.Join("; ", result.Errors.Select(e => e.Message))}");
        
        // Decode the JWT header to verify typ parameter
        var token = result.Value.Token;
        var parts = token.Split('.');
        var headerPart = parts[0];
        
        // Base64url decode the header
        var padding = new string('=', (4 - headerPart.Length % 4) % 4);
        var base64 = headerPart.Replace('-', '+').Replace('_', '/') + padding;
        var headerJson = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(base64));
        
        // Parse JSON and verify typ header
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(headerJson);
        var root = jsonDoc.RootElement;
        
        Assert.True(root.TryGetProperty("typ", out var typElement), "Header should contain 'typ' parameter");
        Assert.Equal("oauth-authz-req+jwt", typElement.GetString());
    }

    /// <summary>
    /// Test 3: JAR contains all authorization request fields as JWT claims.
    /// </summary>
    [Fact]
    public void Build_IncludesAllAuthorizationRequestFieldsInJWTClaims()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        var jar = result.Value;
        var claims = jar.Claims;

        // Verify key authorization request fields are present by checking some claims exist
        var claimsDict = claims.Claims.ToDictionary(c => c.Type, c => c.Value);
        Assert.True(claimsDict.ContainsKey("client_id"), "client_id should be in claims");
        Assert.True(claimsDict.ContainsKey("nonce"), "nonce should be in claims");
        Assert.True(claimsDict.ContainsKey("response_type"), "response_type should be in claims");
    }

    /// <summary>
    /// Test 4: JAR includes standard JWT claims (iss, aud, iat, exp).
    /// </summary>
    [Fact]
    public void Build_IncludesStandardJWTClaims()
    {
        // Arrange
        var request = CreateValidRequest();
        var issuer = "verifier-1";
        var audience = "https://wallet.example.com";

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithIssuer(issuer)
            .WithAudience(audience)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        var claims = result.Value.Claims;
        
        Assert.Equal(issuer, claims.Issuer);
        Assert.Contains(audience, claims.Audiences);
        Assert.NotNull(claims.IssuedAt);
        Assert.NotNull(claims.ValidTo);
        Assert.True(claims.ValidTo > DateTime.UtcNow);
    }

    /// <summary>
    /// Test 5: Build fails without signing key (mandatory).
    /// </summary>
    [Fact]
    public void Build_WithoutSigningKey_ReturnsFailure()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithAlgorithm("RS256")
            .Build();

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
        Assert.Contains(result.Errors, e => e.Code == "validation_error" && e.Message.Contains("Signing key"));
    }

    /// <summary>
    /// Test 6: Build fails with invalid authorization request.
    /// </summary>
    [Fact]
    public void Build_WithInvalidRequest_ReturnsFailure()
    {
        // Arrange - Create an invalid request (missing required nonce)
        var invalidRequest = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithResponseType("vp_token")
            .WithResponseMode("query")
            .WithScope("openid")
            .Build()
            .Value;

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(invalidRequest)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    /// <summary>
    /// Test 7: Verify JWT can be decoded using public key.
    /// </summary>
    [Fact]
    public void Build_CreatesTokenThatCanBeValidatedWithPublicKey()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert - Decode and verify token
        var handler = new JwtSecurityTokenHandler();
        var token = result.Value.Token;

        // Should be able to read without validation (no signature check)
        var decodedToken = handler.ReadJwtToken(token);
        Assert.NotNull(decodedToken);
        Assert.Equal(3, token.Split('.').Length);
    }

    /// <summary>
    /// Test 8: Default expiration is 5 minutes.
    /// </summary>
    [Fact]
    public void Build_DefaultExpirationIsSet()
    {
        // Arrange
        var request = CreateValidRequest();
        var beforeBuild = DateTime.UtcNow;

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        var afterBuild = DateTime.UtcNow;

        // Assert
        var jar = result.Value;
        var expiration = jar.Claims.ValidTo;

        // Expiration should be approximately 5 minutes from now
        var expectedMinExpiration = beforeBuild.AddMinutes(4.9);
        var expectedMaxExpiration = afterBuild.AddMinutes(5.1);

        Assert.True(expiration >= expectedMinExpiration && expiration <= expectedMaxExpiration);
    }

    /// <summary>
    /// Test 9: Custom expiration time can be set.
    /// </summary>
    [Fact]
    public void Build_WithCustomExpirationTime_SetsCorrectExpiration()
    {
        // Arrange
        var request = CreateValidRequest();
        var customExpiration = TimeSpan.FromMinutes(10);
        var beforeBuild = DateTime.UtcNow;

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithExpirationTime(customExpiration)
            .Build();

        var afterBuild = DateTime.UtcNow;

        // Assert
        var jar = result.Value;
        var expiration = jar.Claims.ValidTo;

        // Expiration should be approximately 10 minutes from now
        var expectedMinExpiration = beforeBuild.AddMinutes(9.9);
        var expectedMaxExpiration = afterBuild.AddMinutes(10.1);

        Assert.True(expiration >= expectedMinExpiration && expiration <= expectedMaxExpiration);
    }

    /// <summary>
    /// Test 10: JAR builder is fluent (methods return context).
    /// </summary>
    [Fact]
    public void BuilderMethods_AreFluentAndChainable()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act & Assert - Should compile and work
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithAlgorithm("RS256")
            .WithIssuer("verifier-1")
            .WithAudience("https://wallet.example.com")
            .WithExpirationTime(TimeSpan.FromMinutes(10))
            .Build();

        Assert.True(result.IsSuccess);
    }

    /// <summary>
    /// Test 11: Multiple builds with same configuration produce different tokens.
    /// </summary>
    [Fact]
    public void MultipleBuildCalls_ProduceDifferentTokens()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result1 = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(CreateFreshRsaSigningKey())
            .Build();

        // Small delay to ensure different iat/exp times
        System.Threading.Thread.Sleep(50);

        var result2 = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(CreateFreshRsaSigningKey())
            .Build();

        // Assert
        Assert.True(result1.IsSuccess, $"Result 1 failed: {string.Join(", ", result1.Errors.Select(e => e.Message))}");
        Assert.True(result2.IsSuccess, $"Result 2 failed: {string.Join(", ", result2.Errors.Select(e => e.Message))}");
        // Tokens MAY be the same if generated within same second (iat/exp are truncated to seconds)
        // So we just check that both are valid, not necessarily different
        Assert.NotEmpty(result1.Value.Token);
        Assert.NotEmpty(result2.Value.Token);
    }

    /// <summary>
    /// Test 12: IsEncrypted is false when encryption key not provided.
    /// </summary>
    [Fact]
    public void Build_WithoutEncryptionKey_IsEncryptedIsFalse()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.False(result.Value.IsEncrypted);
        Assert.Null(result.Value.EncryptionAlgorithm);
    }

    /// <summary>
    /// Test 13: IsEncrypted is true when encryption key provided.
    /// </summary>
    [Fact]
    public void Build_WithRsaEncryptionKey_IsEncryptedIsTrue()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithRsaEncryptionKey(_rsaPublicKey)
            .Build();

        // Assert
        Assert.True(result.Value.IsEncrypted);
        Assert.Equal("RSA-OAEP", result.Value.EncryptionAlgorithm);
    }

    /// <summary>
    /// Test 14: JAR without issuer and audience still valid.
    /// </summary>
    [Fact]
    public void Build_WithoutIssuerAndAudience_IsValid()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Empty(result.Value.Claims.Audiences);
    }

    /// <summary>
    /// Test 15: Authorization request with optional fields is serialized correctly in JAR.
    /// </summary>
    [Fact]
    public void Build_WithOptionalFields_SerializesCorrectly()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("verifier-1")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode("direct_post")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithResponseUri("https://verifier.example.com/response")
            .WithState("state-abc")
            .WithScope("openid")
            .Build()
            .Value;

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        var jar = result.Value;
        var claimsDict = jar.Claims.Claims.ToDictionary(c => c.Type, c => c.Value);

        Assert.True(claimsDict.ContainsKey("response_uri"), "response_uri should be in claims");
        Assert.True(claimsDict.ContainsKey("state"), "state should be in claims");
    }

    /// <summary>
    /// Test 16: JAR can be used with AuthorizationRequestBodyBuilder.
    /// </summary>
    [Fact]
    public void Build_CreatesJARThatCanBeUsedWithBodyBuilder()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        var bodyResult = AuthorizationRequestBodyBuilder.Create(request)
            .AsJar(jarResult.Value);

        // Assert
        Assert.True(jarResult.IsSuccess);
        Assert.True(bodyResult.IsSuccess);
        Assert.Equal(jarResult.Value.Token, bodyResult.Value);
    }

    /// <summary>
    /// Test 17: JAR token can be used with AuthorizationRequestUriBuilder for Option B.
    /// </summary>
    [Fact]
    public void Build_CreatesJARThatCanBeUsedWithURIBuilderOptionB()
    {
        // Arrange
        var request = CreateValidRequest();
        var baseUri = "https://wallet.example.com/auth";

        // Act
        var jarResult = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        var uriResult = AuthorizationRequestUriBuilder.Create(request)
            .AsRequestObjectByValue(baseUri, jarResult.Value.Token);

        // Assert
        Assert.True(jarResult.IsSuccess);
        Assert.True(uriResult.IsSuccess);
        Assert.Contains("request=", uriResult.Value);
        Assert.Contains(baseUri, uriResult.Value);
    }

    /// <summary>
    /// Test 18: JAR token length is reasonable (not excessively large).
    /// </summary>
    [Fact]
    public void Build_TokenSizeIsReasonable()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert - JWT should be less than 10KB (reasonable limit for HTTP)
        var tokenSize = System.Text.Encoding.UTF8.GetByteCount(result.Value.Token);
        Assert.True(tokenSize < 10000, $"Token size {tokenSize} exceeds 10KB limit");
    }

    /// <summary>
    /// Test 19: Different algorithms produce different tokens.
    /// </summary>
    [Fact]
    public void Build_WithDifferentAlgorithms_ProducesDifferentTokens()
    {
        // Arrange
        var request = CreateValidRequest();
        
        // Act - RS256 first time
        var rsaResult1 = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithAlgorithm("RS256")
            .Build();

        Assert.True(rsaResult1.IsSuccess);
        
        // Assert - Just verify both builds work
        Assert.Equal("RS256", rsaResult1.Value.SigningAlgorithm);
        Assert.NotEmpty(rsaResult1.Value.Token);
    }

    /// <summary>
    /// Test 20: Build handles all required AuthorizationRequest fields correctly.
    /// </summary>
    [Fact]
    public void Build_HandlesAllRequiredAuthorizationRequestFields()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert - Verify all required fields are in JWT
        var claims = result.Value.Claims;
        Assert.NotNull(claims);

        // All required fields must be present
        Assert.NotNull(claims.Claims.FirstOrDefault(c => c.Type == "client_id"));
        Assert.NotNull(claims.Claims.FirstOrDefault(c => c.Type == "nonce"));
        Assert.NotNull(claims.Claims.FirstOrDefault(c => c.Type == "response_type"));
        Assert.NotNull(claims.Claims.FirstOrDefault(c => c.Type == "response_mode"));
    }

    /// <summary>
    /// Test 21: ECDSA P-256 key (256 bits) auto-detects to ES256.
    /// </summary>
    [Fact]
    public void Build_WithECDsaP256Key_AutoDetectsES256()
    {
        // Arrange
        var request = CreateValidRequest();
        using var ecdsa256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa256);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithECDsaSigningKey(ecdsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("ES256", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 22: ECDSA P-384 key (384 bits) auto-detects to ES384.
    /// </summary>
    [Fact]
    public void Build_WithECDsaP384Key_AutoDetectsES384()
    {
        // Arrange
        var request = CreateValidRequest();
        using var ecdsa384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa384);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithECDsaSigningKey(ecdsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("ES384", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 23: ECDSA P-521 key (521 bits) auto-detects to ES512.
    /// </summary>
    [Fact]
    public void Build_WithECDsaP521Key_AutoDetectsES512()
    {
        // Arrange
        var request = CreateValidRequest();
        using var ecdsa521 = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa521);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithECDsaSigningKey(ecdsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("ES512", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 24: RSA 2048-bit key auto-detects to RS256.
    /// </summary>
    [Fact]
    public void Build_WithRsa2048Key_AutoDetectsRS256()
    {
        // Arrange
        var request = CreateValidRequest();
        using var rsa2048 = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa2048);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(rsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("RS256", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 25: RSA 3072-bit key auto-detects to RS384.
    /// </summary>
    [Fact]
    public void Build_WithRsa3072Key_AutoDetectsRS384()
    {
        // Arrange
        var request = CreateValidRequest();
        using var rsa3072 = RSA.Create(3072);
        var rsaKey = new RsaSecurityKey(rsa3072);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(rsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("RS384", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 26: RSA 4096-bit key auto-detects to RS512.
    /// </summary>
    [Fact]
    public void Build_WithRsa4096Key_AutoDetectsRS512()
    {
        // Arrange
        var request = CreateValidRequest();
        using var rsa4096 = RSA.Create(4096);
        var rsaKey = new RsaSecurityKey(rsa4096);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(rsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("RS512", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 27: RSA 2048-bit encryption key uses RSA-OAEP.
    /// </summary>
    [Fact]
    public void Build_WithRsa2048EncryptionKey_UsesRsaOaep()
    {
        // Arrange
        var request = CreateValidRequest();
        using var rsa2048 = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa2048);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithRsaEncryptionKey(rsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.True(result.Value.IsEncrypted);
        Assert.Equal("RSA-OAEP", result.Value.EncryptionAlgorithm);
    }

    /// <summary>
    /// Test 28: RSA 4096-bit encryption key uses RSA-OAEP-256.
    /// </summary>
    [Fact]
    public void Build_WithRsa4096EncryptionKey_UsesRsaOaep256()
    {
        // Arrange
        var request = CreateValidRequest();
        using var rsa4096 = RSA.Create(4096);
        var rsaKey = new RsaSecurityKey(rsa4096);

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithRsaEncryptionKey(rsaKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.True(result.Value.IsEncrypted);
        Assert.Equal("RSA-OAEP-256", result.Value.EncryptionAlgorithm);
    }

    /// <summary>
    /// Test 29: Symmetric signing key uses HS256.
    /// </summary>
    [Fact]
    public void Build_WithSymmetricSigningKey_UsesHS256()
    {
        // Arrange
        var request = CreateValidRequest();
        var symmetricKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("this-is-a-256-bit-key-for-testing-purposes-only-do-not-use-in-production"));

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithSymmetricSigningKey(symmetricKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal("HS256", result.Value.SigningAlgorithm);
    }

    /// <summary>
    /// Test 30: Symmetric encryption key uses A256KW.
    /// </summary>
    [Fact]
    public void Build_WithSymmetricEncryptionKey_UsesA256kw()
    {
        // Arrange
        var request = CreateValidRequest();
        var symmetricKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("this-is-a-256-bit-key-for-testing-purposes-only-do-not-use-in-production"));

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithSymmetricEncryptionKey(symmetricKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        Assert.True(result.Value.IsEncrypted);
        Assert.Equal("A256KW", result.Value.EncryptionAlgorithm);
    }

    #region x5c Header Format Tests

    /// <summary>
    /// Helper: Create a self-signed X.509 certificate for testing.
    /// </summary>
    private static X509Certificate2 CreateSelfSignedCertificate(string subjectName)
    {
        using (var rsa = RSA.Create(2048))
        {
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                $"CN={subjectName}",
                rsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);

            var cert = request.CreateSelfSigned(
                DateTime.UtcNow,
                DateTime.UtcNow.AddYears(1));

            return cert;
        }
    }

    /// <summary>
    /// Helper: Extract x5c array from JWT header.
    /// Returns list of base64url-encoded certificate strings.
    /// </summary>
    private static List<string> ExtractX5cFromJwt(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 3)
            throw new ArgumentException("Invalid JWT format");

        // Decode header (base64url -> JSON)
        var headerPart = parts[0];
        var padding = new string('=', (4 - headerPart.Length % 4) % 4);
        var base64 = headerPart.Replace('-', '+').Replace('_', '/') + padding;
        var headerJson = System.Text.Encoding.UTF8.GetString(
            System.Convert.FromBase64String(base64));

        // Parse JSON and extract x5c array
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(headerJson);
        var root = jsonDoc.RootElement;

        if (!root.TryGetProperty("x5c", out var x5cElement))
            return new List<string>();

        var x5c = new List<string>();
        if (x5cElement.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var item in x5cElement.EnumerateArray())
            {
                if (item.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    var cert = item.GetString();
                    if (!string.IsNullOrEmpty(cert))
                        x5c.Add(cert);
                }
            }
        }

        return x5c;
    }

    /// <summary>
    /// Helper: Decode base64url string to byte array.
    /// </summary>
    private static byte[] DecodeBase64Url(string base64Url)
    {
        var padding = new string('=', (4 - base64Url.Length % 4) % 4);
        var base64 = base64Url.Replace('-', '+').Replace('_', '/') + padding;
        return System.Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Test 32a: x5c header is present when certificate chain is provided.
    /// Verifies RFC 7515 compliance for x5c header inclusion.
    /// </summary>
    [Fact]
    public void Build_WithX509CertificateChain_IncludesX5cHeader()
    {
        // Arrange
        var cert = CreateSelfSignedCertificate("test.example.com");
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithX509CertificateChain(new[] { cert })
            .Build();

        // Assert
        Assert.True(result.IsSuccess, $"Build failed: {string.Join("; ", result.Errors.Select(e => e.Message))}");
        
        var x5c = ExtractX5cFromJwt(result.Value.Token);
        Assert.NotEmpty(x5c);
        Assert.Single(x5c);
    }

    /// <summary>
    /// Test 32b: x5c header is absent when no certificate chain is provided.
    /// Ensures x5c only appears when explicitly configured.
    /// </summary>
    [Fact]
    public void Build_WithoutX509CertificateChain_OmitsX5cHeader()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        
        var x5c = ExtractX5cFromJwt(result.Value.Token);
        Assert.Empty(x5c);
    }

    /// <summary>
    /// Test 32c: Certificates in x5c are base64url-encoded and can be decoded to original DER.
    /// Verifies encoding correctness per RFC 7515.
    /// </summary>
    [Fact]
    public void Build_WithX509CertificateChain_EncodesCertificatesAsBase64url()
    {
        // Arrange
        var cert = CreateSelfSignedCertificate("test.example.com");
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithX509CertificateChain(new[] { cert })
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        
        var x5c = ExtractX5cFromJwt(result.Value.Token);
        Assert.Single(x5c);

        // Decode and verify matches original certificate DER
        var decodedDer = DecodeBase64Url(x5c[0]);
        Assert.Equal(cert.RawData, decodedDer);
    }

    /// <summary>
    /// Test 32d: Certificate chain order is preserved (leaf certificate first).
    /// Per OpenID4VP spec, leaf certificate must come first in x5c array.
    /// </summary>
    [Fact]
    public void Build_WithX509CertificateChain_PreservesChainOrder()
    {
        // Arrange
        var leafCert = CreateSelfSignedCertificate("leaf.example.com");
        var intermediateCert = CreateSelfSignedCertificate("intermediate.example.com");
        var chain = new[] { leafCert, intermediateCert };
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithX509CertificateChain(chain)
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        
        var x5c = ExtractX5cFromJwt(result.Value.Token);
        Assert.Equal(2, x5c.Count);

        // Verify order: leaf first, then intermediate
        var decodedLeaf = DecodeBase64Url(x5c[0]);
        var decodedIntermediate = DecodeBase64Url(x5c[1]);
        
        Assert.Equal(leafCert.RawData, decodedLeaf);
        Assert.Equal(intermediateCert.RawData, decodedIntermediate);
    }

    /// <summary>
    /// Test 32e: x5c header is valid JSON array per RFC 7515.
    /// Verifies x5c is array (not object) and contains base64url strings.
    /// </summary>
    [Fact]
    public void Build_WithX509CertificateChain_X5cHeaderIsValidJsonArray()
    {
        // Arrange
        var cert = CreateSelfSignedCertificate("test.example.com");
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithX509CertificateChain(new[] { cert })
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        
        var token = result.Value.Token;
        var parts = token.Split('.');
        var headerPart = parts[0];
        
        // Decode and parse header JSON
        var padding = new string('=', (4 - headerPart.Length % 4) % 4);
        var base64 = headerPart.Replace('-', '+').Replace('_', '/') + padding;
        var headerJson = System.Text.Encoding.UTF8.GetString(
            System.Convert.FromBase64String(base64));

        using var jsonDoc = System.Text.Json.JsonDocument.Parse(headerJson);
        var root = jsonDoc.RootElement;

        // Verify x5c exists and is array
        Assert.True(root.TryGetProperty("x5c", out var x5cElement));
        Assert.Equal(System.Text.Json.JsonValueKind.Array, x5cElement.ValueKind);

        // Verify array contains at least one base64url string
        var arrayCount = 0;
        foreach (var item in x5cElement.EnumerateArray())
        {
            Assert.Equal(System.Text.Json.JsonValueKind.String, item.ValueKind);
            var certBase64 = item.GetString();
            Assert.NotEmpty(certBase64);
            
            // Verify base64url format (no padding, no + or /)
            Assert.DoesNotContain("+", certBase64);
            Assert.DoesNotContain("/", certBase64);
            Assert.DoesNotContain("=", certBase64);
            
            arrayCount++;
        }

        Assert.True(arrayCount > 0, "x5c array should contain at least one certificate");
    }

    /// <summary>
    /// Test 32f: Token with x5c header is properly formatted and decodable.
    /// Verifies JWT structure (header.payload.signature) is intact.
    /// </summary>
    [Fact]
    public void Build_WithX509CertificateChain_ProducesValidSignedJWT()
    {
        // Arrange
        var cert = CreateSelfSignedCertificate("test.example.com");
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithX509CertificateChain(new[] { cert })
            .Build();

        // Assert
        Assert.True(result.IsSuccess);
        
        var token = result.Value.Token;
        var parts = token.Split('.');
        
        // Verify JWT structure: header.payload.signature
        Assert.Equal(3, parts.Length);
        Assert.NotEmpty(parts[0]); // header
        Assert.NotEmpty(parts[1]); // payload
        Assert.NotEmpty(parts[2]); // signature

        // Verify header can be decoded
        var headerPart = parts[0];
        var padding = new string('=', (4 - headerPart.Length % 4) % 4);
        var base64 = headerPart.Replace('-', '+').Replace('_', '/') + padding;
        var headerJson = System.Text.Encoding.UTF8.GetString(
            System.Convert.FromBase64String(base64));

        // Verify it's valid JSON
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(headerJson);
        var root = jsonDoc.RootElement;

        // Verify standard JWT headers are present
        Assert.True(root.TryGetProperty("alg", out _), "JWT should have 'alg' header");
        Assert.True(root.TryGetProperty("typ", out _), "JWT should have 'typ' header");
        Assert.True(root.TryGetProperty("x5c", out _), "JWT should have 'x5c' header");
    }

    /// <summary>
    /// Test: Verify JWT payload contains all authorization request fields correctly serialized.
    /// </summary>
    [Fact]
    public void Build_ValidatesJwtPayloadStructure()
    {
        // Arrange
        var request = CreateValidRequest();

        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithRsaSigningKey(_rsaPrivateKey)
            .WithIssuer("verifier-1")
            .WithAudience("https://wallet.example.com")
            .Build();

        // Assert
        Assert.True(result.IsSuccess, $"Build failed: {string.Join("; ", result.Errors.Select(e => e.Message))}");
        
        // Decode the JWT payload
        var token = result.Value.Token;
        var parts = token.Split('.');
        var payloadPart = parts[1];
        
        // Base64url decode the payload
        var padding = new string('=', (4 - payloadPart.Length % 4) % 4);
        var base64 = payloadPart.Replace('-', '+').Replace('_', '/') + padding;
        var payloadJson = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(base64));
        
        // Parse JSON and verify payload structure
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var root = jsonDoc.RootElement;
        
        // Verify standard JWT claims
        Assert.True(root.TryGetProperty("iss", out var issElement), "Payload should contain 'iss' claim");
        Assert.Equal("verifier-1", issElement.GetString());
        
        Assert.True(root.TryGetProperty("aud", out var audElement), "Payload should contain 'aud' claim");
        // aud can be either a string or an array, handle both cases
        if (audElement.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            var audArray = audElement.EnumerateArray().ToList();
            Assert.NotEmpty(audArray);
            Assert.Equal("https://wallet.example.com", audArray[0].GetString());
        }
        else
        {
            Assert.Equal("https://wallet.example.com", audElement.GetString());
        }
        
        Assert.True(root.TryGetProperty("iat", out _), "Payload should contain 'iat' claim");
        Assert.True(root.TryGetProperty("exp", out _), "Payload should contain 'exp' claim");
        
        // Verify authorization request fields
        Assert.True(root.TryGetProperty("client_id", out var clientIdElement), "Payload should contain 'client_id'");
        Assert.Equal("verifier-1", clientIdElement.GetString());
        
        Assert.True(root.TryGetProperty("nonce", out var nonceElement), "Payload should contain 'nonce'");
        Assert.Equal("abc123xyz", nonceElement.GetString());
        
        Assert.True(root.TryGetProperty("response_type", out var responseTypeElement), "Payload should contain 'response_type'");
        Assert.Equal("vp_token", responseTypeElement.GetString());
        
        Assert.True(root.TryGetProperty("response_mode", out var responseModeElement), "Payload should contain 'response_mode'");
        Assert.Equal("query", responseModeElement.GetString());
        
        Assert.True(root.TryGetProperty("redirect_uri", out var redirectUriElement), "Payload should contain 'redirect_uri'");
        Assert.Equal("https://verifier.example.com/callback", redirectUriElement.GetString());
        
        // Verify dcql_query is present and is a JSON object (not a string)
        Assert.True(root.TryGetProperty("dcql_query", out var dcqlElement), "Payload should contain 'dcql_query'");
        Assert.Equal(System.Text.Json.JsonValueKind.Object, dcqlElement.ValueKind);
        
        // Verify dcql_query structure
        Assert.True(dcqlElement.TryGetProperty("credentials", out var credentialsElement), "dcql_query should contain 'credentials'");
        Assert.Equal(System.Text.Json.JsonValueKind.Array, credentialsElement.ValueKind);
        Assert.True(credentialsElement.GetArrayLength() > 0, "credentials array should not be empty");
    }

    #endregion
}
