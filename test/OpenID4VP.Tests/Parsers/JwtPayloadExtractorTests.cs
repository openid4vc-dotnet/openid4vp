using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Parsers;
using Xunit;

namespace OpenID4VP.Tests.Parsers;

/// <summary>
/// Tests for JwtPayloadExtractor.
/// 
/// Tests verify:
/// - Extraction of JSON payload from JWT tokens
/// - Proper base64url decoding
/// - Error handling for invalid tokens
/// </summary>
public class JwtPayloadExtractorTests
{
    private readonly JwtPayloadExtractor _extractor = new();

    /// <summary>
    /// Test 1: ExtractPayloadJson with null JWT returns error.
    /// </summary>
    [Fact]
    public void ExtractPayloadJson_WithNullJwt_ReturnsError()
    {
        // Act
        var result = _extractor.ExtractPayloadJson(null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    /// <summary>
    /// Test 2: ExtractPayloadJson extracts payload from valid JWT.
    /// </summary>
    [Fact]
    public void ExtractPayloadJson_WithValidJwt_ReturnsPayloadJson()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(key, "HS256");
        
        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                { "sub", "test-subject" },
                { "aud", "test-audience" }
            },
            SigningCredentials = credentials
        };

        var token = handler.CreateToken(descriptor) as JwtSecurityToken;

        // Act
        var result = _extractor.ExtractPayloadJson(token);

        // Assert
        Assert.True(result.IsSuccess);
        var payloadJson = result.Value;
        Assert.NotNull(payloadJson);
        Assert.Contains("test-subject", payloadJson);
        Assert.Contains("test-audience", payloadJson);
    }

    /// <summary>
    /// Test 3: ExtractPayloadJson payload is valid JSON.
    /// </summary>
    [Fact]
    public void ExtractPayloadJson_PayloadIsValidJson()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(key, "HS256");

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                { "client_id", "verifier-1" },
                { "nonce", "abc123" }
            },
            SigningCredentials = credentials
        };

        var token = handler.CreateToken(descriptor) as JwtSecurityToken;

        // Act
        var result = _extractor.ExtractPayloadJson(token);

        // Assert
        Assert.True(result.IsSuccess);
        var payloadJson = result.Value;

        // Should be parseable as JSON
        using var doc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;
        
        Assert.True(root.TryGetProperty("client_id", out var clientId));
        Assert.Equal("verifier-1", clientId.GetString());
        
        Assert.True(root.TryGetProperty("nonce", out var nonce));
        Assert.Equal("abc123", nonce.GetString());
    }

    /// <summary>
    /// Test 4: ExtractPayloadJson preserves complex claim values.
    /// </summary>
    [Fact]
    public void ExtractPayloadJson_PreservesComplexClaims()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(key, "HS256");

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                { "simple_claim", "value" },
                { "numeric_claim", 12345 },
                { "boolean_claim", true }
            },
            SigningCredentials = credentials
        };

        var token = handler.CreateToken(descriptor) as JwtSecurityToken;

        // Act
        var result = _extractor.ExtractPayloadJson(token);

        // Assert
        Assert.True(result.IsSuccess);
        var payloadJson = result.Value;

        using var doc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        Assert.Equal("value", root.GetProperty("simple_claim").GetString());
        Assert.Equal(12345, root.GetProperty("numeric_claim").GetInt32());
        Assert.True(root.GetProperty("boolean_claim").GetBoolean());
    }

    /// <summary>
    /// Test 5: ExtractPayloadJson includes standard JWT claims.
    /// </summary>
    [Fact]
    public void ExtractPayloadJson_IncludesStandardJwtClaims()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(key, "HS256");

        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            NotBefore = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = credentials
        };

        var token = handler.CreateToken(descriptor) as JwtSecurityToken;

        // Act
        var result = _extractor.ExtractPayloadJson(token);

        // Assert
        Assert.True(result.IsSuccess);
        var payloadJson = result.Value;

        using var doc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        // Check standard claims exist
        Assert.True(root.TryGetProperty("iss", out _), "iss claim should exist");
        Assert.True(root.TryGetProperty("aud", out _), "aud claim should exist");
        Assert.True(root.TryGetProperty("nbf", out _), "nbf claim should exist");
        Assert.True(root.TryGetProperty("exp", out _), "exp claim should exist");
    }

    /// <summary>
    /// Test 6: ExtractPayloadJson result is non-empty string.
    /// </summary>
    [Fact]
    public void ExtractPayloadJson_ReturnsNonEmptyPayload()
    {
        // Arrange
        var handler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(new byte[32]);
        var credentials = new SigningCredentials(key, "HS256");

        var descriptor = new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { "test", "value" } },
            SigningCredentials = credentials
        };

        var token = handler.CreateToken(descriptor) as JwtSecurityToken;

        // Act
        var result = _extractor.ExtractPayloadJson(token);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.NotEmpty(result.Value);
    }
}
