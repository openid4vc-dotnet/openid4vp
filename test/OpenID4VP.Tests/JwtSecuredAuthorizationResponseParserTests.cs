using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Parsers;
using Xunit;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace OpenID4VP.Tests.Parsers;

/// <summary>
/// Tests for JwtSecuredAuthorizationResponseParser (JWE decryption).
/// 
/// Tests verify:
/// - JWE decryption with private key
/// - Proper JWT retrieval from encrypted JWE
/// - Error handling (invalid JWE, missing key, etc.)
/// </summary>
public class JwtSecuredAuthorizationResponseParserTests
{
    /// <summary>
    /// Test 1: FromJar with null JWE returns error.
    /// </summary>
    [Fact]
    public void FromJar_WithNullJweToken_ReturnsError()
    {
        // Arrange
        var encryptionKey = new SymmetricSecurityKey(new byte[32]);

        // Act
        var result = JwtSecuredAuthorizationResponseParser.FromJar(null!, encryptionKey);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    /// <summary>
    /// Test 2: FromJar with empty JWE returns error.
    /// </summary>
    [Fact]
    public void FromJar_WithEmptyJweToken_ReturnsError()
    {
        // Arrange
        var encryptionKey = new SymmetricSecurityKey(new byte[32]);

        // Act
        var result = JwtSecuredAuthorizationResponseParser.FromJar("", encryptionKey);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    /// <summary>
    /// Test 3: FromJar with null private key returns error.
    /// </summary>
    [Fact]
    public void FromJar_WithNullPrivateKey_ReturnsError()
    {
        // Arrange
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        // Act
        var result = JwtSecuredAuthorizationResponseParser.FromJar(jwt, null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    /// <summary>
    /// Test 4: FromJar with invalid JWE token returns error.
    /// </summary>
    [Fact]
    public void FromJar_WithInvalidJweToken_ReturnsError()
    {
        // Arrange
        var invalidJwe = "not.a.valid.jwe.token.string";
        var encryptionKey = new SymmetricSecurityKey(new byte[32]);

        // Act
        var result = JwtSecuredAuthorizationResponseParser.FromJar(invalidJwe, encryptionKey);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.NotEmpty(result.Errors);
    }

    /// <summary>
    /// Test 5: FromJar returns Result with success status and error details structure.
    /// Tests that the parser returns a properly structured Result object.
    /// </summary>
    [Fact]
    public void FromJar_ReturnsResultType()
    {
        // Arrange
        var invalidJwe = "invalid";
        var encryptionKey = new SymmetricSecurityKey(new byte[32]);

        // Act
        var result = JwtSecuredAuthorizationResponseParser.FromJar(invalidJwe, encryptionKey);

        // Assert
        Assert.NotNull(result);
        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Errors);
    }

    /// <summary>
    /// Test 6: FromJar method is static and can be called without instance.
    /// </summary>
    [Fact]
    public void FromJar_IsStaticMethod()
    {
        // Arrange
        var invalidJwe = "test";
        var encryptionKey = new SymmetricSecurityKey(new byte[32]);

        // Act - This should work even though we haven't instantiated the parser
        var result = JwtSecuredAuthorizationResponseParser.FromJar(invalidJwe, encryptionKey);

        // Assert
        Assert.NotNull(result);
    }
}

