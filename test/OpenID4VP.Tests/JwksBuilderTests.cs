using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Builders;
using Xunit;

namespace OpenID4VP.Tests;

public class JwksBuilderTests
{
    [Fact]
    public void CreatePublicKey_WithRsaKey_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = "test-key-1" };

        // Act
        var result = JwksBuilder.CreatePublicKey(rsaKey, "sig");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        var jwk = result.Value;
        Assert.Equal("sig", jwk.Use);
        Assert.NotNull(jwk.N); // Public modulus should exist
        Assert.Null(jwk.D); // Private exponent should NOT exist
    }

    [Fact]
    public void CreatePublicKey_WithEcdsaKey_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = "test-ec-key-1" };

        // Act
        var result = JwksBuilder.CreatePublicKey(ecdsaKey, "sig");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        var jwk = result.Value;
        Assert.Equal("sig", jwk.Use);
        Assert.NotNull(jwk.X); // Public coordinate X should exist
        Assert.NotNull(jwk.Y); // Public coordinate Y should exist
        Assert.Null(jwk.D); // Private coefficient should NOT exist
    }

    [Fact]
    public void CreatePublicKey_WithNullRsaKey_ReturnsError()
    {
        // Act
        var result = JwksBuilder.CreatePublicKey((RsaSecurityKey)null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be null", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKey_WithNullEcdsaKey_ReturnsError()
    {
        // Act
        var result = JwksBuilder.CreatePublicKey((ECDsaSecurityKey)null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be null", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKey_WithRsaKey_GeneratesKeyIdIfNotProvided()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa); // No KeyId

        // Act
        var result = JwksBuilder.CreatePublicKey(rsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.NotNull(jwk.Kid);
        Assert.StartsWith("key-", jwk.Kid);
    }

    [Fact]
    public void CreatePublicKey_WithEcdsaKey_GeneratesKeyIdIfNotProvided()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa); // No KeyId

        // Act
        var result = JwksBuilder.CreatePublicKey(ecdsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.NotNull(jwk.Kid);
        Assert.StartsWith("key-", jwk.Kid);
    }

    [Fact]
    public void CreatePublicKey_WithRsaKey_PreservesProvidedKeyId()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        const string providedKeyId = "my-custom-key-id";
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = providedKeyId };

        // Act
        var result = JwksBuilder.CreatePublicKey(rsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.Equal(providedKeyId, jwk.Kid);
    }




    [Fact]
    public void CreatePublicKey_WithRsaP256Key_UsesSignatureUsage()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);
        const string usage = "sig";

        // Act
        var result = JwksBuilder.CreatePublicKey(rsaKey, usage);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.Equal(usage, jwk.Use);
    }

    [Fact]
    public void CreatePublicKey_WithEcdsaP384Key_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);

        // Act
        var result = JwksBuilder.CreatePublicKey(ecdsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.NotNull(jwk.X);
        Assert.NotNull(jwk.Y);
        Assert.Null(jwk.D); // Private component should not exist
    }

    [Fact]
    public void CreatePublicKey_WithEcdsaP521Key_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);

        // Act
        var result = JwksBuilder.CreatePublicKey(ecdsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.NotNull(jwk.X);
        Assert.NotNull(jwk.Y);
        Assert.Null(jwk.D);
    }

    [Fact]
    public void CreatePublicKey_Rsa4096Key_ExtractsSuccessfully()
    {
        // Arrange
        using var rsa = RSA.Create(4096);
        var rsaKey = new RsaSecurityKey(rsa);

        // Act
        var result = JwksBuilder.CreatePublicKey(rsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value;
        Assert.NotNull(jwk.N);
        Assert.Null(jwk.D);
    }
}
