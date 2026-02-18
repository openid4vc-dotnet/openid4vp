using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Builders;
using Xunit;

namespace OpenID4VP.Tests;

public class JwksBuilderTests
{
    [Fact]
    public void CreatePublicKeySet_WithRsaKey_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = "test-key-1" };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(rsaKey, "sig");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Single(result.Value.Keys);
        var jwk = result.Value.Keys.First();
        Assert.Equal("sig", jwk.Use);
        Assert.NotNull(jwk.N); // Public modulus should exist
        Assert.Null(jwk.D); // Private exponent should NOT exist
    }

    [Fact]
    public void CreatePublicKeySet_WithEcdsaKey_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = "test-ec-key-1" };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(ecdsaKey, "sig");

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Single(result.Value.Keys);
        var jwk = result.Value.Keys.First();
        Assert.Equal("sig", jwk.Use);
        Assert.NotNull(jwk.X); // Public coordinate X should exist
        Assert.NotNull(jwk.Y); // Public coordinate Y should exist
        Assert.Null(jwk.D); // Private coefficient should NOT exist
    }

    [Fact]
    public void CreatePublicKeySet_WithNullRsaKey_ReturnsError()
    {
        // Act
        var result = JwksBuilder.CreatePublicKeySet((RsaSecurityKey)null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be null", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKeySet_WithNullEcdsaKey_ReturnsError()
    {
        // Act
        var result = JwksBuilder.CreatePublicKeySet((ECDsaSecurityKey)null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be null", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKeySet_WithRsaKey_GeneratesKeyIdIfNotProvided()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa); // No KeyId

        // Act
        var result = JwksBuilder.CreatePublicKeySet(rsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value.Keys.First();
        Assert.NotNull(jwk.Kid);
        Assert.StartsWith("key-", jwk.Kid);
    }

    [Fact]
    public void CreatePublicKeySet_WithEcdsaKey_GeneratesKeyIdIfNotProvided()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa); // No KeyId

        // Act
        var result = JwksBuilder.CreatePublicKeySet(ecdsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value.Keys.First();
        Assert.NotNull(jwk.Kid);
        Assert.StartsWith("key-", jwk.Kid);
    }

    [Fact]
    public void CreatePublicKeySet_WithRsaKey_PreservesProvidedKeyId()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        const string providedKeyId = "my-custom-key-id";
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = providedKeyId };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(rsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value.Keys.First();
        Assert.Equal(providedKeyId, jwk.Kid);
    }

    [Fact]
    public void CreatePublicKeySet_WithMultipleRsaKeys_ExtractsAllKeysSuccessfully()
    {
        // Arrange
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(3072);
        var keys = new SecurityKey[]
        {
            new RsaSecurityKey(rsa1),
            new RsaSecurityKey(rsa2)
        };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(keys);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Equal(2, result.Value.Keys.Count);
        foreach (var jwk in result.Value.Keys)
        {
            Assert.Null(jwk.D); // All should be public only
        }
    }

    [Fact]
    public void CreatePublicKeySet_WithMixedKeyTypes_ExtractsAllKeysSuccessfully()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = new SecurityKey[]
        {
            new RsaSecurityKey(rsa),
            new ECDsaSecurityKey(ecdsa)
        };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(keys);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value);
        Assert.Equal(2, result.Value.Keys.Count);
    }

    [Fact]
    public void CreatePublicKeySet_WithNullKeyCollection_ReturnsError()
    {
        // Act
        var result = JwksBuilder.CreatePublicKeySet((IEnumerable<SecurityKey>)null!);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be null", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKeySet_WithEmptyKeyCollection_ReturnsError()
    {
        // Act
        var result = JwksBuilder.CreatePublicKeySet(Enumerable.Empty<SecurityKey>());

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("cannot be empty", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKeySet_WithUnsupportedKeyType_ReturnsError()
    {
        // Arrange
        var symmetricKey = new SymmetricSecurityKey(new byte[32]);
        var keys = new SecurityKey[] { symmetricKey };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(keys);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("Unsupported key type", result.Errors.First().Message);
    }

    [Fact]
    public void CreatePublicKeySet_WithRsaP256Key_UsesSignatureUsage()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);
        const string usage = "sig";

        // Act
        var result = JwksBuilder.CreatePublicKeySet(rsaKey, usage);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value.Keys.First();
        Assert.Equal(usage, jwk.Use);
    }

    [Fact]
    public void CreatePublicKeySet_WithEcdsaP384Key_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);

        // Act
        var result = JwksBuilder.CreatePublicKeySet(ecdsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Single(result.Value.Keys);
        var jwk = result.Value.Keys.First();
        Assert.NotNull(jwk.X);
        Assert.NotNull(jwk.Y);
        Assert.Null(jwk.D); // Private component should not exist
    }

    [Fact]
    public void CreatePublicKeySet_WithEcdsaP521Key_ExtractsPublicKeySuccessfully()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);

        // Act
        var result = JwksBuilder.CreatePublicKeySet(ecdsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Single(result.Value.Keys);
        var jwk = result.Value.Keys.First();
        Assert.NotNull(jwk.X);
        Assert.NotNull(jwk.Y);
        Assert.Null(jwk.D);
    }

    [Fact]
    public void CreatePublicKeySet_MultipleKeys_AllHaveNoPrivateComponents()
    {
        // Arrange
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(3072);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = new SecurityKey[]
        {
            new RsaSecurityKey(rsa1),
            new RsaSecurityKey(rsa2),
            new ECDsaSecurityKey(ecdsa)
        };

        // Act
        var result = JwksBuilder.CreatePublicKeySet(keys);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(3, result.Value.Keys.Count);
        foreach (var jwk in result.Value.Keys)
        {
            Assert.Null(jwk.D); // No private exponent/coefficient
        }
    }

    [Fact]
    public void CreatePublicKeySet_Rsa4096Key_ExtractsSuccessfully()
    {
        // Arrange
        using var rsa = RSA.Create(4096);
        var rsaKey = new RsaSecurityKey(rsa);

        // Act
        var result = JwksBuilder.CreatePublicKeySet(rsaKey);

        // Assert
        Assert.True(result.IsSuccess);
        var jwk = result.Value.Keys.First();
        Assert.NotNull(jwk.N);
        Assert.Null(jwk.D);
    }
}
