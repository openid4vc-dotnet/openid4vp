namespace OpenID4VP.Tests;

using Microsoft.IdentityModel.Tokens;
using OpenID4VC.Core.Tests;
using OpenID4VP.Builders;
using OpenID4VP.Common;
using System.Security.Cryptography;

public class YiviDemoTests : IDisposable
{
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _rsaPrivateKey;
    private readonly RsaSecurityKey _rsaPublicKey;

    public YiviDemoTests()
    {
        // Generate test RSA key pair - keep RSA alive for duration of tests
        _rsa = RSA.Create();
        _rsaPrivateKey = new RsaSecurityKey(_rsa) { KeyId = "test-key-1" };
        _rsaPublicKey = new RsaSecurityKey(_rsa.ExportParameters(false)) { KeyId = "test-key-1" };
    }

    public void Dispose()
    {
        _rsa?.Dispose();
    }

    [Fact]
    public void Build_AuthRequestInitByRef_Yivi_Succeeds()
    {
        // Request by reference
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId(ClientIdentifierPrefix.X509SanDns, "portal.verifier.dev")
            .WithRequestUri("https://portal.verifier.dev/ibanrequest")
            .WithNonce("random_nonce_value")
            .Build();

        var qrUri = AuthorizationRequestUriBuilder.Create(request.Value)
            .AsRequestObjectByReference("openid4vp://");

        var uri = qrUri.AssertSuccess();

        Assert.NotNull(uri);

        Assert.Contains("client_id=x509_san_dns%3Aportal.verifier.dev", uri);
        Assert.Contains("request_uri=https%3A%2F%2Fportal.verifier.dev%2Fibanrequest", uri);
        Assert.Contains("nonce=random_nonce_value", uri);
        Assert.Contains("openid4vp://", uri);
    }

    [Fact]
    public void Build_AuthRequestByRef_Yivi_Succeeds()
    {
        // Arrange
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId(ClientIdentifierPrefix.X509SanDns, "portal.verifier.dev")
            .WithNonce("abc123xyz")
            .WithResponseType("vp_token")
            .WithResponseMode(ResponseModes.DirectPostJwt)
            .WithResponseUri("https://portal.verifier.dev/consent")
            .WithDcql(builder =>
            {
                builder.AddDcSdJwtCredential("iban", b =>
                {
                    b.AddVctValues("pbdf-staging.pbdf.iban")
                        .AddClaim("iban", "iban");
                });
            })
            .Build();

        using var ecdsa256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa256);


        // Act
        var result = JwtSecuredAuthorizationRequestBuilder.Create(request)
            .WithECDsaSigningKey(ecdsaKey)
            .WithIssuer("yivi")
            .WithAudience("https://portal.verifier.dev")
            .Build();

        // Assert
        if (!result.IsSuccess)
        {
            var errorMessages = string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));
            Assert.Fail($"JAR build failed: {errorMessages}");
        }

        Assert.NotNull(result.Value);
        Assert.NotEmpty(result.Value.Token);
        Assert.Equal(SecurityAlgorithms.EcdsaSha256, result.Value.SigningAlgorithm);
        Assert.False(result.Value.IsEncrypted);
        Assert.NotNull(result.Value.Claims);
    }

}
