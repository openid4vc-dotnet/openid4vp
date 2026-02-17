namespace OpenID4VP.Tests;

using OpenID4VC.Core.Tests;
using OpenID4VP.Builders;

public class YiviDemoTests
{
    [Fact]
    public void Build_CrossDevice_Yivi_Succeeds()
    {
        // Cross-device: Uses minimal request in QR code (client_id + request_uri)
        // Nonce comes in the full AuthorizationRequest fetched from request_uri

        var result = CrossDeviceRequestUriBuilder.Create()
            .WithClientId(ClientIdentifierPrefix.X509SanDns, "portal.verifier.dev")
            .WithRequestUri("https://portal.verifier.dev/ibanrequest")
            .WithNonce("random_nonce_value")
            .Build("openid4vp://");


        var uri = result.AssertSuccess();

        Assert.NotNull(uri);

        Assert.Contains("client_id=x509_san_dns%3Aportal.verifier.dev", uri);
        Assert.Contains("request_uri=https%3A%2F%2Fportal.verifier.dev%2Fibanrequest", uri);
        Assert.Contains("nonce=random_nonce_value", uri);
        Assert.Contains("openid4vp://", uri);
    }
}
