namespace OpenID4VP.Tests;

using OpenID4VC.Core.Tests;
using OpenID4VP.Builders;
using OpenID4VP.Common;

public class YiviDemoTests
{
    [Fact]
    public void Build_CrossDevice_Yivi_Succeeds()
    {
        // Cross-device: Uses minimal request in QR code (client_id + request_uri)
        // Nonce comes in the full AuthorizationRequest fetched from request_uri
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithResponseMode(ResponseModes.DirectPost)
                .WithNonce("random_nonce_value")
                .WithClientId(ClientIdentifierPrefix.X509SanDns, "portal.verifier.dev")
                .WithRequestUri("https://portal.verifier.dev/ibanrequest")
        );

        var request = result.AssertSuccess();

        Assert.NotNull(request);
        Assert.Equal("x509_san_dns:portal.verifier.dev", request.ClientId);
        Assert.Equal("https://portal.verifier.dev/ibanrequest", request.RequestUri);
    }
}
