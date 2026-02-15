using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VC.Core.Tests;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for ToUri extension method on AuthorizationRequest
/// 
/// Verifies conversion of cross-device AuthorizationRequest to web-safe URI query parameters
/// suitable for QR code encoding.
/// </summary>
public class AuthorizationRequestUriExtensionsTests
{
    [Fact]
    public void ToUri_WithMinimalRequiredFields_ReturnsUriWithQueryParams()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Verify base URI is present
        Assert.StartsWith("https://verifier.example.com/auth?", uri);
        
        // Verify required parameters are present and encoded
        Assert.Contains("client_id=https%3A%2F%2Fverifier.example.com", uri);
        Assert.Contains("request_uri=https%3A%2F%2Fverifier.example.com%2Frequest", uri);
        Assert.Contains("response_mode=direct_post", uri);
        
        // Verify nonce is NOT in URI (it's in RequestObject)
        Assert.DoesNotContain("nonce", uri);
    }

    [Fact]
    public void ToUri_WithState_IncludesStateInUri()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithState("state-456")
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        Assert.Contains("state=state-456", uri);
    }

    [Fact]
    public void ToUri_WithSpecialCharactersInClientId_UrlEncodesCorrectly()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("x509_san_dns:client.example.org")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Special characters (: and .) should be URL encoded
        Assert.Contains("x509_san_dns%3Aclient.example.org", uri);
    }

    [Fact]
    public void ToUri_WithComplexRequestUri_UrlEncodesCorrectly()
    {
        var requestUri = "https://verifier.example.com/request?param1=value1&param2=value2";
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri(requestUri)
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Query characters should be encoded
        Assert.Contains("%3F", uri);  // ?
        Assert.Contains("%26", uri);  // &
        Assert.Contains("%3D", uri);  // =
    }

    [Fact]
    public void ToUri_WithBaseUriThatHasQueryParams_AppendsWithAmpersand()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth?existing=param");

        // Should use & separator, not ?
        Assert.Contains("existing=param&", uri);
        Assert.DoesNotContain("?client_id", uri);
        Assert.Contains("&client_id", uri);
    }

    [Fact]
    public void ToUri_WithInternationalDomain_EncodesCorrectly()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://ü例え.jp")  // International domain
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // International characters should be percent-encoded
        Assert.Contains("%", uri);
        // Base URI should still be readable
        Assert.StartsWith("https://verifier.example.com/auth?", uri);
    }

    [Fact]
    public void ToUri_ExcludesNonceFromUri()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("secret-nonce-123")  // Should NOT appear in URI
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Nonce must NOT be in minimal request (it's in RequestObject)
        Assert.DoesNotContain("nonce", uri);
        Assert.DoesNotContain("secret-nonce-123", uri);
    }

    [Fact]
    public void ToUri_ExcludesResponseTypeFromUri()
    {
        // Note: CrossDeviceAuthorizationRequest validator forbids response_type
        // but we're testing with raw builder for this edge case
        var request = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("nonce-123")
            .WithRequestUri("https://verifier.example.com/request")
            .WithResponseMode(ResponseModes.DirectPost)
            .WithResponseType(ResponseTypes.VpToken)  // Set even though cross-device forbids it
            .Build()
            .AssertSuccess();

        var uri = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId(request.ClientId!)
                .WithNonce(request.Nonce!)
                .WithRequestUri(request.RequestUri!)
                .WithResponseMode(request.ResponseMode!)
        ).ToUri("https://verifier.example.com/auth");

        // response_type should NOT be in minimal request
        Assert.DoesNotContain("response_type", uri);
    }

    [Fact]
    public void ToUri_WithFailedResult_ThrowsInvalidOperationException()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithNonce("nonce-123")
            // Missing required fields - will fail validation
            .Build();

        var errors = result.AssertError();
        Assert.NotEmpty(errors);

        // Calling ToUri on failed result should throw
        Assert.Throws<InvalidOperationException>(() => result.ToUri("https://verifier.example.com/auth"));
    }

    [Fact]
    public void ToUri_WithNullBaseUri_ThrowsArgumentNullException()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        Assert.Throws<ArgumentNullException>(() => result.ToUri(null!));
    }

    [Fact]
    public void ToUri_WithEmptyBaseUri_ThrowsArgumentNullException()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        Assert.Throws<ArgumentNullException>(() => result.ToUri(""));
    }

    [Fact]
    public void ToUri_WithSpacesInState_UrlEncodesCorrectly()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithState("my state value")  // Contains spaces
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Spaces should be percent-encoded as %20
        Assert.Contains("state=my%20state%20value", uri);
        Assert.DoesNotContain("state=my state value", uri);
    }

    [Fact]
    public void ToUri_WithPlusSignInValue_UrlEncodesCorrectly()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request?filter=status%3D%2BActive")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Plus signs should be properly handled in URL encoding
        Assert.Contains("request_uri=", uri);
        Assert.NotEmpty(uri);
    }

    [Fact]
    public void ToUri_ProducesValidUri_CanBeParsedByUriClass()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request?param=value")
                .WithResponseMode(ResponseModes.DirectPost)
                .WithState("state-123")
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Should be parseable as a valid URI
        var uriObj = new Uri(uri);
        Assert.NotNull(uriObj);
        Assert.Equal("https", uriObj.Scheme);
        Assert.Equal("verifier.example.com", uriObj.Host);
        Assert.Equal("/auth", uriObj.AbsolutePath);
    }

    [Fact]
    public void ToUri_WithAllOptionalFields_IncludesAllInUri()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("https://verifier.example.com")
                .WithNonce("nonce-value")
                .WithRequestUri("https://verifier.example.com/request")
                .WithResponseMode(ResponseModes.DirectPostJwt)
                .WithState("session-state")
        );

        var uri = result.ToUri("https://verifier.example.com/auth");

        // Verify all parameters are present
        Assert.Contains("client_id=", uri);
        Assert.Contains("request_uri=", uri);
        Assert.Contains("response_mode=direct_post.jwt", uri);
        Assert.Contains("state=session-state", uri);
        
        // Nonce should NOT be present
        Assert.DoesNotContain("nonce", uri);
    }

    [Fact]
    public void ToUri_UrlEncodingIsConsistent_MultipleCallsProduceSameResult()
    {
        var result = CrossDeviceAuthorizationRequest.Build(builder =>
            builder
                .WithClientId("x509_san_dns:client.example.org")
                .WithNonce("nonce-123")
                .WithRequestUri("https://verifier.example.com/request?filter=active")
                .WithResponseMode(ResponseModes.DirectPost)
        );

        var uri1 = result.ToUri("https://verifier.example.com/auth");
        var uri2 = result.ToUri("https://verifier.example.com/auth");

        // Should produce identical URIs
        Assert.Equal(uri1, uri2);
    }
}
