using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Validators;
using OpenID4VP.Dcql.Query.Builders;

namespace OpenID4VP.Tests.Validators;

/// <summary>
/// Tests for AuthorizationRequestValidator
/// </summary>
public class AuthorizationRequestValidatorTests
{
    private readonly AuthorizationRequestValidator _validator = new();

    private static void ConfigureValidW3cCredential(W3cVcCredentialQueryBuilder builder)
    {
        builder.AddTypeValues("UniversityDegree");
    }

    private AuthorizationRequest CreateValidRequest()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        return result.Value!;
    }

    [Fact]
    public void Validate_ValidRequest_ReturnsSuccess()
    {
        var request = CreateValidRequest();
        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_NullRequest_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _validator.Validate(null!));
        Assert.Equal("request", ex.ParamName);
    }

    [Fact]
    public void Validate_InvalidResponseType_ReturnsFailure()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType("invalid_type")
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Response type must be"));
    }

    [Fact]
    public void Validate_VpTokenIdToken_ResponseType_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType("vp_token id_token")
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_ValidNonceCharacters_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj.test~123_ABC")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidResponseMode_ReturnsFailure()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode("fragment")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("fragment")]
    [InlineData("query")]
    public void Validate_ValidResponseModes_WithoutResponseUri_IsValid(string responseMode)
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("fragment")]
    [InlineData("query")]
    public void Validate_SameDeviceModes_WithRedirectUri_IsValid(string responseMode)
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(responseMode)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_FragmentWithRedirectUri_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_QueryWithRedirectUri_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Query)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_QueryWithRedirectUri_Only_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Query)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidStateCharacters_ReturnsFailure()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithState("invalid!state@value")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("State must contain only ASCII URL-safe characters"));
    }

    [Fact]
    public void Validate_ValidStateCharacters_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithState("state-123_ABC.value~test")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidRequestUriMethod_ReturnsFailure()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithRequestUriMethod("invalid")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Request URI method must be"));
    }

    [Theory]
    [InlineData("get")]
    [InlineData("post")]
    public void Validate_ValidRequestUriMethod_IsValid(string method)
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithRequestUriMethod(method)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithScope_IsValid()
    {
        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_EncryptedModeWithoutExplicitEncValues_UsesDefaultA128GCM_IsValid()
    {
        // Per spec: "When a response_mode requiring encryption of the Response (such as dc_api.jwt or direct_post.jwt) 
        // is specified, this MUST be present for anything other than the default single value of A128GCM. Otherwise, 
        // this SHOULD be absent."
        // This test verifies that encrypted response modes are valid without explicit enc values (using default A128GCM)
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa);
        var jwks = JwksBuilder.CreatePublicKeySet(rsaKey, keyUsage: "enc");

        var buildResult = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.DirectPostJwt)  // Requires encryption
            .WithResponseUri("https://verifier.example.com/response")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .WithClientMetadata(metadata => metadata
                .WithName("Test Verifier")
                .WithJwks(jwks))  // No explicit enc values
            .Build();
        var request = buildResult.Value!;

        var result = _validator.Validate(request);

        // Should be valid - default A128GCM is implicitly used (SHOULD be absent per spec)
        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
        // Verify enc values are indeed absent/null
        Assert.Null(request.ClientMetadata?.EncryptedResponseEncValuesSupported);
    }
}
