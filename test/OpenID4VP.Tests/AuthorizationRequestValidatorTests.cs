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

    private AuthorizationRequest CreateValidRequest() =>
        AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

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
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType("invalid_type")
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Response type must be"));
    }

    [Fact]
    public void Validate_VpTokenIdToken_ResponseType_IsValid()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType("vp_token id_token")
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidNonceCharacters_ReturnsFailure()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("invalid!nonce@with#special$chars")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Nonce must contain only ASCII URL-safe characters"));
    }

    [Fact]
    public void Validate_ValidNonceCharacters_IsValid()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj.test~123_ABC")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidResponseMode_ReturnsFailure()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode("invalid_mode")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Response mode must be one of"));
    }

    [Theory]
    [InlineData("fragment")]
    [InlineData("query")]
    public void Validate_ValidResponseModes_WithoutResponseUri_IsValid(string responseMode)
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(responseMode)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("direct_post")]
    [InlineData("direct_post.jwt")]
    public void Validate_DirectPostModes_WithResponseUri_IsValid(string responseMode)
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(responseMode)
            .WithResponseUri("https://verifier.example.com/response")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_DirectPostWithoutResponseUri_ReturnsFailure()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.DirectPost)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Response URI is required"));
    }

    [Fact]
    public void Validate_DirectPostJwtWithoutResponseUri_ReturnsFailure()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.DirectPostJwt)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Response URI is required"));
    }

    [Fact]
    public void Validate_DirectPostWithResponseUri_IsValid()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.DirectPost)
            .WithResponseUri("https://verifier.example.com/response")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidStateCharacters_ReturnsFailure()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithState("invalid!state@value")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("State must contain only ASCII URL-safe characters"));
    }

    [Fact]
    public void Validate_ValidStateCharacters_IsValid()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithState("state-123_ABC.value~test")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_InvalidRequestUriMethod_ReturnsFailure()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRequestUriMethod("invalid")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Request URI method must be"));
    }

    [Theory]
    [InlineData("get")]
    [InlineData("post")]
    public void Validate_ValidRequestUriMethod_IsValid(string method)
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRequestUriMethod(method)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithScope_IsValid()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithScope("com.example.credential_presentation")
            .Build();

        var result = _validator.Validate(request);

        Assert.True(result.IsValid);
    }
}
