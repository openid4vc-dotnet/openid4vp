using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Dcql.Query.Builders;

namespace OpenID4VP.Tests.Builders;

/// <summary>
/// Tests for AuthorizationRequestBuilder
/// </summary>
public class AuthorizationRequestBuilderTests
{
    private static void ConfigureValidW3cCredential(W3cVcCredentialQueryBuilder builder)
    {
        builder.AddTypeValues("UniversityDegree");
    }

    [Fact]
    public void Create_ReturnsNewBuilder()
    {
        var builder = AuthorizationRequestBuilder.Create();
        Assert.NotNull(builder);
    }

    [Fact]
    public void Build_WithAllRequiredFields_ReturnsValidRequest()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.NotNull(request);
        Assert.Equal(ResponseTypes.VpToken, request.ResponseType);
        Assert.Equal("test-verifier", request.ClientId);
        Assert.Equal("n-0S6_WzA2Mj", request.Nonce);
        Assert.Equal(ResponseModes.Fragment, request.ResponseMode);
        Assert.NotNull(request.DcqlQuery);
    }

    [Fact]
    public void Build_MissingResponseType_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("response_type is required", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_MissingClientId_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("client_id is required", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_MissingNonce_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Nonce is required", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_MissingResponseMode_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Response mode is required", ex.Message);
    }

    [Fact]
    public void Build_MissingDcqlAndScope_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback");

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Either dcql_query or scope must be set", ex.Message);
    }

    [Fact]
    public void WithDcql_CalledTwice_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            builder.WithDcql(dcql => dcql.AddMdocCredential("mdoc-1", b => { })));
        
        Assert.Contains("DCQL query can only be set once", ex.Message);
    }

    [Fact]
    public void WithResponseType_NullOrEmpty_ThrowsArgumentException()
    {
        var builder = AuthorizationRequestBuilder.Create();
        
        var ex = Assert.Throws<ArgumentException>(() => builder.WithResponseType(""));
        Assert.Contains("Response type cannot be null or empty", ex.Message);
    }

    [Fact]
    public void WithClientId_NullOrEmpty_ThrowsArgumentException()
    {
        var builder = AuthorizationRequestBuilder.Create();
        
        var ex = Assert.Throws<ArgumentException>(() => builder.WithClientId(""));
        Assert.Contains("Client ID cannot be null or empty", ex.Message);
    }

    [Fact]
    public void WithNonce_NullOrEmpty_ThrowsArgumentException()
    {
        var builder = AuthorizationRequestBuilder.Create();
        
        var ex = Assert.Throws<ArgumentException>(() => builder.WithNonce(""));
        Assert.Contains("Nonce cannot be null or empty", ex.Message);
    }

    [Fact]
    public void WithResponseMode_NullOrEmpty_ThrowsArgumentException()
    {
        var builder = AuthorizationRequestBuilder.Create();
        
        var ex = Assert.Throws<ArgumentException>(() => builder.WithResponseMode(""));
        Assert.Contains("Response mode cannot be null or empty", ex.Message);
    }

    [Fact]
    public void WithDcql_NullAction_ThrowsArgumentNullException()
    {
        var builder = AuthorizationRequestBuilder.Create();
        
        var ex = Assert.Throws<ArgumentNullException>(() => builder.WithDcql(null!));
        Assert.Equal("configure", ex.ParamName);
    }

    [Fact]
    public void AddVerifierAttestation_NullAttestation_ThrowsArgumentNullException()
    {
        var builder = AuthorizationRequestBuilder.Create();
        
        var ex = Assert.Throws<ArgumentNullException>(() => builder.AddVerifierAttestation(null!));
        Assert.Equal("attestation", ex.ParamName);
    }

    [Fact]
    public void Build_WithOptionalFields_IncludesThemInRequest()
    {
        var attestation = VerifierAttestationBuilder.Create()
            .WithFormat("jwt")
            .Build();
        
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithState("state-value")
            .WithRequestUriMethod("post")
            .WithClientMetadata(VerifierMetadataBuilder.Create().Build())
            .AddVerifierAttestation(attestation)
            .AddTransactionData("eyJhbGciOiJFUzI1In0")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.Equal("https://verifier.example.com/callback", request.RedirectUri);
        Assert.Equal("state-value", request.State);
        Assert.Equal("post", request.RequestUriMethod);
        Assert.NotNull(request.ClientMetadata);
        Assert.NotNull(request.VerifierInfo);
        Assert.Single(request.VerifierInfo);
        Assert.NotNull(request.TransactionData);
        Assert.Single(request.TransactionData);
    }

    [Fact]
    public void Build_WithScope_SetsScope()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .Build();

        Assert.Equal("com.example.credential_presentation", request.Scope);
    }

    [Fact]
    public void Build_WithDcqlAndScope_ThrowsInvalidOperationException()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.Contains("Only one of dcql_query or scope can be set", ex.Message);
    }

    [Fact]
    public void FluentChaining_AllMethodsReturnBuilder()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://example.com")
            .WithState("state")
            .WithRequestUriMethod("get")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        Assert.NotNull(builder);
        var result = builder.Build();
        Assert.NotNull(result);
    }
}
