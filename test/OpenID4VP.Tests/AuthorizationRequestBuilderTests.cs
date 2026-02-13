using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VC.Core.Results;

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
    public void Build_WithAllRequiredFields_ReturnsSuccess()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request);
        Assert.Equal(ResponseTypes.VpToken, request.ResponseType);
        Assert.Equal("test-verifier", request.ClientId);
        Assert.Equal("n-0S6_WzA2Mj", request.Nonce);
        Assert.Equal(ResponseModes.Fragment, request.ResponseMode);
        Assert.NotNull(request.DcqlQuery);
    }

    [Fact]
    public void Build_MissingResponseType_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build() succeeds (permissive) - ResponseType is NOT defaulted
        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request);
        Assert.Null(request.ResponseType);  // NO default value anymore
    }

    [Fact]
    public void Build_MissingClientId_ReturnsFailure()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ValidationError>(result.Errors[0]);
        Assert.Contains("client_id is required", result.Errors[0].Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_MissingNonce_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build() succeeds (permissive) - Nonce is NOT defaulted
        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request);
        Assert.Null(request.Nonce);  // NO default value anymore
    }

    [Fact]
    public void Build_MissingResponseMode_ReturnsFailure()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ValidationError>(result.Errors[0]);
        Assert.Contains("response_mode is required", result.Errors[0].Message);
    }

    [Fact]
    public void Build_MissingDcqlAndScope_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .Build();

        // Build() succeeds (permissive) - doesn't validate dcql/scope combo
        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request);
        Assert.Null(request.DcqlQuery);
        Assert.Null(request.Scope);
    }

    [Fact]
    public void WithDcql_CalledTwice_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .WithDcql(dcql => dcql.AddMdocCredential("mdoc-1", b => { }))
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("DCQL query can only be configured once", result.Errors[0].Message);
    }

    [Fact]
    public void WithResponseType_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType("")
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("response_type is required", result.Errors[0].Message);
    }

    [Fact]
    public void WithClientId_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("client_id is required", result.Errors[0].Message);
    }

    [Fact]
    public void WithNonce_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithNonce("")
            .WithResponseMode(ResponseModes.Fragment)
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("nonce is required", result.Errors[0].Message);
    }

    [Fact]
    public void WithResponseMode_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithResponseMode("")
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("response_mode is required", result.Errors[0].Message);
    }

    [Fact]
    public void WithDcql_NullAction_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(null!)
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("DCQL configure action cannot be null", result.Errors[0].Message);
    }

    [Fact]
    public void AddVerifierAttestation_NullAttestation_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("test-verifier")
            .WithResponseMode(ResponseModes.Fragment)
            .AddVerifierAttestation(null!)
            .Build();
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.Contains("Verifier attestation cannot be null", result.Errors[0].Message);
    }

    [Fact]
    public void Build_WithOptionalFields_IncludesThemInRequest()
    {
        var attestation = VerifierAttestationBuilder.Create()
            .WithFormat("jwt")
            .Build();
        
        var result = AuthorizationRequestBuilder.Create()
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

        Assert.True(result.IsSuccess);
        var request = result.Value;
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
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .Build();

        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.Equal("com.example.credential_presentation", request.Scope);
    }

    [Fact]
    public void Build_WithDcqlAndScope_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build() succeeds (permissive)
        Assert.True(result.IsSuccess);
        var request = result.Value;
        Assert.NotNull(request.DcqlQuery);
        Assert.Equal("com.example.credential_presentation", request.Scope);
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
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Build_MultipleErrors_ReturnsAllTogether()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("")           // Error: ClientId required
            .WithNonce("")              // Error: Nonce required
            .WithResponseMode("")       // Error: ResponseMode required
            .WithDcql(null!)            // Error: DCQL configure cannot be null
            .AddVerifierAttestation(null!)  // Error: Attestation cannot be null
            .Build();

        Assert.False(result.IsSuccess);
        Assert.Equal(5, result.Errors.Count);
        
        var messages = result.Errors.Select(e => e.Message).ToList();
        Assert.Contains("client_id is required", messages);
        Assert.Contains("nonce is required", messages);
        Assert.Contains("response_mode is required", messages);
        Assert.Contains("DCQL configure action cannot be null", messages);
        Assert.Contains("Verifier attestation cannot be null", messages);
    }
}
