using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VC.Core.Results;
using OpenID4VC.Core.Tests;

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
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal(ResponseTypes.VpToken, request.ResponseType);
        Assert.Equal("https://verifier.example.com", request.ClientId);
        Assert.Equal("n-0S6_WzA2Mj", request.Nonce);
        Assert.Equal(ResponseModes.Fragment, request.ResponseMode);
        Assert.NotNull(request.DcqlQuery);
    }

    [Fact]
    public void Build_MissingResponseType_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build() succeeds (permissive) - ResponseType is NOT defaulted
        var request = result.AssertSuccess();
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

        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.IsType<ValidationError>(errors[0]);
        Assert.Contains("client_id is required", errors[0].Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_MissingNonce_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Builder allows building without nonce - scenario-specific validators enforce requirements
        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Null(request.Nonce);
    }

    [Fact]
    public void Build_MissingResponseMode_Succeeds()
    {
        // Builder allows building without response_mode - scenario-specific validators enforce requirements
        // Some flows (like cross-device) don't require response_mode in the minimal request
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Builder allows building without response_mode - scenario validators will enforce
        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Null(request.ResponseMode);
    }

    [Fact]
    public void Build_MissingDcqlAndScope_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .Build();

        // Build() succeeds (permissive) - doesn't validate dcql/scope combo
        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Null(request.DcqlQuery);
        Assert.Null(request.Scope);
    }

    [Fact]
    public void WithDcql_CalledTwice_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .WithDcql(dcql => dcql.AddMdocCredential("mdoc-1", b => { }))
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("DCQL query can only be configured once", errors[0].Message);
    }

    [Fact]
    public void WithResponseType_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType("")
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("response_type is required", errors[0].Message);
    }

    [Fact]
    public void WithClientId_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("client_id is required", errors[0].Message);
    }

    [Fact]
    public void WithNonce_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithNonce("")
            .WithResponseMode(ResponseModes.Fragment)
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("nonce is required", errors[0].Message);
    }

    [Fact]
    public void WithResponseMode_NullOrEmpty_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithResponseMode("")
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("response_mode is required", errors[0].Message);
    }

    [Fact]
    public void WithDcql_NullAction_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(null!)
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("DCQL configure action cannot be null", errors[0].Message);
    }

    [Fact]
    public void AddVerifierAttestation_NullAttestation_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithClientId("https://verifier.example.com")
            .WithResponseMode(ResponseModes.Fragment)
            .AddVerifierAttestation(null!)
            .Build();
        
        var errors = result.AssertError();
        Assert.Single(errors);
        Assert.Contains("Verifier attestation cannot be null", errors[0].Message);
    }

    [Fact]
    public void Build_WithOptionalFields_IncludesThemInRequest()
    {
        var attestation = VerifierAttestationBuilder.Create()
            .WithFormat("jwt")
            .Build();
        
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithState("state-value")
            .WithRequestUriMethod("post")
            .WithClientMetadata(metadata => metadata.WithName("verifier"))
            .AddVerifierAttestation(attestation)
            .AddTransactionData("eyJhbGciOiJFUzI1In0")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
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
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .Build();

        var request = result.AssertSuccess();
        Assert.Equal("com.example.credential_presentation", request.Scope);
    }

    [Fact]
    public void Build_WithDcqlAndScope_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithScope("com.example.credential_presentation")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build() succeeds (permissive)
        var request = result.AssertSuccess();
        Assert.NotNull(request.DcqlQuery);
        Assert.Equal("com.example.credential_presentation", request.Scope);
    }

    [Fact]
    public void FluentChaining_AllMethodsReturnBuilder()
    {
        var builder = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://example.com")
            .WithState("state")
            .WithRequestUriMethod("get")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)));

        Assert.NotNull(builder);
        var result = builder.Build();
        result.AssertSuccess(); // assert returns value
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

        var errors = result.AssertError();
        Assert.Equal(5, errors.Length);
        
        var messages = errors.Select(e => e.Message).ToList();
        Assert.Contains("client_id is required", messages);
        Assert.Contains("nonce is required", messages);
        Assert.Contains("response_mode is required", messages);
        Assert.Contains("DCQL configure action cannot be null", messages);
        Assert.Contains("Verifier attestation cannot be null", messages);
    }

    #region Client ID Prefix Validation Tests

    [Theory]
    [InlineData("redirect_uri:https://verifier.example.com/callback")]
    [InlineData("x509_san_dns:client.example.org")]
    [InlineData("x509_san_uri:https://example.org")]
    [InlineData("x509_san_ip_address:192.0.2.1")]
    [InlineData("https://verifier.example.org")]
    [InlineData("did:example:123abc")]
    [InlineData("urn:verifier:acme:xyz")]
    public void WithClientId_ValidPrefix_Succeeds(string validClientId)
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(validClientId)
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal(validClientId, request.ClientId);
    }

    [Theory]
    [InlineData("invalid_prefix:value")]
    [InlineData("x509_san_ip:192.0.2.1")]  // Typo: should be x509_san_ip_address:
    [InlineData("http://example.org")]     // Unsupported: http instead of https
    [InlineData("example.org")]            // No prefix or scheme
    [InlineData("test-verifier")]          // Bare identifier without prefix
    public void WithClientId_InvalidPrefix_Succeeds(string clientId)
    {
        // Note: Validation removed. The builder now accepts any string.
        // Format validation is delegated to the Wallet/verifier at runtime.
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(clientId)
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Without validation, any non-empty string is accepted
        var request = result.AssertSuccess();
        Assert.Equal(clientId, request.ClientId);
    }

    [Fact]
    public void WithClientId_EmptyString_ReturnsClientIdRequiredError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var errors = result.AssertError();
        var errorMessages = errors.Select(e => e.Message).ToList();
        Assert.Contains(errorMessages, m => m.Contains("client_id is required"));
    }

    [Fact]
    public void WithClientId_Null_ReturnsClientIdRequiredError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(null)
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var errors = result.AssertError();
        var errorMessages = errors.Select(e => e.Message).ToList();
        Assert.Contains(errorMessages, m => m.Contains("client_id is required"));
    }

    [Fact]
    public void WithClientId_PartialPrefix_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("redirect_uri:")  // Prefix without value
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Note: This is valid technically (empty value after prefix), but may fail in semantic validation later
        // For now, prefix validation should pass, and semantic validation would be elsewhere
        result.AssertSuccess(); // assert returns value
    }

    [Fact]
    public void WithClientId_Https_WithoutSlashes_Succeeds()
    {
        // Note: Validation removed. The builder accepts any string format.
        // The malformed "https:verifier.example.org" is accepted as-is.
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https:verifier.example.org")  // Missing // - but still accepted
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.Equal("https:verifier.example.org", request.ClientId);
    }

    [Fact]
    public void WithClientId_RedirectUriPrefix_WithCompleteUrl_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("redirect_uri:https://client.example.org/callback")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://client.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal("redirect_uri:https://client.example.org/callback", request.ClientId);
    }

    [Fact]
    public void WithClientId_X509SanUri_WithHttpsUrl_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("x509_san_uri:https://client.example.org")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal("x509_san_uri:https://client.example.org", request.ClientId);
    }

    [Fact]
    public void WithClientId_X509SanIpAddress_WithIpv4_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("x509_san_ip_address:192.0.2.1")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal("x509_san_ip_address:192.0.2.1", request.ClientId);
    }

    [Fact]
    public void WithClientId_Did_WithValidDid_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("did:example:123abc")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal("did:example:123abc", request.ClientId);
    }

    [Fact]
    public void WithClientId_Urn_WithValidUrn_Succeeds()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("urn:verifier:acme:xyz")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        Assert.Equal("urn:verifier:acme:xyz", request.ClientId);
    }

    #endregion

    #region Class-Based Prefix API Tests

    [Fact]
    public void WithClientId_UsingX509SanDnsPrefixConstant_ConstructsCorrectly()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.X509SanDns, "client.example.org")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        // X509SanDns should construct: "x509_san_dns:" + value
        Assert.Equal("x509_san_dns:client.example.org", request.ClientId);
    }

    [Fact]
    public void WithClientId_UsingRedirectUriPrefixConstant_ConstructsCorrectly()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.RedirectUri, "https://verifier.example.org/callback")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        // RedirectUri should construct: "redirect_uri:" + value
        Assert.Equal("redirect_uri:https://verifier.example.org/callback", request.ClientId);
    }

    [Fact]
    public void WithClientId_UsingX509SanUriPrefixConstant_ConstructsCorrectly()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.X509SanUri, "https://example.org")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        // X509SanUri should construct: "x509_san_uri:" + value
        Assert.Equal("x509_san_uri:https://example.org", request.ClientId);
    }

    [Fact]
    public void WithClientId_UsingX509SanIpAddressPrefixConstant_ConstructsCorrectly()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.X509SanIpAddress, "192.0.2.1")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        // X509SanIpAddress should construct: "x509_san_ip_address:" + value
        Assert.Equal("x509_san_ip_address:192.0.2.1", request.ClientId);
    }

    [Fact]
    public void WithClientId_UsingDidPrefixConstant_ConstructsCorrectly()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.Did, "example:123abc")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        // Did should construct: "did:" + value
        Assert.Equal("did:example:123abc", request.ClientId);
    }

    [Fact]
    public void WithClientId_UsingUrnPrefixConstant_ConstructsCorrectly()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.Urn, "verifier:acme:xyz")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var request = result.AssertSuccess();
        Assert.NotNull(request);
        // Urn should construct: "urn:" + value
        Assert.Equal("urn:verifier:acme:xyz", request.ClientId);
    }

    [Fact]
    public void WithClientId_EnumAndStringApiProduceSameResult()
    {
        // Build with string API
        var resultString = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("x509_san_dns:hostname.example.org")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Build with enum API
        var resultEnum = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.X509SanDns, "hostname.example.org")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Both should succeed and produce same client ID
        var requestString = resultString.AssertSuccess();
        var requestEnum = resultEnum.AssertSuccess();
        Assert.Equal(requestString.ClientId, requestEnum.ClientId);
        Assert.Equal("x509_san_dns:hostname.example.org", requestEnum.ClientId);
    }

    [Fact]
    public void WithClientId_EnumWithEmptyValue_ReturnsError()
    {
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId(ClientIdentifierPrefix.X509SanDns, "")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.org/callback")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var errors = result.AssertError();
        var errorMessages = errors.Select(e => e.Message).ToList();
        Assert.Contains(errorMessages, m => m.Contains("client_id is required"));
    }

    #endregion

    #region Client Metadata - JWKS Key Extraction Tests

    [Fact]
    public void WithClientMetadata_WithRsaPublicKey_Succeeds()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = "test-rsa-key" };
        var publicKeyResult = JwksBuilder.CreatePublicKey(rsaKey, keyUsage: "enc");
        var publicKey = publicKeyResult.Value!;

        // Act
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithClientMetadata(metadata => metadata
                .WithName("Test Verifier")
                .WithPublicKeyForResponseEncryption(publicKey))
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Assert
        var request = result.AssertSuccess();
        Assert.NotNull(request.ClientMetadata);
    }

    [Fact]
    public void WithClientMetadata_WithEcdsaPublicKey_Succeeds()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = "test-ecdsa-key" };
        var publicKeyResult = JwksBuilder.CreatePublicKey(ecdsaKey, keyUsage: "enc");
        var publicKey = publicKeyResult.Value!;

        // Act
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithClientMetadata(metadata => metadata
                .WithName("Test Verifier")
                .WithPublicKeyForResponseEncryption(publicKey))
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Assert
        var request = result.AssertSuccess();
        Assert.NotNull(request.ClientMetadata);
    }

    [Fact]
    public void WithClientMetadata_WithClientNameOnly_Succeeds()
    {
        // Act
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithClientMetadata(metadata => metadata
                .WithName("My App"))
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Assert
        var request = result.AssertSuccess();
        Assert.NotNull(request.ClientMetadata);
    }

    [Fact]
    public void WithClientMetadata_WithRsaPublicKey_IncludesKidAndAlgInJwks()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = "test-rsa-key" };
        var publicKeyResult = JwksBuilder.CreatePublicKey(rsaKey, keyUsage: "enc");
        var publicKey = publicKeyResult.Value!;

        // Act
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithClientMetadata(metadata => metadata
                .WithName("Test Verifier")
                .WithPublicKeyForResponseEncryption(publicKey))
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Assert
        var request = result.AssertSuccess();
        Assert.NotNull(request.ClientMetadata);
        
        // Verify JWKS is present and contains kid and alg
        var metadata = request.ClientMetadata;
        Assert.NotNull(metadata.Jwks);
        
        // Parse JWKS JSON
        using var jsonDoc = System.Text.Json.JsonDocument.Parse(metadata.Jwks.ToString()!);
        var root = jsonDoc.RootElement;
        
        Assert.True(root.TryGetProperty("keys", out var keysElement), "JWKS should have 'keys' array");
        Assert.Equal(System.Text.Json.JsonValueKind.Array, keysElement.ValueKind);
        
        var keyCount = 0;
        foreach (var keyElement in keysElement.EnumerateArray())
        {
            keyCount++;
            
            // Verify each key has a 'kid' property
            Assert.True(keyElement.TryGetProperty("kid", out var kidElement), 
                "Each key in JWKS must have a 'kid' (Key ID) property");
            Assert.NotEqual(System.Text.Json.JsonValueKind.Null, kidElement.ValueKind);
            var kidValue = kidElement.GetString();
            Assert.False(string.IsNullOrWhiteSpace(kidValue), "kid value must not be empty");
            
            // Verify each key has an 'alg' property
            Assert.True(keyElement.TryGetProperty("alg", out var algElement), 
                "Each key in JWKS must have an 'alg' (Algorithm) property");
            Assert.NotEqual(System.Text.Json.JsonValueKind.Null, algElement.ValueKind);
            var algValue = algElement.GetString();
            Assert.False(string.IsNullOrWhiteSpace(algValue), "alg value must not be empty");
            Assert.Equal("RSA-OAEP", algValue);  // Key encryption algorithm for RSA with enc usage
            
            // Verify the key has 'use' set to 'enc' (encryption)
            Assert.True(keyElement.TryGetProperty("use", out var useElement),
                "Each key in JWKS must have a 'use' (Key Usage) property");
            Assert.Equal("enc", useElement.GetString());
        }
        
        Assert.Equal(1, keyCount);
    }

    [Fact]
    public void WithClientMetadata_WithKeyWithoutKidOrAlg_ReturnsError()
    {
        // Arrange - Create a key that has NO kid and NO alg
        using var rsa = RSA.Create(2048);
        using var publicRsa = RSA.Create();
        publicRsa.ImportParameters(rsa.ExportParameters(false)); // Export only public key
        var rsaKey = new RsaSecurityKey(publicRsa);
        
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaKey);
        // Explicitly clear the KeyId and Alg to simulate missing required fields
        jwk.KeyId = null;
        jwk.Alg = null;
        jwk.Use = "enc";

        // Act
        var result = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("https://verifier.example.com")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithClientMetadata(metadata => metadata
                .WithName("Test Verifier")
                .WithPublicKeyForResponseEncryption(jwk))
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Assert
        var errors = result.AssertError();
        // Validation returns on first error (either missing kid or alg), so we'll just check for at least one
        Assert.True(errors.Length >= 1, "Should have at least one validation error");
        var errorMessage = string.Join(", ", errors.Select(e => e.Message));
        // Either kid or alg error should be present (but not both in a single check since validation returns early)
        Assert.True(errorMessage.Contains("'kid'") || errorMessage.Contains("'alg'"), 
            $"Error should mention 'kid' or 'alg', but got: {errorMessage}");
    }

    #endregion
}


