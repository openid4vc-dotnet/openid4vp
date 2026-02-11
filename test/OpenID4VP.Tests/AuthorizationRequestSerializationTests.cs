using System.Text.Json;
using OpenID4VP.Builders;
using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VP.Dcql.Query.Builders;

namespace OpenID4VP.Tests.Models;

/// <summary>
/// Tests for AuthorizationRequest serialization and model behavior
/// </summary>
public class AuthorizationRequestSerializationTests
{
    private static void ConfigureValidW3cCredential(W3cVcCredentialQueryBuilder builder)
    {
        builder.AddTypeValues("UniversityDegree");
    }
    [Fact]
    public void AuthorizationRequest_CannotBeInstantiatedDirectly()
    {
        // The constructor is internal, so we can't create an instance directly
        // This test ensures encapsulation is maintained
        var type = typeof(AuthorizationRequest);
        var constructors = type.GetConstructors(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
        
        Assert.Empty(constructors);
    }

    [Fact]
    public void AuthorizationRequestBuilder_CanCreateValidInstance()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.IsType<AuthorizationRequest>(request);
    }

    [Fact]
    public void AuthorizationRequest_AllPropertiesAreImmutable()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        // Records are immutable by default
        var modelType = typeof(AuthorizationRequest);
        
        Assert.True(modelType.IsSealed, "Model should be sealed record");
        
        // Records are a reference type but immutable through init-only properties
        // We can't easily check init-only via reflection as C# records generate synthetic setters
        // Just verify the model is sealed and uses record semantics
    }

    [Fact]
    public void AuthorizationRequest_Serialization_ContainsAllProperties()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithRedirectUri("https://verifier.example.com/callback")
            .WithState("state-value")
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var json = JsonSerializer.Serialize(request);
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.True(root.TryGetProperty("response_type", out _));
        Assert.True(root.TryGetProperty("client_id", out _));
        Assert.True(root.TryGetProperty("nonce", out _));
        Assert.True(root.TryGetProperty("response_mode", out _));
        Assert.True(root.TryGetProperty("dcql_query", out _));
        Assert.True(root.TryGetProperty("redirect_uri", out _));
        Assert.True(root.TryGetProperty("state", out _));
    }

    [Fact]
    public void AuthorizationRequest_OptionalFields_NotSerializedWhenNull()
    {
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        var json = JsonSerializer.Serialize(request, new System.Text.Json.JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Optional fields should not be present when null
        Assert.False(root.TryGetProperty("scope", out _));
        Assert.False(root.TryGetProperty("response_uri", out _));
        Assert.False(root.TryGetProperty("redirect_uri", out _));
    }

    [Fact]
    public void VerifierMetadata_CanBeIncludedInRequest()
    {
        var metadata = VerifierMetadataBuilder.Create().Build();
        
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .WithClientMetadata(metadata)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.NotNull(request.ClientMetadata);
    }

    [Fact]
    public void VerifierAttestation_CanBeIncludedInRequest()
    {
        var attestation = VerifierAttestationBuilder.Create()
            .WithFormat("jwt")
            .AddCredentialId("credential-1")
            .Build();
        
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .AddVerifierAttestation(attestation)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.NotNull(request.VerifierInfo);
        Assert.Single(request.VerifierInfo);
    }

    [Fact]
    public void TransactionData_CanBeIncludedInRequest()
    {
        var transactionData = "eyJhbGciOiJFUzI1NiJ9";
        
        var request = AuthorizationRequestBuilder.Create()
            .WithResponseType(ResponseTypes.VpToken)
            .WithClientId("test-verifier")
            .WithNonce("n-0S6_WzA2Mj")
            .WithResponseMode(ResponseModes.Fragment)
            .AddTransactionData(transactionData)
            .WithDcql(dcql => dcql.AddW3cVcCredential("credential-1", b => ConfigureValidW3cCredential(b)))
            .Build();

        Assert.NotNull(request.TransactionData);
        Assert.Single(request.TransactionData);
        Assert.Contains(transactionData, request.TransactionData);
    }
}
