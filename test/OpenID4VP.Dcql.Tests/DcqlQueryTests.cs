using System.Text.Json;
using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Query.Validators;

namespace OpenID4VP.Dcql.Tests;

public class DcqlQueryTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    [Fact]
    public void CreateSimpleSdJwtVcQuery_ShouldSucceed()
    {
        // Arrange & Act
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("identity_credential", credential =>
            {
                credential
                    .AddVctValues("https://credentials.example.com/identity")
                    .AddClaim("last_name", "last_name")
                    .AddClaim("first_name", "first_name");
            })
            .Build();

        // Assert
        Assert.NotNull(query);
        Assert.Single(query.Credentials);
        
        var credential = query.Credentials[0] as SdJwtVcCredentialQuery;
        Assert.NotNull(credential);
        Assert.Equal("identity_credential", credential.Id);
        Assert.Equal("vc+sd-jwt", credential.Format);
        Assert.Equal(2, credential.Claims?.Count ?? 0);
    }

    [Fact]
    public void ValidateQuery_WithValidQuery_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("test_credential", _ => { })
            .Build();

        var validator = new DcqlQueryValidator();

        // Act
        var result = validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void ValidateQuery_WithDuplicateIds_ShouldFail()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("duplicate", _ => { })
            .AddSdJwtVcCredential("duplicate", _ => { })
            .Build();

        var validator = new DcqlQueryValidator();

        // Act
        var result = validator.Validate(query);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains(result.Errors, e => e.Message.Contains("unique"));
    }

    [Fact]
    public void SerializeQuery_ShouldProduceValidJson()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddDcSdJwtCredential("my_credential", credential =>
            {
                credential
                    .AddVctValues("https://credentials.example.com/identity_credential")
                    .AddClaim("last_name", "last_name")
                    .AddClaim("first_name", "first_name")
                    .AddClaim("address", "address", "street_address");
            })
            .Build();

        // Act
        var json = JsonSerializer.Serialize(query, JsonOptions);

        // Assert - Serialization
        Assert.NotNull(json);
        Assert.Contains("\"credentials\":", json);
        Assert.Contains("\"my_credential\"", json);
        Assert.Contains("\"format\":", json);
        Assert.Contains("\"last_name\"", json);
        
        // Assert - Full round-trip deserialization now works with JsonPropertyOrder!
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, JsonOptions);
        Assert.NotNull(deserialized);
        Assert.Single(deserialized.Credentials);
        Assert.Equal("my_credential", deserialized.Credentials[0].Id);
        Assert.Equal("dc+sd-jwt", deserialized.Credentials[0].Format);
        
        // Verify it's the correct derived type
        var dcSdJwt = Assert.IsType<DcSdJwtCredentialQuery>(deserialized.Credentials[0]);
        Assert.NotNull(dcSdJwt.Claims);
        Assert.Equal(3, dcSdJwt.Claims.Count);
        Assert.Equal("last_name", dcSdJwt.Claims[0].Path[0].AsString);
    }

    [Fact]
    public void MdocClaimQuery_WithPath_ShouldWork()
    {
        // Arrange & Act
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential.AddMdocClaim("family_name", MdocFormats.DefaultNamespace, "family_name", intentToRetain: false);
            })
            .Build();

        var claim = Assert.IsType<MdocCredentialQuery>(query.Credentials[0]).Claims![0];

        // Assert
        Assert.Equal(MdocFormats.DefaultNamespace, claim.NamespaceValue);
        Assert.Equal("family_name", claim.ElementValue);
        Assert.False(claim.IntentToRetain);
    }

    [Fact]
    public void ClaimPathComponent_AllTypes_ShouldWork()
    {
        // String component
        var stringComp = new ClaimPathComponent("address");
        Assert.True(stringComp.IsString);
        Assert.Equal("address", stringComp.AsString);

        // Integer component
        var intComp = new ClaimPathComponent(1);
        Assert.True(intComp.IsInteger);
        Assert.Equal(1, intComp.AsInteger);

        // Null component (all array elements)
        var nullComp = new ClaimPathComponent();
        Assert.True(nullComp.IsNull);
    }

    [Fact]
    public void TrustedAuthority_Aki_ShouldValidateBase64Url()
    {
        // Valid base64url
        var validAki = new AuthorityKeyIdentifierTrustAuthority
        {
            Values = new NonEmptyArray<string>("s9tIpPmhxdiuNkHMEWNpYim8S8Y")
        };
        
        Assert.NotNull(validAki);

        // Invalid base64url should throw
        Assert.Throws<ArgumentException>(() =>
        {
            _ = new AuthorityKeyIdentifierTrustAuthority
            {
                Values = new NonEmptyArray<string>("not-valid-base64url!")
            };
        });
    }
}
