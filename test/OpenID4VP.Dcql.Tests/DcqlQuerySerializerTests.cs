using System.Text.Json;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Query.Serialization;

namespace OpenID4VP.Dcql.Tests;

public class DcqlQuerySerializerTests
{
    [Fact]
    public async Task Serialize_SimpleQuery_ProducesValidJson()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b => b.WithDoctype(MdocFormats.MDL))
            .Build();

        // Act
        var json = DcqlQuerySerializer.Serialize(query);

        // Assert
        await Verify(json);
    }

    [Fact]
    public async Task Serialize_ComplexQuery_ProducesValidJson()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b =>
            {
                b.WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait")
                    .AddMdocClaim("given_name", MdocFormats.DefaultNamespace, "given_name");
            })
            .AddW3cVcCredential("diploma", b =>
            {
                b.AddTypeValues("VerifiableCredential", "UniversityDegreeCredential")
                    .AddClaim("degree_type", "credentialSubject", "degreeType")
                    .AddClaim("name", "credentialSubject", "name");
            })
            .Build();

        // Act
        var json = DcqlQuerySerializer.Serialize(query);

        // Assert
        await Verify(json);
    }

    [Fact]
    public async Task Serialize_Indented_ProducesFormattedJson()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b => b.WithDoctype(MdocFormats.MDL))
            .Build();

        // Act
        var json = DcqlQuerySerializer.Serialize(query, indented: true);

        // Assert
        await Verify(json);
    }

    [Fact]
    public async Task SerializeToUtf8Bytes_Query_ProducesBytes()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b => b.WithDoctype(MdocFormats.MDL))
            .Build();

        // Act
        var bytes = DcqlQuerySerializer.SerializeToUtf8Bytes(query);

        // Assert
        Assert.NotNull(bytes);
        Assert.NotEmpty(bytes);
        var json = System.Text.Encoding.UTF8.GetString(bytes);
        await Verify(json);
    }

    [Fact]
    public void Deserialize_ValidJson_ReturnsQuery()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("vc", b =>
            {
                b.AddTypeValues("VerifiableCredential", "TestCredential")
                    .AddClaim("claim1", "path", "to", "claim");
            })
            .Build();
        var json = DcqlQuerySerializer.Serialize(query);

        // Act
        var deserialized = DcqlQuerySerializer.Deserialize(json);

        // Assert
        Assert.NotNull(deserialized);
        Assert.NotNull(deserialized.Credentials);
        Assert.Single(deserialized.Credentials);
        
        var credential = deserialized.Credentials[0];
        Assert.Equal("vc", credential.Id);
    }

    [Fact]
    public void Deserialize_MdocCredential_ReturnsCorrectType()
    {
        // Arrange - use a query built with the builder to ensure valid JSON structure
        var builtQuery = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b =>
            {
                b.WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("given_name", MdocFormats.DefaultNamespace, "given_name");
            })
            .Build();
        
        var json = DcqlQuerySerializer.Serialize(builtQuery);

        // Act
        var query = DcqlQuerySerializer.Deserialize(json);

        // Assert
        Assert.NotNull(query);
        Assert.Single(query.Credentials);
        
        var credential = query.Credentials[0] as MdocCredentialQuery;
        Assert.NotNull(credential);
        Assert.Equal("mdl", credential.Id);
        Assert.Equal(MdocFormats.MDL, credential.Meta?.DoctypeValue);
    }

    [Fact]
    public void Deserialize_W3cVcCredential_ReturnsCorrectType()
    {
        // Arrange - use a query built with the builder to ensure valid JSON structure
        var builtQuery = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("diploma", b =>
            {
                b.AddTypeValues("VerifiableCredential", "DiplomaCredential")
                    .AddClaim("degree_type", "credentialSubject", "degreeType");
            })
            .Build();
        
        var json = DcqlQuerySerializer.Serialize(builtQuery);

        // Act
        var query = DcqlQuerySerializer.Deserialize(json);

        // Assert
        Assert.NotNull(query);
        Assert.Single(query.Credentials);
        
        var credential = query.Credentials[0] as W3cVcCredentialQuery;
        Assert.NotNull(credential);
        Assert.Equal("diploma", credential.Id);
    }

    [Fact]
    public void DeserializeFromUtf8Bytes_ValidBytes_ReturnsQuery()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b => b.WithDoctype(MdocFormats.MDL))
            .Build();
        var bytes = DcqlQuerySerializer.SerializeToUtf8Bytes(query);

        // Act
        var deserialized = DcqlQuerySerializer.DeserializeFromUtf8Bytes(bytes);

        // Assert
        Assert.NotNull(deserialized);
        Assert.NotNull(deserialized.Credentials);
        Assert.Single(deserialized.Credentials);
    }

    [Fact]
    public void Serialize_Deserialize_RoundTrip_PreservesData()
    {
        // Arrange
        var original = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b =>
            {
                b.WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait")
                    .RequireCryptographicHolderBinding(true)
                    .AddClaimSet("portrait", "given_name");
            })
            .AddW3cVcCredential("vc", b =>
            {
                b.AddTypeValues("VerifiableCredential", "TestVC")
                    .AddClaim("claim1", "path", "to", "claim")
                    .AddClaimSet("claim1", "claim2");
            })
            .AddCredentialSet(cs => cs.AddOption("mdl", "vc"))
            .Build();

        // Act
        var json = DcqlQuerySerializer.Serialize(original);
        var deserialized = DcqlQuerySerializer.Deserialize(json);

        // Assert
        Assert.Equal(original.Credentials.Count, deserialized.Credentials.Count);
        Assert.Equal(original.CredentialSets?.Count ?? 0, deserialized.CredentialSets?.Count ?? 0);
        
        // Check first credential
        var originalMdoc = original.Credentials[0] as MdocCredentialQuery;
        var deserializedMdoc = deserialized.Credentials[0] as MdocCredentialQuery;
        Assert.NotNull(originalMdoc);
        Assert.NotNull(deserializedMdoc);
        Assert.Equal(originalMdoc.Id, deserializedMdoc.Id);
        Assert.Equal(originalMdoc.Meta?.DoctypeValue, deserializedMdoc.Meta?.DoctypeValue);
    }

    [Fact]
    public void Serialize_NullQuery_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DcqlQuerySerializer.Serialize(null!));
    }

    [Fact]
    public void Deserialize_NullJson_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DcqlQuerySerializer.Deserialize(null!));
    }

    [Fact]
    public void Deserialize_EmptyJson_ThrowsJsonException()
    {
        // Act & Assert
        Assert.Throws<JsonException>(() => DcqlQuerySerializer.Deserialize(""));
    }

    [Fact]
    public void Deserialize_InvalidJson_ThrowsJsonException()
    {
        // Act & Assert
        Assert.Throws<JsonException>(() => DcqlQuerySerializer.Deserialize("{invalid json}"));
    }

    [Fact]
    public void Deserialize_MissingCredentials_ThrowsJsonException()
    {
        // Arrange
        var json = @"{}";

        // Act & Assert
        Assert.Throws<JsonException>(() => DcqlQuerySerializer.Deserialize(json));
    }

    [Fact]
    public void SerializeToUtf8Bytes_NullQuery_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DcqlQuerySerializer.SerializeToUtf8Bytes(null!));
    }

    [Fact]
    public void DeserializeFromUtf8Bytes_NullBytes_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => DcqlQuerySerializer.DeserializeFromUtf8Bytes(null!));
    }

    [Fact]
    public void GetDefaultOptions_ReturnsValidOptions()
    {
        // Act
        var options = DcqlQuerySerializer.GetDefaultOptions();

        // Assert
        Assert.NotNull(options);
        Assert.Equal(JsonNamingPolicy.SnakeCaseLower, options.PropertyNamingPolicy);
    }

    [Fact]
    public void Serialize_AuthorizationRequestScenario_ProducesCompactJson()
    {
        // This test demonstrates the real-world use case:
        // The dcql_query parameter in an Authorization Request needs to be compact
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", b =>
            {
                b.WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait");
            })
            .Build();

        // Act
        var json = DcqlQuerySerializer.Serialize(query, indented: false);

        // Assert - Compact JSON without unnecessary whitespace
        Assert.NotNull(json);
        Assert.DoesNotContain("\n", json);
        Assert.DoesNotContain("  ", json);
        
        // Should be valid for use in URL parameters
        Assert.True(json.Length > 0);
        Assert.StartsWith("{", json);
        Assert.EndsWith("}", json);
    }

    [Fact]
    public async Task Serialize_IdentityQueryWithSdJwtOnly_ProducesValidJson()
    {
        // This test demonstrates an identity query using SD-JWT only
        // Queries first name and last name from idcard, passport OR drivers license
        var query = DcqlQueryBuilder.Create()
            .AddDcSdJwtCredential("idcard", b =>
            {
                b.AddVctValues("pbdf-staging.pbdf.idcard")
                    .AddClaim("fn", "firstName")
                    .AddClaim("ln", "lastName");
            })
            .AddDcSdJwtCredential("passport", b =>
            {
                b.AddVctValues("pbdf-staging.pbdf.passport")
                    .AddClaim("fn", "firstName")
                    .AddClaim("ln", "lastName");
            })
            .AddDcSdJwtCredential("drivers_license", b =>
            {
                b.AddVctValues("pbdf-staging.pbdf.drivinglicence")
                    .AddClaim("fn", "firstName")
                    .AddClaim("ln", "lastName");
            })
            .AddCredentialSet(cs => cs.AddOption("idcard", "passport", "drivers_license"))
            .Build();

        // Assert build produced credential sets
        Assert.NotNull(query.CredentialSets);
        Assert.Single(query.CredentialSets);
        
        // Act
        var json = DcqlQuerySerializer.Serialize(query, true);

        // Assert
        await Verify(json);
        
        // Verify it's valid JSON and can be deserialized
        var deserialized = DcqlQuerySerializer.Deserialize(json);
        Assert.NotNull(deserialized);
        Assert.Equal(3, deserialized.Credentials.Count);
        Assert.NotNull(deserialized.CredentialSets);
        Assert.Single(deserialized.CredentialSets);
        
        // Verify all credentials are SD-JWT type
        foreach (var credential in deserialized.Credentials)
        {
            Assert.IsType<DcSdJwtCredentialQuery>(credential);
        }
    }
}
