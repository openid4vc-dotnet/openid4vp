using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;
using System.Text.Json;

namespace OpenID4VP.Dcql.Tests;

public class FluentApiTests
{
    [Fact]
    public void FluentApi_BuildSimpleQuery_ShouldWork()
    {
        // Act
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("driver_license", credential =>
            {
                credential
                    .AddVctValues("https://example.com/driver_license")
                    .AddClaim("first_name", "credentialSubject", "firstName")
                    .AddClaim("last_name", "credentialSubject", "lastName");
            })
            .Build();

        // Assert
        Assert.NotNull(query);
        Assert.Single(query.Credentials);
        
        var credential = query.Credentials[0] as SdJwtVcCredentialQuery;
        Assert.NotNull(credential);
        Assert.Equal("driver_license", credential.Id);
        Assert.Equal("vc+sd-jwt", credential.Format);
        Assert.Equal(2, credential.Claims?.Count ?? 0);
    }

    [Fact]
    public void FluentApi_BuildComplexQuery_ShouldWork()
    {
        // Act
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential", "PersonIdentificationData")
                    .RequireCryptographicHolderBinding(true)
                    .AddClaim("given_name", "credentialSubject", "given_name")
                    .AddClaim("family_name", "credentialSubject", "family_name")
                    .AddClaim("birthdate", "credentialSubject", "birthdate")
                    .AddClaimSet("given_name", "family_name")
                    .AddTrustedAuthorityAki("abc123", "def456");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait")
                    .AddMdocClaim("driving_privileges", MdocFormats.DefaultNamespace, "driving_privileges");
            })
            .AddCredentialSet(set =>
            {
                set
                    .AddOption("pid")
                    .AddOption("mdl")
                    .Required(false);
            })
            .Build();

        // Assert
        Assert.NotNull(query);
        Assert.Equal(2, query.Credentials.Count);
        Assert.Single(query.CredentialSets!);

        // Verify W3C VC credential
        var w3cCred = query.Credentials[0] as W3cVcCredentialQuery;
        Assert.NotNull(w3cCred);
        Assert.Equal("pid", w3cCred.Id);
        Assert.Equal(3, w3cCred.Claims?.Count);
        Assert.Single(w3cCred.ClaimSets!);
        Assert.Single(w3cCred.TrustedAuthorities!); // Only 1 authority added

        // Verify mdoc credential
        var mdocCred = query.Credentials[1] as MdocCredentialQuery;
        Assert.NotNull(mdocCred);
        Assert.Equal("mdl", mdocCred.Id);
        Assert.Equal(MdocFormats.MDL, mdocCred.Meta?.DoctypeValue);
        Assert.Equal(2, mdocCred.Claims?.Count);
    }

    [Fact]
    public void FluentApi_BuildAndSerialize_ShouldProduceValidJson()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddDcSdJwtCredential("identity", credential =>
            {
                credential
                    .AddVctValues("https://credentials.example.com/identity")
                    .AllowMultiple(false)
                    .RequireCryptographicHolderBinding(true)
                    .AddClaim("email", "email")
                    .AddClaim("phone", "phone_number");
            })
            .Build();

        // Act
        var json = JsonSerializer.Serialize(query, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        // Debug: Output JSON
        Console.WriteLine("Serialized JSON:");
        Console.WriteLine(json);

        // Assert
        Assert.Contains("\"id\": \"identity\"", json);
        // Format is automatically added by polymorphic serializer
        Assert.Contains("identity", json);
        Assert.Contains("email", json);

        // Verify round-trip
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json);
        Assert.NotNull(deserialized);
        Assert.Single(deserialized.Credentials);
        Assert.Equal("identity", deserialized.Credentials[0].Id);
    }

    [Fact]
    public void FluentApi_MdocWithMultipleClaims_ShouldWork()
    {
        // Act
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("drivers_license", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("family_name", MdocFormats.DefaultNamespace, "family_name", intentToRetain: true)
                    .AddMdocClaim("given_name", MdocFormats.DefaultNamespace, "given_name", intentToRetain: true)
                    .AddMdocClaim("birth_date", MdocFormats.DefaultNamespace, "birth_date")
                    .AddClaimSet("family_name", "given_name", "birth_date")
                    .AllowMultiple(false);
            })
            .Build();

        // Assert
        var mdocCred = query.Credentials[0] as MdocCredentialQuery;
        Assert.NotNull(mdocCred);
        Assert.Equal(3, mdocCred.Claims?.Count);
        
        // Verify intent_to_retain
        var familyNameClaim = mdocCred.Claims![0];
        Assert.Equal("family_name", familyNameClaim.Id);
        Assert.True(familyNameClaim.IntentToRetain);
    }

    [Fact]
    public void FluentApi_MultipleCredentialSets_ShouldWork()
    {
        // Act
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("option_a", credential => 
                credential.AddTypeValues("VerifiableCredential", "TypeA"))
            .AddW3cVcCredential("option_b", credential => 
                credential.AddTypeValues("VerifiableCredential", "TypeB"))
            .AddW3cVcCredential("option_c", credential => 
                credential.AddTypeValues("VerifiableCredential", "TypeC"))
            .AddCredentialSet(set => set
                .AddOption("option_a")
                .AddOption("option_b")
                .Required(true))
            .AddCredentialSet(set => set
                .AddOption("option_c")
                .Required(false))
            .Build();

        // Assert
        Assert.Equal(3, query.Credentials.Count);
        Assert.Equal(2, query.CredentialSets!.Count);
        Assert.True(query.CredentialSets[0].Required);
        Assert.False(query.CredentialSets[1].Required);
    }

    [Fact]
    public void FluentApi_LdpVcCredential_ShouldWork()
    {
        // Act
        var query = DcqlQueryBuilder.Create()
            .AddLdpVcCredential("university_degree", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential", "UniversityDegreeCredential")
                    .AddClaim("degree_name", "credentialSubject", "degree", "name")
                    .AddClaim("degree_type", "credentialSubject", "degree", "type");
            })
            .Build();

        // Assert
        var ldpCred = query.Credentials[0] as LdpVcCredentialQuery;
        Assert.NotNull(ldpCred);
        Assert.Equal("ldp_vc", ldpCred.Format);
        Assert.Equal(2, ldpCred.Claims?.Count);
    }
}
