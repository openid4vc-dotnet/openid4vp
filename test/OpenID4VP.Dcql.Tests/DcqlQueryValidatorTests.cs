using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Query.Validators;

namespace OpenID4VP.Dcql.Tests;

/// <summary>
/// Tests for DcqlQueryValidator demonstrating validation rules for DCQL queries.
/// Tests cover: structure validation, uniqueness, credential validation, claim sets, and credential sets.
/// </summary>
public class DcqlQueryValidatorTests
{
    private readonly DcqlQueryValidator _validator = new();

    [Fact]
    public void Validate_WithValidSimpleQuery_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Validate_WithMultipleCredentials_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential.AddTypeValues("VerifiableCredential");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential.WithDoctype(MdocFormats.MDL);
            })
            .AddSdJwtVcCredential("credential", credential =>
            {
                credential.AddVctValues("https://example.com");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithDuplicateCredentialIds_ShouldFail()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("duplicate_id", credential =>
            {
                credential.AddVctValues("https://example.com/vc1");
            })
            .AddSdJwtVcCredential("duplicate_id", credential =>
            {
                credential.AddVctValues("https://example.com/vc2");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.False(result.IsSuccess);
        Assert.True(result.Errors.Any(e => e.Message.Contains("unique")));
    }

    [Fact]
    public void Validate_WithValidCredentialIds_ShouldPass()
    {
        // Arrange - Test various valid ID formats
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential_1", credential => 
                credential.AddVctValues("https://example.com/1"))
            .AddSdJwtVcCredential("credential-2", credential => 
                credential.AddVctValues("https://example.com/2"))
            .AddSdJwtVcCredential("credential3", credential => 
                credential.AddVctValues("https://example.com/3"))
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithValidCredentialSets_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/1");
            })
            .AddSdJwtVcCredential("credential2", credential =>
            {
                credential.AddVctValues("https://example.com/2");
            })
            .AddCredentialSet(set =>
            {
                set.AddOption("credential1").AddOption("credential2");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithNullCredentialSets_ShouldPass()
    {
        // Arrange - credential_sets is optional (can be null)
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Null(query.CredentialSets);
    }

    [Fact]
    public void Validate_WithW3cVcWithMeta_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential.AddTypeValues("VerifiableCredential");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithAllCredentialFormats_ShouldPass()
    {
        // Arrange - Test all supported credential formats
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential.WithDoctype(MdocFormats.MDL);
            })
            .AddW3cVcCredential("w3c", credential =>
            {
                credential.AddTypeValues("VerifiableCredential");
            })
            .AddLdpVcCredential("ldp", credential =>
            {
                credential.AddTypeValues("VerifiableCredential");
            })
            .AddSdJwtVcCredential("sdjwt", credential =>
            {
                credential.AddVctValues("https://example.com");
            })
            .AddDcSdJwtCredential("dcsdjwt", credential =>
            {
                credential.AddVctValues("https://example.com");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(5, query.Credentials.Count);
    }

    [Fact]
    public void Validate_WithValidClaimSets_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("given_name", "credentialSubject", "given_name")
                    .AddClaim("family_name", "credentialSubject", "family_name")
                    .AddClaimSet("given_name", "family_name");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_ComplexQuery_WithMultipleCredentialsAndSets_ShouldPass()
    {
        // Arrange - Complex realistic scenario
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential", "PersonIdentificationData")
                    .AddClaim("given_name", "credentialSubject", "given_name")
                    .AddClaim("family_name", "credentialSubject", "family_name")
                    .AddClaimSet("given_name", "family_name");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait");
            })
            .AddCredentialSet(set =>
            {
                set.AddOption("pid").AddOption("mdl").Required(false);
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.NotNull(query.CredentialSets);
    }

    [Fact]
    public void Validate_WithMdocCredentialOptionalMeta_ShouldPass()
    {
        // Arrange - Mdoc meta is optional
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                // No doctype specified, so no metadata
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithValidSpecialCharactersInIds_ShouldPass()
    {
        // Arrange - Test valid ID formats with underscores and hyphens
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("valid_credential", credential =>
            {
                credential.AddVctValues("https://example.com/1");
            })
            .AddSdJwtVcCredential("valid-credential", credential =>
            {
                credential.AddVctValues("https://example.com/2");
            })
            .AddSdJwtVcCredential("validCredential123", credential =>
            {
                credential.AddVctValues("https://example.com/3");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithMdocCredential_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("family_name", MdocFormats.DefaultNamespace, "family_name")
                    .AddMdocClaim("given_name", MdocFormats.DefaultNamespace, "given_name");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithMdocClaimSets_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("family_name", MdocFormats.DefaultNamespace, "family_name")
                    .AddMdocClaim("given_name", MdocFormats.DefaultNamespace, "given_name")
                    .AddClaimSet("family_name", "given_name");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithLdpVcCredential_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddLdpVcCredential("ldp", credential =>
            {
                credential.AddTypeValues("VerifiableCredential");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_MultipleCredentialSets_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("option_a", credential =>
            {
                credential.AddTypeValues("VerifiableCredential", "TypeA");
            })
            .AddW3cVcCredential("option_b", credential =>
            {
                credential.AddTypeValues("VerifiableCredential", "TypeB");
            })
            .AddW3cVcCredential("option_c", credential =>
            {
                credential.AddTypeValues("VerifiableCredential", "TypeC");
            })
            .AddCredentialSet(set =>
            {
                set.AddOption("option_a").AddOption("option_b");
            })
            .AddCredentialSet(set =>
            {
                set.AddOption("option_c").Required(true);
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(2, query.CredentialSets!.Count);
    }

    [Fact]
    public void Validate_WithTrustedAuthorities_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddTrustedAuthorityAki("aki123", "aki456");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithRequireCryptographicHolderBinding_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .RequireCryptographicHolderBinding(false);
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithMultipleCredentialsAllowMultiple_ShouldPass()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AllowMultiple(true);
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AllowMultiple(false);
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_CallsDelegatedValidators()
    {
        // Arrange - Verify that child validators are invoked
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("w3c", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("name", "credentialSubject", "name");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert - If delegated validators weren't working, validation might fail differently
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_WithComplexClaimSets_ShouldPass()
    {
        // Arrange - Multiple claims in multiple claim sets
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("given_name", "credentialSubject", "given_name")
                    .AddClaim("family_name", "credentialSubject", "family_name")
                    .AddClaim("birthdate", "credentialSubject", "birthdate")
                    .AddClaimSet("given_name", "family_name")
                    .AddClaimSet("birthdate");
            })
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_VerifiesFormatValues()
    {
        // Arrange - Verify all credential types get correct format values
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", c => c.WithDoctype(MdocFormats.MDL))
            .AddW3cVcCredential("w3c", c => c.AddTypeValues("VerifiableCredential"))
            .AddLdpVcCredential("ldp", c => c.AddTypeValues("VerifiableCredential"))
            .AddSdJwtVcCredential("sdjwt", c => c.AddVctValues("https://example.com"))
            .AddDcSdJwtCredential("dcsdjwt", c => c.AddVctValues("https://example.com"))
            .Build();

        // Act
        var result = _validator.Validate(query);

        // Assert
        Assert.True(result.IsSuccess);
        Assert.Equal(CredentialFormats.MsoMdoc, query.Credentials[0].Format);
        Assert.Equal(CredentialFormats.JwtVcJson, query.Credentials[1].Format);
        Assert.Equal(CredentialFormats.LdpVc, query.Credentials[2].Format);
        Assert.Equal(CredentialFormats.VcSdJwt, query.Credentials[3].Format);
        Assert.Equal(CredentialFormats.DcSdJwt, query.Credentials[4].Format);
    }
}



