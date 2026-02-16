using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Tests;

/// <summary>
/// Tests for IClaimQuery interface demonstrating polymorphic claim handling
/// across different credential query formats.
/// </summary>
public class IClaimQueryTests
{
    [Fact]
    public void JsonClaimQuery_ImplementsIClaimQuery_WithIdProperty()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("test", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("email", "credentialSubject", "email");
            })
            .Build();

        var credential = query.Credentials[0] as W3cVcCredentialQuery;
        var claim = credential!.Claims![0];

        // Act
        IClaimQuery claimQuery = claim;
        var id = claimQuery.Id;

        // Assert
        Assert.NotNull(claimQuery);
        Assert.Equal("email", id);
    }

    [Fact]
    public void JsonClaimQuery_ImplementsIClaimQuery_WithValuesProperty()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("test", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("email", "credentialSubject", "email");
            })
            .Build();

        var credential = query.Credentials[0] as W3cVcCredentialQuery;
        var claim = credential!.Claims![0];

        // Act
        IClaimQuery claimQuery = claim;
        var values = claimQuery.Values;

        // Assert
        Assert.NotNull(claimQuery);
        Assert.Null(values); // No values specified in builder
    }

    [Fact]
    public void MdocClaimQuery_ImplementsIClaimQuery_WithIdProperty()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("family_name", MdocFormats.DefaultNamespace, "family_name");
            })
            .Build();

        var credential = query.Credentials[0] as MdocCredentialQuery;
        var claim = credential!.Claims![0];

        // Act
        IClaimQuery claimQuery = claim;
        var id = claimQuery.Id;

        // Assert
        Assert.NotNull(claimQuery);
        Assert.Equal("family_name", id);
    }

    [Fact]
    public void MdocClaimQuery_ImplementsIClaimQuery_WithValuesProperty()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait");
            })
            .Build();

        var credential = query.Credentials[0] as MdocCredentialQuery;
        var claim = credential!.Claims![0];

        // Act
        IClaimQuery claimQuery = claim;
        var values = claimQuery.Values;

        // Assert
        Assert.NotNull(claimQuery);
        Assert.Null(values); // No values specified in builder
    }

    [Fact]
    public void IClaimQuery_PolymorphicAccess_MixedClaimTypes()
    {
        // Arrange - Create query with both JSON and mdoc claims
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("pid", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("given_name", "credentialSubject", "given_name")
                    .AddClaim("family_name", "credentialSubject", "family_name");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait")
                    .AddMdocClaim("driving_privileges", MdocFormats.DefaultNamespace, "driving_privileges");
            })
            .Build();

        var w3cCred = query.Credentials[0] as W3cVcCredentialQuery;
        var mdocCred = query.Credentials[1] as MdocCredentialQuery;

        // Act - Access all claims polymorphically through IClaimQuery
        var allClaims = new List<IClaimQuery>();
        allClaims.AddRange(w3cCred!.Claims!);
        allClaims.AddRange(mdocCred!.Claims!);

        var claimIds = allClaims.Select(c => c.Id).ToList();

        // Assert
        Assert.Equal(4, allClaims.Count);
        Assert.Contains("given_name", claimIds);
        Assert.Contains("family_name", claimIds);
        Assert.Contains("portrait", claimIds);
        Assert.Contains("driving_privileges", claimIds);
    }

    [Fact]
    public void IClaimQuery_PolymorphicAccess_FilterByClaims()
    {
        // Arrange - Create query with multiple credentials
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("cred1", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("email", "credentialSubject", "email")
                    .AddClaim("phone", "credentialSubject", "phone");
            })
            .AddMdocCredential("cred2", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait");
            })
            .Build();

        // Act - Find all claims matching a pattern
        var allClaims = new List<IClaimQuery>();
        foreach (var cred in query.Credentials)
        {
            if (cred is W3cVcCredentialQuery w3c && w3c.Claims != null)
                allClaims.AddRange(w3c.Claims);
            else if (cred is MdocCredentialQuery mdoc && mdoc.Claims != null)
                allClaims.AddRange(mdoc.Claims);
        }

        var emailClaim = allClaims.FirstOrDefault(c => c.Id == "email");
        var portraitClaim = allClaims.FirstOrDefault(c => c.Id == "portrait");

        // Assert
        Assert.NotNull(emailClaim);
        Assert.NotNull(portraitClaim);
        Assert.Equal("email", emailClaim.Id);
        Assert.Equal("portrait", portraitClaim.Id);
    }

    [Fact]
    public void IClaimQuery_CanBeUsedInCollections()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("test", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("email", "credentialSubject", "email")
                    .AddClaim("phone", "credentialSubject", "phone");
            })
            .Build();

        var credential = query.Credentials[0] as W3cVcCredentialQuery;
        IEnumerable<IClaimQuery> claimList = credential!.Claims!.Cast<IClaimQuery>().ToList();

        // Act
        var firstClaim = claimList.First();
        var claimCount = claimList.Count();
        var hasEmailClaim = claimList.Any(c => c.Id == "email");

        // Assert
        Assert.Equal(2, claimCount);
        Assert.True(hasEmailClaim);
        Assert.Equal("email", firstClaim.Id);
    }

    [Fact]
    public void IClaimQuery_CanBeProcessedUniformly()
    {
        // Arrange - Create claims from different types
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("w3c", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("given_name", "credentialSubject", "given_name");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("family_name", MdocFormats.DefaultNamespace, "family_name");
            })
            .Build();

        var w3cCred = query.Credentials[0] as W3cVcCredentialQuery;
        var mdocCred = query.Credentials[1] as MdocCredentialQuery;

        // Act - Process all claims uniformly
        var processor = new ClaimProcessor();
        processor.AddClaim(w3cCred!.Claims![0]);
        processor.AddClaim(mdocCred!.Claims![0]);

        var summary = processor.GetSummary();

        // Assert
        Assert.Equal(2, summary.TotalClaims);
        Assert.Contains("given_name", summary.AllClaimIds);
        Assert.Contains("family_name", summary.AllClaimIds);
    }

    [Fact]
    public void IClaimQuery_ImplementationConsistency_JsonClaimQuery()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("test", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("sub", "credentialSubject", "sub");
            })
            .Build();

        var credential = query.Credentials[0] as W3cVcCredentialQuery;
        var jsonClaim = credential!.Claims![0] as JsonClaimQuery;
        IClaimQuery claimInterface = jsonClaim!;

        // Act & Assert - Verify interface contract
        Assert.NotNull(jsonClaim.Id);
        Assert.Equal(jsonClaim.Id, claimInterface.Id);
        Assert.Equal(jsonClaim.Values, claimInterface.Values);
    }

    [Fact]
    public void IClaimQuery_ImplementationConsistency_MdocClaimQuery()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("given_name", MdocFormats.DefaultNamespace, "given_name");
            })
            .Build();

        var credential = query.Credentials[0] as MdocCredentialQuery;
        var mdocClaim = credential!.Claims![0] as MdocClaimQuery;
        IClaimQuery claimInterface = mdocClaim!;

        // Act & Assert - Verify interface contract
        Assert.NotNull(mdocClaim.Id);
        Assert.Equal(mdocClaim.Id, claimInterface.Id);
        Assert.Equal(mdocClaim.Values, claimInterface.Values);
    }

    [Fact]
    public void IClaimQuery_AllCredentialTypes_ExposeClaims()
    {
        // Arrange - Create all credential types
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("w3c", credential =>
            {
                credential.AddTypeValues("VerifiableCredential").AddClaim("claim1", "credentialSubject", "claim1");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential.WithDoctype(MdocFormats.MDL).AddMdocClaim("claim2", MdocFormats.DefaultNamespace, "claim2");
            })
            .AddLdpVcCredential("ldp", credential =>
            {
                credential.AddTypeValues("VerifiableCredential").AddClaim("claim3", "credentialSubject", "claim3");
            })
            .AddSdJwtVcCredential("sdjwt", credential =>
            {
                credential.AddVctValues("https://example.com").AddClaim("claim4", "credentialSubject", "claim4");
            })
            .AddDcSdJwtCredential("dcsdjwt", credential =>
            {
                credential.AddVctValues("https://example.com").AddClaim("claim5", "credentialSubject", "claim5");
            })
            .Build();

        // Act - Verify all credentials expose claims through IClaimQuery
        var allClaims = new List<IClaimQuery>();
        foreach (var cred in query.Credentials)
        {
            var claimsProperty = cred.GetType().GetProperty("Claims");
            if (claimsProperty?.GetValue(cred) is System.Collections.IEnumerable claims)
            {
                foreach (var claim in claims)
                {
                    if (claim is IClaimQuery claimQuery)
                        allClaims.Add(claimQuery);
                }
            }
        }

        // Assert
        Assert.Equal(5, allClaims.Count);
        var ids = allClaims.Select(c => c.Id).ToList();
        Assert.Contains("claim1", ids);
        Assert.Contains("claim2", ids);
        Assert.Contains("claim3", ids);
        Assert.Contains("claim4", ids);
        Assert.Contains("claim5", ids);
    }

    [Fact]
    public void IClaimQuery_Enables_OperationWithoutTypeChecking()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddW3cVcCredential("w3c", credential =>
            {
                credential
                    .AddTypeValues("VerifiableCredential")
                    .AddClaim("email", "credentialSubject", "email")
                    .AddClaim("phone", "credentialSubject", "phone");
            })
            .AddMdocCredential("mdl", credential =>
            {
                credential
                    .WithDoctype(MdocFormats.MDL)
                    .AddMdocClaim("portrait", MdocFormats.DefaultNamespace, "portrait");
            })
            .Build();

        // Act - Get all claim IDs without any type checking
        var allClaimIds = new List<string>();
        foreach (var cred in query.Credentials)
        {
            var claimsProperty = cred.GetType().GetProperty("Claims");
            if (claimsProperty?.GetValue(cred) is System.Collections.IEnumerable claimsEnum)
            {
                foreach (IClaimQuery claim in claimsEnum)
                {
                    if (claim.Id != null)
                        allClaimIds.Add(claim.Id);
                }
            }
        }

        // Assert - No type checking required
        Assert.Equal(3, allClaimIds.Count);
        Assert.Contains("email", allClaimIds);
        Assert.Contains("phone", allClaimIds);
        Assert.Contains("portrait", allClaimIds);
    }
}

/// <summary>
/// Helper class demonstrating practical use of IClaimQuery interface.
/// </summary>
internal class ClaimProcessor
{
    private readonly List<IClaimQuery> _claims = new();

    public void AddClaim(IClaimQuery claim)
    {
        _claims.Add(claim);
    }

    public ClaimSummary GetSummary()
    {
        return new ClaimSummary
        {
            TotalClaims = _claims.Count,
            AllClaimIds = _claims.Where(c => c.Id != null).Select(c => c.Id!).ToList()
        };
    }
}

/// <summary>
/// Summary of processed claims demonstrating IClaimQuery usage.
/// </summary>
internal class ClaimSummary
{
    public int TotalClaims { get; set; }
    public List<string> AllClaimIds { get; set; } = new();
}
