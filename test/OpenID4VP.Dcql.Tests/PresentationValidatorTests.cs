using OpenID4VP.Dcql.Presentation;
using OpenID4VP.Dcql.Query.Builders;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Tests;

public class PresentationValidatorTests
{
    [Fact]
    public void Validate_WithValidPresentation_ShouldReturnTrue()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token_here") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Validate_WithPresentationIdNotInQuery_ShouldReturnFalse()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "unknown_credential", new PresentationEntry("jwt_token_here") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Validate_WithMultipleCredentials_ValidPresentation_ShouldReturnTrue()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc1");
            })
            .AddSdJwtVcCredential("credential2", credential =>
            {
                credential.AddVctValues("https://example.com/vc2");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token_1") },
                { "credential2", new PresentationEntry("jwt_token_2") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Validate_WithMultipleCredentialsPartialPresentation_ShouldReturnTrue()
    {
        // Arrange - only one credential required
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc1");
            })
            .AddSdJwtVcCredential("credential2", credential =>
            {
                credential.AddVctValues("https://example.com/vc2");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token_1") }
                // credential2 not provided
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Validate_WithMultipleConstraintViolation_ShouldReturnFalse()
    {
        // Arrange - credential1 has multiple=false but we provide 2 presentations
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential
                    .AllowMultiple(false) // Explicitly set to false
                    .AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token_1", "jwt_token_2") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Validate_WithMultipleConstraintAllowed_ShouldReturnTrue()
    {
        // Arrange - credential1 has multiple=true so we can provide 2 presentations
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential
                    .AllowMultiple(true)
                    .AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token_1", "jwt_token_2") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Validate_WithEmptyPresentation_ShouldReturnTrue()
    {
        // Arrange - query has credentials but presentation is empty (all optional)
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>()
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsValidFor_ExtensionMethod_ShouldWork()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token") }
            }
        };

        // Act
        var result = presentation.IsValidFor(query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void IsValidFor_ExtensionMethod_WithInvalidPresentation_ShouldReturnFalse()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "unknown", new PresentationEntry("jwt_token") }
            }
        };

        // Act
        var result = presentation.IsValidFor(query);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void IsValidFor_WithCustomValidator_ShouldUseProvidedValidator()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddSdJwtVcCredential("credential1", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "credential1", new PresentationEntry("jwt_token") }
            }
        };

        var customValidator = new PresentationValidator();

        // Act
        var result = presentation.IsValidFor(query, customValidator);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Validate_WithMdocCredential_ValidPresentation_ShouldReturnTrue()
    {
        // Arrange
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential.WithDoctype(MdocFormats.MDL);
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "mdl", new PresentationEntry("cbor_encoded_data") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Validate_MixedFormats_ValidPresentation_ShouldReturnTrue()
    {
        // Arrange - multiple different credential formats
        var query = DcqlQueryBuilder.Create()
            .AddMdocCredential("mdl", credential =>
            {
                credential.WithDoctype(MdocFormats.MDL);
            })
            .AddSdJwtVcCredential("credential", credential =>
            {
                credential.AddVctValues("https://example.com/vc");
            })
            .Build();

        var presentation = new DcqlPresentation
        {
            Presentations = new Dictionary<string, PresentationEntry>
            {
                { "mdl", new PresentationEntry("cbor_data") },
                { "credential", new PresentationEntry("jwt_token") }
            }
        };

        var validator = new PresentationValidator();

        // Act
        var result = validator.Validate(presentation, query);

        // Assert
        Assert.True(result);
    }
}
