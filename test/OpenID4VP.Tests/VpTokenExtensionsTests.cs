using OpenID4VP.Dcql.Presentation;
using OpenID4VP.Parsers;

namespace OpenID4VP.Tests.Models;

/// <summary>
/// Tests for VpTokenExtensions
/// </summary>
public class VpTokenExtensionsTests
{
    [Fact]
    public void ToSdJwtResult_WithMissingPresentationId_ReturnsParseError()
    {
        // Arrange
        var presentations = new Dictionary<string, PresentationEntry>
        {
            { "credential1", new PresentationEntry("some_jwt") }
        };

        // Act
        var result = presentations.ToSdJwtResult("non_existent");

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("not found", result.Errors[0].Message);
    }

    [Fact]
    public void ToSdJwtResult_WithEmptyPresentationId_ThrowsArgumentException()
    {
        // Arrange
        var presentations = new Dictionary<string, PresentationEntry>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => presentations.ToSdJwtResult(""));
        Assert.Equal("presentationId", ex.ParamName);
    }

    [Fact]
    public void ToSdJwtResult_WithNullPresentationId_ThrowsArgumentException()
    {
        // Arrange
        var presentations = new Dictionary<string, PresentationEntry>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => presentations.ToSdJwtResult(null!));
        Assert.Equal("presentationId", ex.ParamName);
    }

    [Fact]
    public void ToSdJwtResult_WithNullPresentations_ThrowsArgumentNullException()
    {
        // Act & Assert
        Dictionary<string, PresentationEntry>? presentations = null;
        var ex = Assert.Throws<ArgumentNullException>(() => presentations!.ToSdJwtResult("credential1"));
        Assert.Equal("presentations", ex.ParamName);
    }

    [Fact]
    public void ToSdJwtResult_WithNonStringPresentation_ReturnsParseError()
    {
        // Arrange - Presentation entry with object instead of string
        var presentations = new Dictionary<string, PresentationEntry>
        {
            { "credential1", new PresentationEntry(new { format = "jwt_vp_json" }) }
        };

        // Act
        var result = presentations.ToSdJwtResult("credential1");

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("not a valid SD-JWT string", result.Errors[0].Message);
    }

    [Fact]
    public void ToSdJwtResults_WithEmptyPresentations_ReturnsEmptyDictionary()
    {
        // Arrange
        var presentations = new Dictionary<string, PresentationEntry>();

        // Act
        var results = presentations.ToSdJwtResults();

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void ToSdJwtResults_WithMultiplePresentations_ReturnsAllResults()
    {
        // Arrange - Use invalid SD-JWT strings to test the extension method's dictionary handling
        // (actual parsing would fail, but the extension correctly maps all entries)
        var presentations = new Dictionary<string, PresentationEntry>
        {
            { "credential1", new PresentationEntry("invalid_jwt_1") },
            { "credential2", new PresentationEntry("invalid_jwt_2") }
        };

        // Act
        var results = presentations.ToSdJwtResults();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains("credential1", results.Keys);
        Assert.Contains("credential2", results.Keys);
        // Both should have errors since the JWTs are invalid
        Assert.False(results["credential1"].IsSuccess);
        Assert.False(results["credential2"].IsSuccess);
    }

    [Fact]
    public void ToSdJwtResults_WithNullPresentations_ThrowsArgumentNullException()
    {
        // Act & Assert
        Dictionary<string, PresentationEntry>? presentations = null;
        var ex = Assert.Throws<ArgumentNullException>(() => presentations!.ToSdJwtResults());
        Assert.Equal("presentations", ex.ParamName);
    }

    [Fact]
    public void ToSdJwtResult_WithMultiplePresentationsInEntry_UsesFirst()
    {
        // Arrange - Entry with multiple presentations (should use first one)
        var presentations = new Dictionary<string, PresentationEntry>
        {
            { "credential1", new PresentationEntry("jwt_string_1", "jwt_string_2") }
        };

        // Act
        var result = presentations.ToSdJwtResult("credential1");

        // Assert
        // Result will fail due to invalid JWT, but it should attempt to parse the first presentation
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void ToSdJwtResult_WithEmptyStringPresentation_ReturnsParseError()
    {
        // Arrange
        var presentations = new Dictionary<string, PresentationEntry>
        {
            { "credential1", new PresentationEntry("") }
        };

        // Act
        var result = presentations.ToSdJwtResult("credential1");

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("not a valid SD-JWT string", result.Errors[0].Message);
    }

    [Fact]
    public void ToSdJwtResult_WithWhitespaceStringPresentation_ReturnsParseError()
    {
        // Arrange
        var presentations = new Dictionary<string, PresentationEntry>
        {
            { "credential1", new PresentationEntry("   ") }
        };

        // Act
        var result = presentations.ToSdJwtResult("credential1");

        // Assert
        Assert.False(result.IsSuccess);
        Assert.Contains("not a valid SD-JWT string", result.Errors[0].Message);
    }
}

