using System.Text.Json;
using OpenID4VP.Parsers;

namespace OpenID4VP.Tests.Parsers;

/// <summary>
/// Tests for VpTokenParser
/// </summary>
public class VpTokenParserTests
{
    private readonly VpTokenParser _parser = new();

    [Fact]
    public void Parse_ValidJwtPresentation_ReturnsVpToken()
    {
        var json = @"{ ""vp_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."" }";
        
        var vpToken = _parser.Parse(json);
        
        Assert.NotNull(vpToken);
        Assert.NotNull(vpToken.Presentations);
        Assert.IsType<string>(vpToken.Presentations);
        Assert.Equal("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...", vpToken.Presentations);
    }

    [Fact]
    public void Parse_ValidArrayPresentation_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": [
                ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..1"",
                ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..2""
            ] 
        }";
        
        var vpToken = _parser.Parse(json);
        
        Assert.NotNull(vpToken);
        Assert.NotNull(vpToken.Presentations);
        Assert.IsType<JsonElement>(vpToken.Presentations);
    }

    [Fact]
    public void Parse_ValidObjectPresentation_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": {
                ""format"": ""jwt_vp_json"",
                ""presentation"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...""
            }
        }";
        
        var vpToken = _parser.Parse(json);
        
        Assert.NotNull(vpToken);
        Assert.NotNull(vpToken.Presentations);
        Assert.IsType<JsonElement>(vpToken.Presentations);
    }

    [Fact]
    public void Parse_MissingVpTokenProperty_ThrowsInvalidOperationException()
    {
        var json = @"{ ""other_property"": ""value"" }";
        
        var ex = Assert.Throws<InvalidOperationException>(() => _parser.Parse(json));
        Assert.Contains("vp_token", ex.Message);
    }

    [Fact]
    public void Parse_EmptyJsonString_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => _parser.Parse(""));
        Assert.Equal("json", ex.ParamName);
    }

    [Fact]
    public void Parse_NullJsonString_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => _parser.Parse(null!));
        Assert.Equal("json", ex.ParamName);
    }

    [Fact]
    public void Parse_InvalidJson_Throws()
    {
        var invalidJson = @"{ ""vp_token"": invalid }";
        
        var ex = Record.Exception(() => _parser.Parse(invalidJson));
        Assert.NotNull(ex);
    }

    [Fact]
    public void Parse_VpTokenIsEmptyString_ReturnsVpToken()
    {
        var json = @"{ ""vp_token"": """" }";
        
        // Empty strings are allowed - validation of JWT format is not the parser's job
        var vpToken = _parser.Parse(json);
        
        Assert.NotNull(vpToken);
        Assert.Equal("", vpToken.Presentations);
    }

    [Fact]
    public void Parse_VpTokenIsNull_ThrowsInvalidOperationException()
    {
        var json = @"{ ""vp_token"": null }";
        
        var ex = Assert.Throws<InvalidOperationException>(() => _parser.Parse(json));
    }

    [Fact]
    public void Parse_VpTokenIsNumber_ThrowsInvalidOperationException()
    {
        var json = @"{ ""vp_token"": 123 }";
        
        var ex = Assert.Throws<InvalidOperationException>(() => _parser.Parse(json));
        Assert.Contains("string, array, or object", ex.Message);
    }

    [Fact]
    public void Parse_VpTokenIsBoolean_ThrowsInvalidOperationException()
    {
        var json = @"{ ""vp_token"": true }";
        
        var ex = Assert.Throws<InvalidOperationException>(() => _parser.Parse(json));
        Assert.Contains("string, array, or object", ex.Message);
    }

    [Fact]
    public void Parse_MultipleProperties_IgnoresOtherProperties()
    {
        var json = @"{ 
            ""vp_token"": ""jwt_presentation"",
            ""iss"": ""https://wallet.example.com"",
            ""aud"": ""https://verifier.example.com""
        }";
        
        var vpToken = _parser.Parse(json);
        
        Assert.NotNull(vpToken);
        Assert.Equal("jwt_presentation", vpToken.Presentations);
    }

    [Fact]
    public void Parse_ComplexNestedObject_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": {
                ""format"": ""ldp_vp"",
                ""presentation"": {
                    ""@context"": [""https://www.w3.org/2018/credentials/v1""],
                    ""type"": [""VerifiablePresentation""],
                    ""verifiableCredential"": [""vc1"", ""vc2""]
                }
            }
        }";
        
        var vpToken = _parser.Parse(json);
        
        Assert.NotNull(vpToken);
        Assert.NotNull(vpToken.Presentations);
    }
}
