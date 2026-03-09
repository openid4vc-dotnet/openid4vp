using System.Text.Json;
using OpenID4VP.Parsers;
using OpenID4VP.Dcql.Presentation;

namespace OpenID4VP.Tests.Parsers;

/// <summary>
/// Tests for VpTokenParser
/// </summary>
public class VpTokenParserTests
{
    private readonly VpTokenParser _parser = new();

    [Fact]
    public void Parse_ValidObjectPresentation_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...""]
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var vpToken = result.Value!;
        Assert.NotNull(vpToken.Presentations);
        Assert.Single(vpToken.Presentations);
        Assert.True(vpToken.Presentations.ContainsKey("credential1"));
        var entry = vpToken.Presentations["credential1"];
        Assert.NotNull(entry);
        Assert.Single(entry.GetPresentations());
    }

    [Fact]
    public void Parse_MultipleEntriesInObject_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""jwt1...""],
                ""credential2"": [""jwt2...""]
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var vpToken = result.Value!;
        Assert.Equal(2, vpToken.Presentations.Count);
        Assert.True(vpToken.Presentations.ContainsKey("credential1"));
        Assert.True(vpToken.Presentations.ContainsKey("credential2"));
    }

    [Fact]
    public void Parse_MultiplePresentsInEntry_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""jwt1..."", ""jwt2...""]
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var vpToken = result.Value!;
        Assert.Single(vpToken.Presentations);
        var entry = vpToken.Presentations["credential1"];
        Assert.Equal(2, entry.Count);
    }

    [Fact]
    public void Parse_MissingVpTokenProperty_ReturnsParseError()
    {
        var json = @"{ ""other_property"": ""value"" }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("vp_token", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_EmptyJsonString_ReturnsParseError()
    {
        var result = _parser.Parse("");
        
        Assert.False(result.IsSuccess);
        Assert.Contains("null or empty", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_NullJsonString_ReturnsParseError()
    {
        var result = _parser.Parse(null!);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("null or empty", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_InvalidJson_ReturnsParseError()
    {
        var invalidJson = @"{ ""vp_token"": invalid }";
        
        var result = _parser.Parse(invalidJson);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("Invalid JSON", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_VpTokenIsNull_ReturnsParseError()
    {
        var json = @"{ ""vp_token"": null }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("JSON object", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_VpTokenIsString_ReturnsParseError()
    {
        var json = @"{ ""vp_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."" }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("JSON object", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_VpTokenIsArray_ReturnsParseError()
    {
        var json = @"{ 
            ""vp_token"": [
                ""jwt1..."",
                ""jwt2...""
            ]
        }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("JSON object", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_VpTokenIsNumber_ReturnsParseError()
    {
        var json = @"{ ""vp_token"": 123 }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("JSON object", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_VpTokenIsBoolean_ReturnsParseError()
    {
        var json = @"{ ""vp_token"": true }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("JSON object", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_MultipleProperties_IgnoresOtherProperties()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""jwt...""]
            },
            ""iss"": ""https://wallet.example.com"",
            ""aud"": ""https://verifier.example.com""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var vpToken = result.Value!;
        Assert.Single(vpToken.Presentations);
    }

    [Fact]
    public void Parse_ComplexNestedPresentations_ReturnsVpToken()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [
                    {
                        ""@context"": [""https://www.w3.org/2018/credentials/v1""],
                        ""type"": [""VerifiablePresentation""],
                        ""verifiableCredential"": [""vc1""]
                    }
                ]
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var vpToken = result.Value!;
        Assert.Single(vpToken.Presentations);
        Assert.True(vpToken.Presentations.ContainsKey("credential1"));
    }

    [Fact]
    public void Parse_EmptyVpTokenObject_ReturnsParseError()
    {
        var json = @"{ ""vp_token"": {} }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("at least one presentation", result.Errors[0].Message);
    }

    [Fact]
    public void Parse_PresentationEntryWithEmptyArray_ReturnsParseError()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": []
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Contains("Must contain at least one presentation", result.Errors[0].Message);
    }
}

