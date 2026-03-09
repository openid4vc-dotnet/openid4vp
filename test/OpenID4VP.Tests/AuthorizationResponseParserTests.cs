using OpenID4VC.Core.Results;
using OpenID4VP.Parsers;

namespace OpenID4VP.Tests.Parsers;

/// <summary>
/// Tests for AuthorizationResponseParser
/// </summary>
public class AuthorizationResponseParserTests
{
    private readonly AuthorizationResponseParser _parser = new();

    [Fact]
    public void Parse_ValidResponseWithVpTokenOnly_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...""]
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Single(response.VpToken.Presentations);
        Assert.Null(response.State);
        Assert.Null(response.IdToken);
    }

    [Fact]
    public void Parse_ResponseWithVpTokenAndState_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...""]
            },
            ""state"": ""state-abc-123""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Single(response.VpToken.Presentations);
        Assert.Equal("state-abc-123", response.State);
        Assert.Null(response.IdToken);
    }

    [Fact]
    public void Parse_ResponseWithVpTokenStateAndIdToken_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...""]
            },
            ""state"": ""state-123"",
            ""id_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Single(response.VpToken.Presentations);
        Assert.Equal("state-123", response.State);
        Assert.Equal("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id", response.IdToken);
    }

    [Fact]
    public void Parse_ResponseWithMultipleVpTokenEntries_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": {
                ""credential1"": [""jwt1...""],
                ""credential2"": [""jwt2..."", ""jwt3...""]
            }
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Equal(2, response.VpToken.Presentations.Count);
    }

    [Fact]
    public void Parse_MissingVpToken_ReturnsParserError()
    {
        var json = @"{ ""state"": ""state-123"" }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_NullJson_ReturnsParserError()
    {
        var result = _parser.Parse((string)null!);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_EmptyJsonString_ReturnsParserError()
    {
        var result = _parser.Parse("");
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_InvalidJson_ReturnsJsonError()
    {
        var invalidJson = @"{ invalid json }";
        
        var result = _parser.Parse(invalidJson);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<JsonError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_NotAnObject_ReturnsParserError()
    {
        var json = @"[""array""]";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_CaseSensitiveProperties_ReturnsParserError()
    {
        var json = @"{ 
            ""VP_Token"": {
                ""credential1"": [""jwt...""]
            },
            ""STATE"": ""state-123""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_ComplexResponse_ReturnsAuthorizationResponse()
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
            },
            ""state"": ""complex-state-123"",
            ""id_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id"",
            ""extra_param"": ""ignored""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Single(response.VpToken.Presentations);
        Assert.Equal("complex-state-123", response.State);
        Assert.Equal("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id", response.IdToken);
    }
}
