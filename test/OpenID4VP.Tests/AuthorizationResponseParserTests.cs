using System.Text.Json;
using OpenID4VC.Core.Results;
using OpenID4VP.Models;
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
            ""vp_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Null(response.State);
        Assert.Null(response.IdToken);
    }

    [Fact]
    public void Parse_ResponseWithVpTokenAndState_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."",
            ""state"": ""state-abc-123""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Equal("state-abc-123", response.State);
        Assert.Null(response.IdToken);
    }

    [Fact]
    public void Parse_ResponseWithVpTokenStateAndIdToken_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."",
            ""state"": ""state-123"",
            ""id_token"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
        Assert.Equal("state-123", response.State);
        Assert.Equal("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id", response.IdToken);
    }

    [Fact]
    public void Parse_ResponseWithArrayVpToken_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": [
                ""jwt1..."",
                ""jwt2...""
            ]
        }";
        
        var result = _parser.Parse(json);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.NotNull(response.VpToken);
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
            ""VP_Token"": ""jwt..."",
            ""STATE"": ""state-123""
        }";
        
        var result = _parser.Parse(json);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void ParseFormParameters_ValidParameters_ReturnsAuthorizationResponse()
    {
        var parameters = new Dictionary<string, string>
        {
            { "vp_token", "jwt_presentation" },
            { "state", "state-abc" }
        };
        
        var result = _parser.ParseFormParameters(parameters);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.Equal("jwt_presentation", (string?)response.VpToken.Presentations);
        Assert.Equal("state-abc", response.State);
    }

    [Fact]
    public void ParseFormParameters_OnlyVpToken_ReturnsAuthorizationResponse()
    {
        var parameters = new Dictionary<string, string>
        {
            { "vp_token", "jwt_presentation" }
        };
        
        var result = _parser.ParseFormParameters(parameters);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.Equal("jwt_presentation", (string?)response.VpToken.Presentations);
        Assert.Null(response.State);
    }

    [Fact]
    public void ParseFormParameters_WithIdToken_ReturnsAuthorizationResponse()
    {
        var parameters = new Dictionary<string, string>
        {
            { "vp_token", "vp..." },
            { "state", "state-x" },
            { "id_token", "idt..." }
        };
        
        var result = _parser.ParseFormParameters(parameters);
        
        Assert.True(result.IsSuccess);
        var response = result.Value!;
        Assert.NotNull(response);
        Assert.Equal("vp...", (string?)response.VpToken.Presentations);
        Assert.Equal("state-x", response.State);
        Assert.Equal("idt...", response.IdToken);
    }

    [Fact]
    public void ParseFormParameters_MissingVpToken_ReturnsParserError()
    {
        var parameters = new Dictionary<string, string>
        {
            { "state", "state-123" }
        };
        
        var result = _parser.ParseFormParameters(parameters);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void ParseFormParameters_NullParameters_ReturnsParserError()
    {
        var result = _parser.ParseFormParameters(null!);
        
        Assert.False(result.IsSuccess);
        Assert.Single(result.Errors);
        Assert.IsType<ParseError>(result.Errors[0]);
    }

    [Fact]
    public void Parse_ComplexResponse_ReturnsAuthorizationResponse()
    {
        var json = @"{ 
            ""vp_token"": {
                ""format"": ""jwt_vp_json"",
                ""presentation"": ""eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."",
                ""metadata"": {
                    ""issuer"": ""https://wallet.example.com""
                }
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
        Assert.Equal("complex-state-123", response.State);
        Assert.Equal("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...id", response.IdToken);
    }
}
