namespace OpenID4VP.Parsers;

using OpenID4VC.Core.Results;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class ParserErrors
{
    // Common to both parsers
    public static Error InvalidJsonInput() 
        => new ParseError("JSON string cannot be null or empty", "");

    public static Error InvalidVpTokenType(JsonValueKind kind) 
        => new ParseError($"vp_token must be a string, array, or object, got {kind}", "");

    // AuthorizationResponse specific
    public static Error NullResponseJson() 
        => new ParseError("Response JSON cannot be null", "");

    public static Error InvalidResponseJsonType(JsonValueKind kind) 
        => new ParseError($"Response JSON must be an object, got {kind}", "");

    public static Error MissingVpTokenProperty() 
        => new ParseError("Response must contain 'vp_token' property", "");

    public static Error MissingVpTokenParameter() 
        => new ParseError("Response must contain 'vp_token' parameter", "");

    public static Error NullFormParameters() 
        => new ParseError("Form parameters dictionary cannot be null", "");

    // VpToken specific
    public static Error NullVpTokenJson() 
        => new ParseError("VP Token JSON cannot be null", "");

    public static Error InvalidVpTokenStructure(InvalidOperationException ex)
        => new ParseError($"Invalid VP Token structure: {ex.Message}", "");
}