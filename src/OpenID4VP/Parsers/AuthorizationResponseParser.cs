using System.Text.Json;
using System.Text.Json.Serialization;
using OpenID4VC.Core.Results;
using OpenID4VP.Models;

namespace OpenID4VP.Parsers;

/// <summary>
/// Parser for deserializing Authorization Responses from JSON.
/// 
/// Handles the JSON structure of Authorization Responses sent from Wallet to Verifier.
/// Supports both direct JSON parsing and automatic deserialization via System.Text.Json.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8
/// </summary>
public sealed class AuthorizationResponseParser
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly VpTokenParser _vpTokenParser = new();

    /// <summary>
    /// Parses a JSON string into an AuthorizationResponse object.
    /// </summary>
    /// <param name="json">The JSON string containing the response data</param>
    /// <returns>A Result containing the parsed AuthorizationResponse if successful, or errors if parsing failed</returns>
    public Result<AuthorizationResponse> Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return ParserErrors.InvalidJsonInput();

        try
        {
            using var doc = JsonDocument.Parse(json);
            return Parse(doc.RootElement);
        }
        catch (JsonException ex)
        {
            return JsonErrors.InvalidJsonStructure(ex, json);
        }
    }

    /// <summary>
    /// Parses a JSON element into an AuthorizationResponse object.
    /// </summary>
    /// <param name="json">The JSON element containing the response data</param>
    /// <returns>A Result containing the parsed AuthorizationResponse if successful, or errors if parsing failed</returns>
    public Result<AuthorizationResponse> Parse(JsonElement json)
    {
        if (json.ValueKind == JsonValueKind.Null)
            return ParserErrors.NullResponseJson();

        if (json.ValueKind != JsonValueKind.Object)
            return ParserErrors.InvalidResponseJsonType(json.ValueKind);

        // vp_token is REQUIRED
        if (!json.TryGetProperty("vp_token", out var vpTokenElement))
            return ParserErrors.MissingVpTokenProperty();

        // Parse the VP Token - create a wrapper object if vp_token is not already an object
        var presentations = vpTokenElement.ValueKind switch
        {
            JsonValueKind.String => (object)(vpTokenElement.GetString() ?? ""),
            JsonValueKind.Array => vpTokenElement.Clone(),
            JsonValueKind.Object => vpTokenElement.Clone(),
            _ => null
        };

        if (presentations == null)
            return ParserErrors.InvalidVpTokenType(vpTokenElement.ValueKind);

        var vpToken = new VpToken { Presentations = presentations };

        // Parse optional state
        var state = json.TryGetProperty("state", out var stateElement) && stateElement.ValueKind == JsonValueKind.String 
            ? stateElement.GetString() 
            : null;

        // Parse optional id_token
        var idToken = json.TryGetProperty("id_token", out var idTokenElement) && idTokenElement.ValueKind == JsonValueKind.String 
            ? idTokenElement.GetString() 
            : null;

        var response = new AuthorizationResponse
        {
            VpToken = vpToken,
            State = state,
            IdToken = idToken
        };

        return response;
    }
}
