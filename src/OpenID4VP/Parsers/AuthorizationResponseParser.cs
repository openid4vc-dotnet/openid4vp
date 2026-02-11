using System.Text.Json;
using System.Text.Json.Serialization;
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
    /// <returns>A parsed AuthorizationResponse object</returns>
    /// <exception cref="ArgumentException">If json is null or empty</exception>
    /// <exception cref="JsonException">If json is not valid JSON</exception>
    /// <exception cref="InvalidOperationException">If required properties are missing</exception>
    public AuthorizationResponse Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("JSON string cannot be null or empty", nameof(json));

        using var doc = JsonDocument.Parse(json);
        return Parse(doc.RootElement);
    }

    /// <summary>
    /// Parses a JSON element into an AuthorizationResponse object.
    /// </summary>
    /// <param name="json">The JSON element containing the response data</param>
    /// <returns>A parsed AuthorizationResponse object</returns>
    /// <exception cref="ArgumentNullException">If json is null</exception>
    /// <exception cref="InvalidOperationException">If required properties are missing</exception>
    public AuthorizationResponse Parse(JsonElement json)
    {
        if (json.ValueKind == JsonValueKind.Null)
            throw new ArgumentNullException(nameof(json), "Response JSON cannot be null");

        if (json.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"Response JSON must be an object, got {json.ValueKind}");

        // vp_token is REQUIRED
        if (!json.TryGetProperty("vp_token", out var vpTokenElement))
            throw new InvalidOperationException("Response must contain 'vp_token' property");

        // Parse the VP Token - create a wrapper object if vp_token is not already an object
        VpToken vpToken;
        // vp_token is a string, array, or object - wrap it in a VpToken
        vpToken = new VpToken { Presentations = vpTokenElement.ValueKind switch
        {
            JsonValueKind.String => (object)(vpTokenElement.GetString() ?? ""),
            JsonValueKind.Array => vpTokenElement.Clone(),
            JsonValueKind.Object => vpTokenElement.Clone(),
            _ => throw new InvalidOperationException($"vp_token must be a string, array, or object, got {vpTokenElement.ValueKind}")
        }};

        // Parse optional state
        var state = json.TryGetProperty("state", out var stateElement) && stateElement.ValueKind == JsonValueKind.String 
            ? stateElement.GetString() 
            : null;

        // Parse optional id_token
        var idToken = json.TryGetProperty("id_token", out var idTokenElement) && idTokenElement.ValueKind == JsonValueKind.String 
            ? idTokenElement.GetString() 
            : null;

        return new AuthorizationResponse
        {
            VpToken = vpToken,
            State = state,
            IdToken = idToken
        };
    }

    /// <summary>
    /// Parses an AuthorizationResponse from form parameters (typically from direct_post response mode).
    /// </summary>
    /// <param name="parameters">Dictionary of form parameters</param>
    /// <returns>A parsed AuthorizationResponse object</returns>
    /// <exception cref="ArgumentNullException">If parameters is null</exception>
    /// <exception cref="InvalidOperationException">If required parameters are missing</exception>
    public AuthorizationResponse ParseFormParameters(Dictionary<string, string> parameters)
    {
        if (parameters == null)
            throw new ArgumentNullException(nameof(parameters));

        if (!parameters.TryGetValue("vp_token", out var vpTokenStr))
            throw new InvalidOperationException("Response must contain 'vp_token' parameter");

        var vpToken = new VpToken { Presentations = vpTokenStr };

        parameters.TryGetValue("state", out var state);
        parameters.TryGetValue("id_token", out var idToken);

        return new AuthorizationResponse
        {
            VpToken = vpToken,
            State = state,
            IdToken = idToken
        };
    }
}
