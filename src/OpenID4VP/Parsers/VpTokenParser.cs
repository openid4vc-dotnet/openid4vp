using System.Text.Json;
using OpenID4VP.Models;

namespace OpenID4VP.Parsers;

/// <summary>
/// Parser for deserializing VP Tokens from JSON.
/// 
/// Handles the JSON structure of VP Tokens which can contain presentations in various formats.
/// Keeps presentation structure opaque (format-agnostic) to support multiple credential formats.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.1
/// </summary>
public sealed class VpTokenParser
{
    /// <summary>
    /// Parses a JSON element into a VpToken object.
    /// </summary>
    /// <param name="json">The JSON element containing the VP Token data</param>
    /// <returns>A parsed VpToken object</returns>
    /// <exception cref="ArgumentNullException">If json is null</exception>
    /// <exception cref="InvalidOperationException">If required properties are missing</exception>
    public VpToken Parse(JsonElement json)
    {
        if (json.ValueKind == JsonValueKind.Null)
            throw new ArgumentNullException(nameof(json), "VP Token JSON cannot be null");

        // Extract presentations from vp_token property
        if (!json.TryGetProperty("vp_token", out var vpTokenElement))
            throw new InvalidOperationException("VP Token must contain 'vp_token' property");

        // Presentations can be a string (JWT), array, or object - keep opaque
        var presentations = vpTokenElement.ValueKind switch
        {
            JsonValueKind.String => (object)(vpTokenElement.GetString() ?? ""),
            JsonValueKind.Array => vpTokenElement.Clone(),
            JsonValueKind.Object => vpTokenElement.Clone(),
            _ => throw new InvalidOperationException($"vp_token must be a string, array, or object, got {vpTokenElement.ValueKind}")
        };

        return new VpToken
        {
            Presentations = presentations
        };
    }

    /// <summary>
    /// Parses a JSON string into a VpToken object.
    /// </summary>
    /// <param name="json">The JSON string containing the VP Token data</param>
    /// <returns>A parsed VpToken object</returns>
    /// <exception cref="ArgumentException">If json is null or empty</exception>
    /// <exception cref="JsonException">If json is not valid JSON</exception>
    /// <exception cref="InvalidOperationException">If required properties are missing</exception>
    public VpToken Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            throw new ArgumentException("JSON string cannot be null or empty", nameof(json));

        using var doc = JsonDocument.Parse(json);
        return Parse(doc.RootElement);
    }
}
