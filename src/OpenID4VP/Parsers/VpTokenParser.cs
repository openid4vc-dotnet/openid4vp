using System.Text.Json;
using System.Text.Json.Serialization;
using OpenID4VC.Core.Results;
using OpenID4VP.Models;
using OpenID4VP.Dcql.Presentation;

namespace OpenID4VP.Parsers;

/// <summary>
/// Parser for deserializing VP Tokens from JSON.
/// 
/// The VP Token is always a JSON object (dictionary) where each key is a presentation ID
/// and each value is a PresentationEntry containing one or more presentations.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.1
/// </summary>
public sealed class VpTokenParser
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new PresentationEntryConverter() }
    };

    /// <summary>
    /// Parses a JSON element into a VpToken object.
    /// </summary>
    /// <param name="json">The JSON element containing the VP Token data</param>
    /// <returns>A Result containing the parsed VpToken if successful, or errors if parsing failed</returns>
    public Result<VpToken> Parse(JsonElement json)
    {
        if (json.ValueKind == JsonValueKind.Null)
            return new ParseError("VP Token JSON cannot be null");

        // Extract presentations from vp_token property
        if (!json.TryGetProperty("vp_token", out var vpTokenElement))
            return new ParseError("VP Token must contain 'vp_token' property");

        // VP Token must always be a JSON object (dictionary)
        if (vpTokenElement.ValueKind != JsonValueKind.Object)
            return new ParseError($"vp_token must be a JSON object, got {vpTokenElement.ValueKind}");

        // Parse the object as a dictionary of id -> PresentationEntry
        Dictionary<string, PresentationEntry>? presentations;
        try
        {
            presentations = JsonSerializer.Deserialize<Dictionary<string, PresentationEntry>>(
                vpTokenElement.GetRawText(),
                JsonOptions
            ) ?? new Dictionary<string, PresentationEntry>();
        }
        catch (Exception ex)
        {
            return new ParseError($"Failed to deserialize vp_token as dictionary of presentations: {ex.Message}");
        }

        // Validate that vp_token is not empty
        if (presentations.Count == 0)
            return new ParseError("vp_token must contain at least one presentation entry");

        // Validate each presentation entry has at least one presentation
        foreach (var (presentationId, entry) in presentations)
        {
            if (string.IsNullOrWhiteSpace(presentationId))
                return new ParseError("Presentation ID cannot be null or empty");

            if (entry == null)
                return new ParseError($"Presentation entry for ID '{presentationId}' cannot be null");

            if (entry.Count == 0)
                return new ParseError($"Presentation entry for ID '{presentationId}' must contain at least one presentation");
        }

        return new VpToken
        {
            Presentations = presentations
        };
    }

    /// <summary>
    /// Parses a JSON string into a VpToken object.
    /// </summary>
    /// <param name="json">The JSON string containing the VP Token data</param>
    /// <returns>A Result containing the parsed VpToken if successful, or errors if parsing failed</returns>
    public Result<VpToken> Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new ParseError("JSON string cannot be null or empty");

        try
        {
            using var doc = JsonDocument.Parse(json);
            return Parse(doc.RootElement);
        }
        catch (JsonException ex)
        {
            return new ParseError($"Invalid JSON format: {ex.Message}");
        }
    }
}

