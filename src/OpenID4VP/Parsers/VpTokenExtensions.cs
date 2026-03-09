using OpenID4VC.Core.Results;
using OpenID4VP.Dcql.Presentation;
using OpenID4VP.Models;

namespace OpenID4VP.Parsers;

/// <summary>
/// Extension methods for VpToken to convert presentations to various formats.
/// </summary>
public static class VpTokenExtensions
{
    /// <summary>
    /// Converts a presentation entry to SdJwtResult by parsing it as an SD-JWT string.
    /// </summary>
    /// <param name="presentations">The VpToken presentations dictionary</param>
    /// <param name="presentationId">The ID of the presentation to convert</param>
    /// <returns>Result containing SdJwtResult if successful, or parsing errors</returns>
    public static Result<SdJwtResult> ToSdJwtResult(
        this Dictionary<string, PresentationEntry> presentations,
        string presentationId)
    {
        if (presentations == null)
            throw new ArgumentNullException(nameof(presentations));

        if (string.IsNullOrWhiteSpace(presentationId))
            throw new ArgumentException("Presentation ID cannot be null or empty", nameof(presentationId));

        if (!presentations.TryGetValue(presentationId, out var entry))
            return new ParseError($"Presentation with ID '{presentationId}' not found");

        // Get the first presentation (SD-JWT should be a single string)
        var presentations_enumerable = entry.GetPresentations().ToList();
        if (presentations_enumerable.Count == 0)
            return new ParseError($"Presentation entry '{presentationId}' contains no presentations");

        var sdJwtString = presentations_enumerable[0] as string;
        if (string.IsNullOrWhiteSpace(sdJwtString))
            return new ParseError($"Presentation entry '{presentationId}' is not a valid SD-JWT string");

        // Parse using SdJwtParser
        return SdJwtParser.Parse(sdJwtString);
    }

    /// <summary>
    /// Converts all presentation entries to SdJwtResult by parsing them as SD-JWT strings.
    /// </summary>
    /// <param name="presentations">The VpToken presentations dictionary</param>
    /// <returns>Dictionary of presentation ID to parsing result</returns>
    public static Dictionary<string, Result<SdJwtResult>> ToSdJwtResults(
        this Dictionary<string, PresentationEntry> presentations)
    {
        if (presentations == null)
            throw new ArgumentNullException(nameof(presentations));

        var results = new Dictionary<string, Result<SdJwtResult>>();

        foreach (var (presentationId, _) in presentations)
        {
            results[presentationId] = presentations.ToSdJwtResult(presentationId);
        }

        return results;
    }
}

