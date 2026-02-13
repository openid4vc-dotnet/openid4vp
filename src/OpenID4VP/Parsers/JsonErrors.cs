using System.Text.Json;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Parsers;

/// <summary>
/// Factory for creating JsonError instances with consistent error codes and messages.
/// Used when JSON document parsing fails, capturing line number information.
/// </summary>
internal static class JsonErrors
{
    /// <summary>
    /// Creates a JsonError from a JsonException, extracting line number information.
    /// </summary>
    /// <param name="jsonException">The JsonException caught during parsing.</param>
    /// <param name="jsonContent">Optional: the raw JSON that failed to parse.</param>
    /// <returns>A JsonError containing details from the exception.</returns>
    public static JsonError InvalidJsonStructure(JsonException jsonException, string? jsonContent = null)
    {
        var message = $"Invalid JSON structure: {jsonException.Message}";
        return new JsonError(message, jsonContent, jsonException.LineNumber);
    }

    /// <summary>
    /// Creates a JsonError with a custom message and optional JSON content.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="jsonContent">Optional: the raw JSON that failed to parse.</param>
    /// <param name="lineNumber">Optional: the line number where the error occurred.</param>
    /// <param name="bytePosition">Optional: the byte position where the error occurred.</param>
    /// <returns>A JsonError with the provided details.</returns>
    public static JsonError InvalidJsonStructure(string message, string? jsonContent = null, long? lineNumber = null, long? bytePosition = null)
    {
        return new JsonError(message, jsonContent, lineNumber, bytePosition);
    }
}


