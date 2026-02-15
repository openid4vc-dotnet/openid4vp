using OpenID4VP.Dcql.Query.Models;
using System.Text.Json;

namespace OpenID4VP.Dcql.Query.Serialization;

/// <summary>
/// Provides JSON serialization for DCQL queries suitable for Authorization Requests.
/// The dcql_query parameter in OpenID for Verifiable Presentations requires the query
/// to be JSON-serialized.
/// 
/// Usage:
/// var json = DcqlQuerySerializer.Serialize(query);
/// var query = DcqlQuerySerializer.Deserialize(json);
/// </summary>
public static class DcqlQuerySerializer
{
    private static readonly JsonSerializerOptions DefaultOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,

        // + sign is ascaped to \u002B by default in System.Text.Json, which can cause issues with certain characters in query parameters.
        // Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Serializes a DcqlQuery to JSON for use in Authorization Request dcql_query parameter.
    /// </summary>
    /// <param name="query">The DCQL query to serialize</param>
    /// <param name="indented">Whether to format with indentation for readability (default: false)</param>
    /// <returns>JSON representation of the query</returns>
    public static string Serialize(DcqlQuery query, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(query);
        
        var options = indented 
            ? new JsonSerializerOptions(DefaultOptions) { WriteIndented = true }
            : DefaultOptions;
        
        return JsonSerializer.Serialize(query, options);
    }

    /// <summary>
    /// Deserializes a JSON string to a DcqlQuery.
    /// </summary>
    /// <param name="json">JSON representation of the query</param>
    /// <returns>Deserialized DcqlQuery</returns>
    /// <exception cref="JsonException">Thrown if JSON is invalid or doesn't match DcqlQuery schema</exception>
    public static DcqlQuery Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        
        if (string.IsNullOrWhiteSpace(json))
        {
            throw new JsonException("JSON string cannot be empty");
        }

        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, DefaultOptions);
        
        return deserialized ?? throw new JsonException("Failed to deserialize DcqlQuery");
    }

    /// <summary>
    /// Serializes a DcqlQuery to JSON bytes for use in Authorization Request.
    /// </summary>
    /// <param name="query">The DCQL query to serialize</param>
    /// <returns>UTF-8 encoded JSON bytes</returns>
    public static byte[] SerializeToUtf8Bytes(DcqlQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        
        return JsonSerializer.SerializeToUtf8Bytes(query, DefaultOptions);
    }

    /// <summary>
    /// Deserializes UTF-8 encoded JSON bytes to a DcqlQuery.
    /// </summary>
    /// <param name="json">UTF-8 encoded JSON bytes</param>
    /// <returns>Deserialized DcqlQuery</returns>
    /// <exception cref="JsonException">Thrown if JSON is invalid or doesn't match DcqlQuery schema</exception>
    public static DcqlQuery DeserializeFromUtf8Bytes(byte[] json)
    {
        ArgumentNullException.ThrowIfNull(json);
        
        var deserialized = JsonSerializer.Deserialize<DcqlQuery>(json, DefaultOptions);
        
        return deserialized ?? throw new JsonException("Failed to deserialize DcqlQuery from bytes");
    }

    /// <summary>
    /// Gets the default JSON serializer options used for DCQL queries.
    /// </summary>
    /// <returns>JsonSerializerOptions configured for DCQL</returns>
    public static JsonSerializerOptions GetDefaultOptions() => new(DefaultOptions);
}
