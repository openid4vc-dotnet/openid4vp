using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Presentation;

/// <summary>
/// DCQL Presentation structure (VP Token).
/// 
/// This is a JSON-encoded object containing entries where the key is the id value used for
/// a Credential Query in the DCQL query and the value is an array of one or more Presentations
/// that match the respective Credential Query.
/// 
/// Pure Data Model - validation logic is delegated to IPresentationValidator.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8.1
/// </summary>
public sealed record DcqlPresentation
{
    /// <summary>
    /// Presentations keyed by credential query ID.
    /// Each entry contains one or more presentations (string or JSON object) for that credential.
    /// 
    /// When 'multiple' is false, the array MUST contain only one Presentation.
    /// When 'multiple' is true, the array MAY contain multiple Presentations.
    /// </summary>
    [JsonExtensionData]
    public required Dictionary<string, PresentationEntry> Presentations { get; init; }

    /// <summary>
    /// Gets the presentation(s) for a specific credential query ID.
    /// </summary>
    public PresentationEntry? this[string credentialId] =>
        Presentations.TryGetValue(credentialId, out var entry) ? entry : null;
}

/// <summary>
/// A presentation entry can be either:
/// - A single presentation (string or JSON object) - for backward compatibility
/// - An array of presentations (standard format)
/// </summary>
[JsonConverter(typeof(PresentationEntryConverter))]
public sealed class PresentationEntry
{
    private readonly object[] _presentations;

    public PresentationEntry(object presentation)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        _presentations = [presentation];
    }

    public PresentationEntry(params object[] presentations)
    {
        if (presentations.Length == 0)
            throw new ArgumentException("Must contain at least one presentation", nameof(presentations));
        _presentations = presentations;
    }

    public int Count => _presentations.Length;
    public object this[int index] => _presentations[index];

    public IEnumerable<object> GetPresentations() => _presentations;

    public bool IsSinglePresentation => _presentations.Length == 1;
}

/// <summary>
/// JSON converter for PresentationEntry to handle both single value and array formats.
/// </summary>
public class PresentationEntryConverter : JsonConverter<PresentationEntry>
{
    public override PresentationEntry Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.StartArray)
        {
            var presentations = new List<object>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                    break;

                var presentation = ReadPresentation(ref reader, options);
                presentations.Add(presentation);
            }

            return new PresentationEntry(presentations.ToArray());
        }
        else
        {
            // Single presentation (legacy format)
            var presentation = ReadPresentation(ref reader, options);
            return new PresentationEntry(presentation);
        }
    }

    private static object ReadPresentation(ref Utf8JsonReader reader, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString()!,
            JsonTokenType.StartObject => JsonSerializer.Deserialize<Dictionary<string, object>>(ref reader, options)!,
            _ => throw new JsonException($"Unexpected token type for presentation: {reader.TokenType}")
        };
    }

    public override void Write(Utf8JsonWriter writer, PresentationEntry value, JsonSerializerOptions options)
    {
        if (value.IsSinglePresentation)
        {
            // Write as single value for backward compatibility (optional)
            WritePresentation(writer, value[0], options);
        }
        else
        {
            // Write as array (standard format)
            writer.WriteStartArray();
            foreach (var presentation in value.GetPresentations())
            {
                WritePresentation(writer, presentation, options);
            }
            writer.WriteEndArray();
        }
    }

    private static void WritePresentation(Utf8JsonWriter writer, object presentation, JsonSerializerOptions options)
    {
        if (presentation is string str)
        {
            writer.WriteStringValue(str);
        }
        else
        {
            JsonSerializer.Serialize(writer, presentation, options);
        }
    }
}
