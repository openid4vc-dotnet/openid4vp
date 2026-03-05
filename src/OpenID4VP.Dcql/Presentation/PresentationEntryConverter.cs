using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Presentation;

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
