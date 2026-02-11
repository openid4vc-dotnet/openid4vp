using System.Text.Json;
using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Base class for all claim query types.
/// Specifies claims within a requested Credential.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.3
/// </summary>
public abstract record DcqlClaimQuery : IClaimQuery
{
    /// <summary>
    /// REQUIRED if claim_sets present, OPTIONAL otherwise.
    /// A string identifying the particular claim. The value MUST be a non-empty string consisting
    /// of alphanumeric, underscore (_) or hyphen (-) characters.
    /// </summary>
    [JsonPropertyName("id")]
    public string? Id { get; init; }

    /// <summary>
    /// OPTIONAL. An array of strings, integers or boolean values that specifies the expected values
    /// of the claim. If the values property is present, the Wallet SHOULD return the claim only if
    /// the type and value of the claim both match for at least one of the elements in the array.
    /// </summary>
    [JsonPropertyName("values")]
    public object[]? Values { get; init; }
}

/// <summary>
/// Claim query for JSON-based credentials (W3C VC, SD-JWT VC).
/// Uses JSON path pointer semantics.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 7.1
/// </summary>
public sealed record JsonClaimQuery : DcqlClaimQuery
{
    [JsonConstructor]
    internal JsonClaimQuery() { }

    /// <summary>
    /// REQUIRED. A non-empty array representing a claims path pointer that specifies the path
    /// to a claim within the Verifiable Credential.
    /// 
    /// Path components:
    /// - string: select object key
    /// - integer (>=0): select array index
    /// - null: select all array elements
    /// </summary>
    [JsonPropertyName("path")]
    public required NonEmptyArray<ClaimPathComponent> Path { get; init; }
}

/// <summary>
/// Represents a component in a JSON claims path pointer.
/// Can be a string (object key), integer (array index), or null (all array elements).
/// </summary>
[JsonConverter(typeof(ClaimPathComponentConverter))]
public readonly struct ClaimPathComponent
{
    private readonly object? _value;

    public ClaimPathComponent(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _value = key;
    }

    public ClaimPathComponent(int index)
    {
        if (index < 0)
            throw new ArgumentOutOfRangeException(nameof(index), "Array index must be non-negative");
        _value = index;
    }

    public ClaimPathComponent()
    {
        _value = null; // Represents null for "all array elements"
    }

    public bool IsString => _value is string;
    public bool IsInteger => _value is int;
    public bool IsNull => _value == null;

    public string AsString => _value as string ?? throw new InvalidOperationException("Component is not a string");
    public int AsInteger => _value is int i ? i : throw new InvalidOperationException("Component is not an integer");

    public override string ToString() => _value switch
    {
        string s => $"'{s}'",
        int i => i.ToString(),
        null => "null",
        _ => _value.ToString() ?? "unknown"
    };
}

/// <summary>
/// JSON converter for ClaimPathComponent to handle string/int/null union type.
/// </summary>
public class ClaimPathComponentConverter : JsonConverter<ClaimPathComponent>
{
    public override ClaimPathComponent Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => new ClaimPathComponent(reader.GetString()!),
            JsonTokenType.Number => new ClaimPathComponent(reader.GetInt32()),
            JsonTokenType.Null => new ClaimPathComponent(),
            _ => throw new JsonException($"Unexpected token type for claim path component: {reader.TokenType}")
        };
    }

    public override void Write(Utf8JsonWriter writer, ClaimPathComponent value, JsonSerializerOptions options)
    {
        if (value.IsString)
            writer.WriteStringValue(value.AsString);
        else if (value.IsInteger)
            writer.WriteNumberValue(value.AsInteger);
        else
            writer.WriteNullValue();
    }
}

/// <summary>
/// Claim query for ISO mdoc credentials.
/// Uses two-element path [namespace, element] or legacy namespace/claim_name syntax.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 7.2 and Appendix B.2.4
/// </summary>
public sealed record MdocClaimQuery : DcqlClaimQuery
{
    [JsonConstructor]
    internal MdocClaimQuery() { }

    /// <summary>
    /// Path syntax (Draft 24+): An array defining a claims path pointer into an mdoc.
    /// Must contain exactly two string elements: [namespace, data_element_identifier].
    /// </summary>
    [JsonPropertyName("path")]
    public string[]? Path { get; init; }

    /// <summary>
    /// OPTIONAL. A boolean that is equivalent to IntentToRetain variable defined in
    /// Section 8.3.2.1.2.1 of ISO.18013-5.
    /// </summary>
    [JsonPropertyName("intent_to_retain")]
    public bool? IntentToRetain { get; init; }

    // Legacy syntax (Draft 23) - kept for backward compatibility
    
    /// <summary>
    /// Legacy: A string that specifies the namespace of the data element within the mdoc.
    /// Example: "org.iso.18013.5.1"
    /// </summary>
    [JsonPropertyName("namespace")]
    public string? Namespace { get; init; }

    /// <summary>
    /// Legacy: A string that specifies the data element identifier within the provided namespace.
    /// Example: "first_name"
    /// </summary>
    [JsonPropertyName("claim_name")]
    public string? ClaimName { get; init; }

    /// <summary>
    /// Gets the namespace from either path or legacy namespace field.
    /// </summary>
    [JsonIgnore]
    public string? NamespaceValue => Path?.Length == 2 ? Path[0] : Namespace;

    /// <summary>
    /// Gets the element identifier from either path or legacy claim_name field.
    /// </summary>
    [JsonIgnore]
    public string? ElementValue => Path?.Length == 2 ? Path[1] : ClaimName;
}
