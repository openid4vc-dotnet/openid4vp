using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Common;

/// <summary>
/// Represents a non-empty array.
/// </summary>
/// <typeparam name="T">The type of elements in the array.</typeparam>
[JsonConverter(typeof(NonEmptyArrayConverterFactory))]
public sealed class NonEmptyArray<T> : IReadOnlyList<T>
{
    private readonly T[] _items;

    public NonEmptyArray(T first, params T[] rest)
    {
        ArgumentNullException.ThrowIfNull(first);
        
        _items = new T[rest.Length + 1];
        _items[0] = first;
        Array.Copy(rest, 0, _items, 1, rest.Length);
    }

    public NonEmptyArray(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        _items = items.ToArray();
        
        if (_items.Length == 0)
        {
            throw new ArgumentException("Array must contain at least one element", nameof(items));
        }
    }

    public T this[int index] => _items[index];
    public int Count => _items.Length;

    public IEnumerator<T> GetEnumerator() => ((IEnumerable<T>)_items).GetEnumerator();
    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => _items.GetEnumerator();

    public static implicit operator T[](NonEmptyArray<T> array) => array._items;
    
    public static NonEmptyArray<T>? FromArray(T[]? array)
    {
        if (array == null || array.Length == 0)
        {
            return null;
        }
        
        return new NonEmptyArray<T>(array);
    }
}

/// <summary>
/// Extension methods for NonEmptyArray.
/// </summary>
public static class NonEmptyArrayExtensions
{
    public static NonEmptyArray<T>? ToNonEmptyArray<T>(this IEnumerable<T>? source)
    {
        if (source == null)
        {
            return null;
        }

        var array = source.ToArray();
        return array.Length == 0 ? null : new NonEmptyArray<T>(array);
    }

    public static bool IsNonEmpty<T>(this T[]? array) => array is { Length: > 0 };
}

/// <summary>
/// JSON converter factory for NonEmptyArray&lt;T&gt;.
/// </summary>
public class NonEmptyArrayConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert)
    {
        if (!typeToConvert.IsGenericType)
            return false;

        return typeToConvert.GetGenericTypeDefinition() == typeof(NonEmptyArray<>);
    }

    public override JsonConverter? CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        Type elementType = typeToConvert.GetGenericArguments()[0];
        Type converterType = typeof(NonEmptyArrayConverter<>).MakeGenericType(elementType);
        
        return (JsonConverter?)Activator.CreateInstance(converterType);
    }
}

/// <summary>
/// JSON converter for NonEmptyArray&lt;T&gt;.
/// Serializes as a JSON array and deserializes while validating non-empty constraint.
/// </summary>
/// <typeparam name="T">The type of elements in the array.</typeparam>
public class NonEmptyArrayConverter<T> : JsonConverter<NonEmptyArray<T>>
{
    public override NonEmptyArray<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartArray)
        {
            throw new JsonException($"Expected array for NonEmptyArray<{typeof(T).Name}>, got {reader.TokenType}");
        }

        var items = new List<T>();
        
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray)
                break;

            var item = JsonSerializer.Deserialize<T>(ref reader, options);
            if (item != null)
                items.Add(item);
        }

        if (items.Count == 0)
        {
            throw new JsonException($"NonEmptyArray<{typeof(T).Name}> cannot be empty");
        }

        return new NonEmptyArray<T>(items.ToArray());
    }

    public override void Write(Utf8JsonWriter writer, NonEmptyArray<T> value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        
        foreach (var item in value)
        {
            JsonSerializer.Serialize(writer, item, options);
        }
        
        writer.WriteEndArray();
    }
}
