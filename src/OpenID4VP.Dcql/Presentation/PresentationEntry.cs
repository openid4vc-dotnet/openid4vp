using System.Text.Json.Serialization;

namespace OpenID4VP.Dcql.Presentation;

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
