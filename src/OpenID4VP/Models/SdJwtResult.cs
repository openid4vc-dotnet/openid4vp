namespace OpenID4VP.Models;

public class SdJwtResult
{
    public string HeaderJson { get; set; } = "";
    public string PayloadJson { get; set; } = "";
    public List<Disclosure> Disclosures { get; set; } = new();
    public Dictionary<string, object> RevealedClaims { get; set; } = new();
}

public class Disclosure
{
    public string ClaimName { get; set; } = "";
    public object? Value { get; set; }
    public string Salt { get; set; } = "";
    public string RawJson { get; set; } = "";
    public string Digest { get; set; } = "";
}
