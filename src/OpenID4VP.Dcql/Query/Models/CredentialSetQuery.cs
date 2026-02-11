using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// A Credential Set Query is an object representing a request for one or more credentials
/// to satisfy a particular use case with the Verifier.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6.2
/// </summary>
public sealed record CredentialSetQuery
{
    [JsonConstructor]
    internal CredentialSetQuery() { }

    /// <summary>
    /// REQUIRED. A non-empty array, where each value in the array is a list of Credential Query
    /// identifiers representing one set of Credentials that satisfies the use case.
    /// </summary>
    [JsonPropertyName("options")]
    public required NonEmptyArray<string[]> Options { get; init; }

    /// <summary>
    /// OPTIONAL. Boolean which indicates whether this set of Credentials is required to satisfy
    /// the particular use case at the Verifier. If omitted, the default value is 'true'.
    /// </summary>
    [JsonPropertyName("required")]
    public bool Required { get; init; } = true;
}
