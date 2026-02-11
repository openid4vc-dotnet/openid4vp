using System.Text.Json.Serialization;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// The Digital Credentials Query Language (DCQL, pronounced [ˈdakl̩]) is a
/// JSON-encoded query language that allows the Verifier to request Verifiable
/// Presentations that match the query. The Verifier MAY encode constraints on the
/// combinations of credentials and claims that are requested. The Wallet evaluates
/// the query against the Verifiable Credentials it holds and returns Verifiable
/// Presentations matching the query.
/// 
/// Specification: OpenID for Verifiable Presentations 1.0, Section 6
/// </summary>
public sealed record DcqlQuery
{
    [JsonConstructor]
    internal DcqlQuery() { }

    /// <summary>
    /// REQUIRED. A non-empty array of Credential Queries that specify the requested Verifiable Credentials.
    /// </summary>
    [JsonPropertyName("credentials")]
    [JsonPropertyOrder(order: 1)]
    public required NonEmptyArray<DcqlCredentialQuery> Credentials { get; init; }

    /// <summary>
    /// OPTIONAL. A non-empty array of credential set queries that specifies additional constraints 
    /// on which of the requested Verifiable Credentials to return.
    /// </summary>
    [JsonPropertyName("credential_sets")]
    [JsonPropertyOrder(order: 1)]
    public NonEmptyArray<CredentialSetQuery>? CredentialSets { get; init; }
}
