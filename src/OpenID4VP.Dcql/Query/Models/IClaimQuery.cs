namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Interface for claim queries across all credential formats.
/// Enables format-agnostic handling of claims without type switching.
/// Implements Dependency Inversion - depend on abstraction, not concrete types.
/// </summary>
public interface IClaimQuery
{
    /// <summary>
    /// REQUIRED if claim_sets present, OPTIONAL otherwise.
    /// A string identifying the particular claim.
    /// </summary>
    string? Id { get; }

    /// <summary>
    /// OPTIONAL. An array of expected claim values.
    /// </summary>
    object[]? Values { get; }
}
