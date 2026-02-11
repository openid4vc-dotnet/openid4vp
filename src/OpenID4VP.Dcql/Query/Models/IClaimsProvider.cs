namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Interface for credential queries that provide claims information.
/// Enables validators and other components to extract claims without type switching.
/// </summary>
public interface IClaimsProvider
{
    /// <summary>
    /// Gets the claim IDs defined in this credential query.
    /// </summary>
    /// <returns>Enumerable of claim IDs, or null if no claims are defined</returns>
    IEnumerable<string>? GetClaimIds();
}
