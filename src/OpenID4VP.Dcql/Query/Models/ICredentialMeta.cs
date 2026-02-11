namespace OpenID4VP.Dcql.Query.Models;

/// <summary>
/// Interface for credential metadata across all credential formats.
/// Enables format-agnostic handling of metadata without type switching.
/// Implements Dependency Inversion - depend on abstraction, not concrete types.
/// </summary>
public interface ICredentialMeta
{
    // Marker interface - no common properties across all metadata types
    // Allows code to depend on the abstraction rather than concrete types
}
