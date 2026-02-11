using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Presentation;

/// <summary>
/// Interface for validating presentations against DCQL queries.
/// Enables presentation validation logic to be separated from the data model.
/// </summary>
public interface IPresentationValidator
{
    /// <summary>
    /// Validates that presentation IDs match the query credential IDs and
    /// respects the 'multiple' constraint of each credential.
    /// </summary>
    /// <param name="presentation">The presentation to validate</param>
    /// <param name="query">The DCQL query to validate against</param>
    /// <returns>True if valid, false otherwise</returns>
    bool Validate(DcqlPresentation presentation, DcqlQuery query);
}
