using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Presentation;

/// <summary>
/// Validates presentations against DCQL queries.
/// Single Responsibility: Only validates presentation-query relationships.
/// </summary>
public sealed class PresentationValidator : IPresentationValidator
{
    /// <summary>
    /// Validates that presentation IDs match the query credential IDs and
    /// respects the 'multiple' constraint of each credential.
    /// </summary>
    /// <param name="presentation">The presentation to validate</param>
    /// <param name="query">The DCQL query to validate against</param>
    /// <returns>True if valid, false otherwise</returns>
    public bool Validate(DcqlPresentation presentation, DcqlQuery query)
    {
        var queryIds = new HashSet<string>(query.Credentials.Select(c => c.Id));
        
        // All presentation IDs must exist in query
        foreach (var presentationId in presentation.Presentations.Keys)
        {
            if (!queryIds.Contains(presentationId))
                return false;
        }

        // Validate multiple constraint
        foreach (var credential in query.Credentials)
        {
            if (presentation.Presentations.TryGetValue(credential.Id, out var entry))
            {
                if (!credential.Multiple && entry.Count > 1)
                    return false;
            }
        }

        return true;
    }
}
