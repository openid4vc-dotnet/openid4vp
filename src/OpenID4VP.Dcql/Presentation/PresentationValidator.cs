using OpenID4VC.Core.Results;
using OpenID4VC.Core.Validation;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Presentation;

/// <summary>
/// Validates presentations against DCQL queries.
/// Single Responsibility: Only validates presentation-query relationships.
/// </summary>
public sealed class PresentationValidator : IValidator<DcqlPresentation, DcqlQuery>
{
    /// <summary>
    /// Validates that presentation IDs match the query credential IDs and
    /// respects the 'multiple' constraint of each credential.
    /// </summary>
    /// <param name="presentation">The presentation to validate</param>
    /// <param name="query">The DCQL query to validate against</param>
    /// <returns>Result with Success() if valid, or Failure with ValidationErrors if invalid</returns>
    public Result Validate(DcqlPresentation presentation, DcqlQuery query)
    {
        var errors = new List<ValidationError>();
        var queryIds = new HashSet<string>(query.Credentials.Select(c => c.Id));
        
        // All presentation IDs must exist in query
        foreach (var presentationId in presentation.Presentations.Keys)
        {
            if (!queryIds.Contains(presentationId))
            {
                errors.Add(new ValidationError($"Presentation ID '{presentationId}' does not exist in query", "presentations"));
            }
        }

        // Validate multiple constraint
        foreach (var credential in query.Credentials)
        {
            if (presentation.Presentations.TryGetValue(credential.Id, out var entry))
            {
                if (!credential.Multiple && entry.Count > 1)
                {
                    errors.Add(new ValidationError($"Credential '{credential.Id}' does not allow multiple presentations but {entry.Count} were provided", credential.Id));
                }
            }
        }

        return errors.Count > 0 ? errors.Cast<Error>().ToArray() : Result.Success();
    }
}
