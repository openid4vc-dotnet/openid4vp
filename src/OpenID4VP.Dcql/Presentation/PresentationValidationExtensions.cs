using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Presentation;

/// <summary>
/// Extension methods for presentation validation.
/// Provides convenient access to IPresentationValidator functionality.
/// </summary>
public static class PresentationValidationExtensions
{
    /// <summary>
    /// Validates that this presentation matches the given query.
    /// Uses the default PresentationValidator implementation.
    /// </summary>
    /// <param name="presentation">The presentation to validate</param>
    /// <param name="query">The DCQL query to validate against</param>
    /// <returns>True if the presentation is valid for the query, false otherwise</returns>
    public static bool IsValidFor(this DcqlPresentation presentation, DcqlQuery query)
    {
        var validator = new PresentationValidator();
        return validator.Validate(presentation, query);
    }

    /// <summary>
    /// Validates that this presentation matches the given query using a custom validator.
    /// </summary>
    /// <param name="presentation">The presentation to validate</param>
    /// <param name="query">The DCQL query to validate against</param>
    /// <param name="validator">The validator to use</param>
    /// <returns>True if the presentation is valid for the query, false otherwise</returns>
    public static bool IsValidFor(this DcqlPresentation presentation, DcqlQuery query, IPresentationValidator validator)
    {
        return validator.Validate(presentation, query);
    }
}
