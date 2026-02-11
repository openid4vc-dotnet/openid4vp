using FluentValidation;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validator for DcqlQuery according to OpenID4VP 1.0 specification.
/// Single Responsibility: Only validates query structure (not cross-references).
/// </summary>
public class DcqlQueryValidator : AbstractValidator<DcqlQuery>
{
    public DcqlQueryValidator()
    {
        // Structure validation
        RuleFor(x => x.Credentials)
            .NotNull()
            .WithMessage("credentials is REQUIRED")
            .Must(c => c.Count > 0)
            .WithMessage("credentials must be a non-empty array");

        RuleFor(x => x.Credentials)
            .Must(HaveUniqueIds)
            .WithMessage("Credential query IDs must be unique")
            .When(x => x.Credentials != null);

        RuleForEach(x => x.Credentials)
            .SetValidator(new DcqlCredentialQueryValidator())
            .When(x => x.Credentials != null);

        RuleForEach(x => x.Credentials)
            .SetValidator(new ClaimSetReferenceValidator())
            .When(x => x.Credentials != null);

        RuleFor(x => x.CredentialSets)
            .Must(c => c == null || c.Count > 0)
            .WithMessage("credential_sets must be null or non-empty array");

        // Cross-reference validation delegated to specialized validator
        RuleFor(x => x)
            .SetValidator(new CredentialSetReferenceValidator())
            .When(x => x.CredentialSets != null && x.Credentials != null);
    }

    private static bool HaveUniqueIds(NonEmptyArray<DcqlCredentialQuery> credentials)
    {
        var ids = credentials.Select(c => c.Id).ToList();
        return ids.Count == ids.Distinct().Count();
    }
}
