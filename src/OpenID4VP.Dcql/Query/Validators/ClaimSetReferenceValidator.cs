using FluentValidation;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validates that claim_sets reference only defined claim IDs.
/// Single Responsibility: Only validates claim set cross-references.
/// Depends on: IClaimsProvider abstraction (DIP)
/// </summary>
public class ClaimSetReferenceValidator : AbstractValidator<DcqlCredentialQuery>
{
    public ClaimSetReferenceValidator()
    {
        RuleFor(x => x.ClaimSets)
            .Must(ValidateClaimSetReferences)
            .WithMessage("claim_sets must reference only defined claim IDs")
            .When(x => x.ClaimSets != null);
    }

    private static bool ValidateClaimSetReferences(IClaimsProvider provider, NonEmptyArray<NonEmptyArray<string>>? claimSets)
    {
        if (claimSets == null)
            return true;

        var claimIds = provider.GetClaimIds();
        if (claimIds == null)
            return true; // No claims defined, validation will fail elsewhere if claim_sets exist

        var allDefinedIds = new HashSet<string>(claimIds);

        foreach (var claimSet in claimSets)
        {
            foreach (var claimId in claimSet)
            {
                if (!allDefinedIds.Contains(claimId))
                {
                    return false;
                }
            }
        }

        return true;
    }
}
