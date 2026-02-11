using FluentValidation;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Common;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validator for DcqlCredentialQuery and its derived types.
/// Depends on: IClaimsProvider abstraction (DIP) for accessing claims
/// </summary>
public class DcqlCredentialQueryValidator : AbstractValidator<DcqlCredentialQuery>
{
    public DcqlCredentialQueryValidator()
    {
        RuleFor(x => x.Id)
            .NotEmpty()
            .WithMessage("id is REQUIRED")
            .Must(ValidationPatterns.IsValidId)
            .WithMessage("id must contain only alphanumeric, underscore, or hyphen characters");

        RuleFor(x => x.Format)
            .NotEmpty()
            .WithMessage("format is REQUIRED")
            .Must(f => new[] { CredentialFormats.MsoMdoc, CredentialFormats.JwtVcJson, CredentialFormats.LdpVc, CredentialFormats.VcSdJwt, CredentialFormats.DcSdJwt }.Contains(f))
            .WithMessage($"format must be one of: {CredentialFormats.MsoMdoc}, {CredentialFormats.JwtVcJson}, {CredentialFormats.LdpVc}, {CredentialFormats.VcSdJwt}, {CredentialFormats.DcSdJwt}");

        RuleFor(x => x.ClaimSets)
            .Must(ValidateClaimSetReferences)
            .WithMessage("claim_sets must reference only defined claim IDs")
            .When(x => x.ClaimSets != null);

        // Format-specific validation
        RuleFor(x => x)
            .Must(x => x is not W3cVcCredentialQuery w3c || w3c.Meta != null)
            .WithMessage("meta is REQUIRED for W3C VC format");

        RuleFor(x => x)
            .Must(x => x is not W3cVcCredentialQuery w3c || w3c.Meta?.TypeValues?.Count > 0)
            .WithMessage("type_values is REQUIRED and must be non-empty for W3C VC format");
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
