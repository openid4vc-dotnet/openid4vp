using OpenID4VC.Core.Validation;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Common;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validator for DcqlCredentialQuery and its derived types.
/// Depends on: IClaimsProvider abstraction (DIP) for accessing claims
/// </summary>
public class DcqlCredentialQueryValidator : IValidator<DcqlCredentialQuery>
{
    public Result Validate(DcqlCredentialQuery obj)
    {
        var errors = new List<ValidationError>();

        // Validate ID is not empty
        if (string.IsNullOrEmpty(obj.Id))
        {
            errors.Add(new ValidationError("id is REQUIRED", "id"));
        }
        else if (!OpenID4VP.Dcql.Common.ValidationPatterns.IsValidId(obj.Id))
        {
            errors.Add(new ValidationError("id must contain only alphanumeric, underscore, or hyphen characters", "id"));
        }

        // Validate format is not empty
        if (string.IsNullOrEmpty(obj.Format))
        {
            errors.Add(new ValidationError("format is REQUIRED", "format"));
        }
        else
        {
            var validFormats = new[] { CredentialFormats.MsoMdoc, CredentialFormats.JwtVcJson, CredentialFormats.LdpVc, CredentialFormats.VcSdJwt, CredentialFormats.DcSdJwt };
            if (!validFormats.Contains(obj.Format))
            {
                errors.Add(new ValidationError($"format must be one of: {CredentialFormats.MsoMdoc}, {CredentialFormats.JwtVcJson}, {CredentialFormats.LdpVc}, {CredentialFormats.VcSdJwt}, {CredentialFormats.DcSdJwt}", "format"));
            }
        }

        // Validate claim set references
        if (obj.ClaimSets != null && !ValidateClaimSetReferences(obj, obj.ClaimSets))
        {
            errors.Add(new ValidationError("claim_sets must reference only defined claim IDs", "claim_sets"));
        }

        // Validate format-specific constraints
        if (obj is W3cVcCredentialQuery w3c)
        {
            if (w3c.Meta == null)
            {
                errors.Add(new ValidationError("meta is REQUIRED for W3C VC format", "meta"));
            }
            else if (w3c.Meta.TypeValues == null || w3c.Meta.TypeValues.Count == 0)
            {
                errors.Add(new ValidationError("type_values is REQUIRED and must be non-empty for W3C VC format", "type_values"));
            }
        }

        return errors.Count > 0 ? errors.Cast<Error>().ToArray() : Result.Success();
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
