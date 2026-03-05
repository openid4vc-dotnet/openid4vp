using OpenID4VC.Core.Validation;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VP.Dcql.Common;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validator for DcqlQuery according to OpenID4VP 1.0 specification.
/// Single Responsibility: Only validates query structure (not cross-references).
/// </summary>
public class DcqlQueryValidator : IValidator<DcqlQuery>
{
    public Result Validate(DcqlQuery obj)
    {
        var errors = new List<ValidationError>();

        // Validate credentials is not null
        if (obj.Credentials == null)
        {
            errors.Add(new ValidationError("credentials is REQUIRED", "credentials"));
            return errors.Cast<Error>().ToArray();
        }

        // Validate credentials is non-empty
        if (obj.Credentials.Count == 0)
        {
            errors.Add(new ValidationError("credentials must be a non-empty array", "credentials"));
            return errors.Cast<Error>().ToArray();
        }

        // Validate credential IDs are unique
        var ids = obj.Credentials.Select(c => c.Id).ToList();
        if (ids.Count != ids.Distinct().Count())
        {
            errors.Add(new ValidationError("Credential query IDs must be unique", "credentials"));
        }

        // Validate each credential query
        var credentialValidator = new DcqlCredentialQueryValidator();
        for (int i = 0; i < obj.Credentials.Count; i++)
        {
            var credentialResult = credentialValidator.Validate(obj.Credentials[i]);
            if (!credentialResult.IsSuccess)
            {
                errors.AddRange(credentialResult.Errors.Cast<ValidationError>());
            }
        }

        // Validate claim set references in each credential
        var claimSetValidator = new ClaimSetReferenceValidator();
        for (int i = 0; i < obj.Credentials.Count; i++)
        {
            var claimSetResult = claimSetValidator.Validate(obj.Credentials[i]);
            if (!claimSetResult.IsSuccess)
            {
                errors.AddRange(claimSetResult.Errors.Cast<ValidationError>());
            }
        }

        // Validate credential_sets structure
        if (obj.CredentialSets != null && obj.CredentialSets.Count == 0)
        {
            errors.Add(new ValidationError("credential_sets must be null or non-empty array", "credential_sets"));
        }

        // Validate credential set references
        if (obj.CredentialSets != null && obj.Credentials != null)
        {
            var credentialSetValidator = new CredentialSetReferenceValidator();
            var credentialSetResult = credentialSetValidator.Validate(obj);
            if (!credentialSetResult.IsSuccess)
            {
                errors.AddRange(credentialSetResult.Errors.Cast<ValidationError>());
            }
        }

        return errors.Count > 0 ? errors.Cast<Error>().ToArray() : Result.Success();
    }
}
