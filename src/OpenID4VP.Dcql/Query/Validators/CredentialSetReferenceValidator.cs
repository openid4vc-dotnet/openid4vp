using OpenID4VC.Core.Validation;
using OpenID4VP.Dcql.Query.Models;
using OpenID4VC.Core.Results;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validates that credential_set references only defined credential query IDs.
/// Single Responsibility: Only validates credential set cross-references.
/// </summary>
public class CredentialSetReferenceValidator : IValidator<DcqlQuery>
{
    public Result Validate(DcqlQuery obj)
    {
        var errors = new List<ValidationError>();

        if (obj.CredentialSets != null && obj.Credentials != null)
        {
            var credentialIds = new HashSet<string>(obj.Credentials.Select(c => c.Id));
            var undefinedIds = new List<string>();

            foreach (var credentialSet in obj.CredentialSets)
            {
                foreach (var option in credentialSet.Options)
                {
                    foreach (var credentialId in option)
                    {
                        if (!credentialIds.Contains(credentialId))
                        {
                            undefinedIds.Add(credentialId);
                        }
                    }
                }
            }

            if (undefinedIds.Count > 0)
            {
                var message = $"Credential set contains undefined credential id(s): '{string.Join(", ", undefinedIds)}'";
                errors.Add(new ValidationError(message, "credential_sets"));
            }
        }

        return errors.Count > 0 ? errors.Cast<Error>().ToArray() : Result.Success();
    }
}
