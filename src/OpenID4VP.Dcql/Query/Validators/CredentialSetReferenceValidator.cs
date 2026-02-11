using FluentValidation;
using OpenID4VP.Dcql.Query.Models;

namespace OpenID4VP.Dcql.Query.Validators;

/// <summary>
/// Validates that credential_set references only defined credential query IDs.
/// Single Responsibility: Only validates credential set cross-references.
/// </summary>
public class CredentialSetReferenceValidator : AbstractValidator<DcqlQuery>
{
    public CredentialSetReferenceValidator()
    {
        RuleFor(x => x)
            .Must(ValidateCredentialSetReferences)
            .WithMessage(x => GetCredentialSetErrorMessage(x))
            .When(x => x.CredentialSets != null && x.Credentials != null);
    }

    private static bool ValidateCredentialSetReferences(DcqlQuery query)
    {
        if (query.CredentialSets == null || query.Credentials == null)
            return true;

        var credentialIds = new HashSet<string>(query.Credentials.Select(c => c.Id));
        var undefinedIds = new List<string>();

        foreach (var credentialSet in query.CredentialSets)
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

        return undefinedIds.Count == 0;
    }

    private static string GetCredentialSetErrorMessage(DcqlQuery query)
    {
        if (query.CredentialSets == null || query.Credentials == null)
            return string.Empty;

        var credentialIds = new HashSet<string>(query.Credentials.Select(c => c.Id));
        var undefinedIds = new List<string>();

        foreach (var credentialSet in query.CredentialSets)
        {
            foreach (var option in credentialSet.Options)
            {
                foreach (var credentialId in option)
                {
                    if (!credentialIds.Contains(credentialId) && !undefinedIds.Contains(credentialId))
                    {
                        undefinedIds.Add(credentialId);
                    }
                }
            }
        }

        return $"Credential set contains undefined credential id(s): '{string.Join(", ", undefinedIds)}'";
    }
}
