namespace OpenID4VP.Validators;

using OpenID4VC.Core.Results;

internal static class ValidatorErrors
{
    public static Error FromValidator(string message) 
        => new ValidationError(message);
}
