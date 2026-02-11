using OpenID4VP.Common;
using OpenID4VP.Models;

namespace OpenID4VP.Validators;

/// <summary>
/// Validator for AuthorizationResponse objects.
/// Validates spec compliance and security requirements.
///
/// Specification: OpenID for Verifiable Presentations 1.0, Section 8
/// </summary>
public sealed class AuthorizationResponseValidator : IValidator<AuthorizationResponse>
{
    /// <summary>
    /// Validates the AuthorizationResponse for spec compliance.
    /// </summary>
    /// <param name="response">The response to validate</param>
    /// <returns>ValidationResult with success or list of errors</returns>
    /// <exception cref="ArgumentNullException">If response is null</exception>
    public ValidationResult Validate(AuthorizationResponse response)
    {
        if (response == null)
            throw new ArgumentNullException(nameof(response));

        var errors = new List<string>();

        ValidateVpToken(response.VpToken, errors);
        ValidateState(response.State, errors);

        return errors.Count > 0 
            ? ValidationResult.Failure(errors) 
            : ValidationResult.Success();
    }

    /// <summary>
    /// Validates that the response's state matches the expected state from the request.
    /// This check prevents CSRF attacks.
    /// </summary>
    /// <param name="response">The response to validate</param>
    /// <param name="expectedState">The state value from the original Authorization Request</param>
    /// <returns>ValidationResult indicating if state matches</returns>
    /// <exception cref="ArgumentNullException">If response or expectedState is null</exception>
    public ValidationResult ValidateStateMatch(AuthorizationResponse response, string expectedState)
    {
        if (response == null)
            throw new ArgumentNullException(nameof(response));

        if (expectedState == null)
            throw new ArgumentNullException(nameof(expectedState));

        var errors = new List<string>();

        // If response has state, it MUST match expected state
        if (!string.IsNullOrEmpty(response.State))
        {
            if (response.State != expectedState)
                errors.Add($"State mismatch: response state '{response.State}' does not match expected state '{expectedState}'");
        }
        else
        {
            // State was in request but not in response
            errors.Add("Response missing 'state' parameter that was present in request");
        }

        return errors.Count > 0 
            ? ValidationResult.Failure(errors) 
            : ValidationResult.Success();
    }

    private static void ValidateVpToken(VpToken vpToken, List<string> errors)
    {
        if (vpToken == null)
        {
            errors.Add("VP Token is required");
            return;
        }

        if (vpToken.Presentations == null)
            errors.Add("VP Token presentations cannot be null");
    }

    private static void ValidateState(string? state, List<string> errors)
    {
        if (state == null)
            return;

        // State should only contain URL-safe characters if present
        // But we allow any non-empty string for now (format varies by response mode)
        if (string.IsNullOrEmpty(state))
            errors.Add("State cannot be an empty string");
    }
}
