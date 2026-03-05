using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

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
    /// <returns>Result with Success() if valid, or Failure with ValidationErrors if invalid</returns>
    /// <exception cref="ArgumentNullException">If response is null</exception>
    public Result Validate(AuthorizationResponse response)
    {
        if (response == null)
            throw new ArgumentNullException(nameof(response));

        var errors = new List<ValidationError>();

        ValidateVpToken(response.VpToken, errors);
        ValidateState(response.State, errors);

        return errors.Count > 0 
            ? errors.Cast<Error>().ToArray()
            : Result.Success();
    }

    /// <summary>
    /// Validates that the response's state matches the expected state from the request.
    /// This check prevents CSRF attacks.
    /// </summary>
    /// <param name="response">The response to validate</param>
    /// <param name="expectedState">The state value from the original Authorization Request</param>
    /// <returns>Result with Success() if state matches, or Failure with ValidationErrors if mismatch</returns>
    /// <exception cref="ArgumentNullException">If response or expectedState is null</exception>
    public Result ValidateStateMatch(AuthorizationResponse response, string expectedState)
    {
        if (response == null)
            throw new ArgumentNullException(nameof(response));

        if (expectedState == null)
            throw new ArgumentNullException(nameof(expectedState));

        var errors = new List<ValidationError>();

        // If response has state, it MUST match expected state
        if (!string.IsNullOrEmpty(response.State))
        {
            if (response.State != expectedState)
                errors.Add(new ValidationError($"State mismatch: response state '{response.State}' does not match expected state '{expectedState}'", "state"));
        }
        else
        {
            // State was in request but not in response
            errors.Add(new ValidationError("Response missing 'state' parameter that was present in request", "state"));
        }

        return errors.Count > 0 
            ? errors.Cast<Error>().ToArray()
            : Result.Success();
    }

    private static void ValidateVpToken(VpToken vpToken, List<ValidationError> errors)
    {
        if (vpToken == null)
        {
            errors.Add(new ValidationError("VP Token is required", "vp_token"));
            return;
        }

        if (vpToken.Presentations == null)
            errors.Add(new ValidationError("VP Token presentations cannot be null", "vp_token"));
    }

    private static void ValidateState(string? state, List<ValidationError> errors)
    {
        if (state == null)
            return;

        // State should only contain URL-safe characters if present
        // But we allow any non-empty string for now (format varies by response mode)
        if (string.IsNullOrEmpty(state))
            errors.Add(new ValidationError("State cannot be an empty string", "state"));
    }
}
