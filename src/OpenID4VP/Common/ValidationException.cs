namespace OpenID4VP.Common;

/// <summary>
/// Exception thrown when validation fails during builder construction.
/// 
/// This exception wraps a ValidationResult and provides a detailed error message
/// containing all validation errors found.
/// </summary>
public sealed class ValidationException : InvalidOperationException
{
    /// <summary>
    /// Gets the validation result containing detailed error information.
    /// </summary>
    public ValidationResult ValidationResult { get; }

    /// <summary>
    /// Initializes a new instance of the ValidationException class.
    /// </summary>
    /// <param name="validationResult">The validation result containing the errors</param>
    public ValidationException(ValidationResult validationResult)
        : base(BuildMessage(validationResult))
    {
        ValidationResult = validationResult;
    }

    /// <summary>
    /// Initializes a new instance of the ValidationException class with a custom message.
    /// </summary>
    /// <param name="message">The error message</param>
    /// <param name="validationResult">The validation result containing the errors</param>
    public ValidationException(string message, ValidationResult validationResult)
        : base(message)
    {
        ValidationResult = validationResult;
    }

    /// <summary>
    /// Builds a formatted error message from the validation result.
    /// </summary>
    private static string BuildMessage(ValidationResult result)
    {
        if (result.IsValid)
            return "Validation succeeded but exception was raised. This should not happen.";

        if (result.Errors.Count == 0)
            return "Validation failed with no error details provided.";

        if (result.Errors.Count == 1)
            return result.Errors[0];

        // Multiple errors - format as bullet list
        var errorLines = result.Errors.Select(e => $"  • {e}");
        return "Validation failed with the following errors:\n" + string.Join("\n", errorLines);
    }
}
