namespace OpenID4VC.Core.Results;

/// <summary>
/// Abstract base class for all error types in the Result<T> pattern.
/// This enforces explicit error classification and enables extensibility
/// for domain-specific error types.
/// </summary>
public abstract class Error
{
    /// <summary>
    /// Gets the error code (e.g., "validation_error", "parse_error", "domain_error").
    /// Used for error type discrimination without instanceof checks.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets the human-readable error message.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Initializes a new instance of the Error class.
    /// </summary>
    /// <param name="code">The error code identifier.</param>
    /// <param name="message">The human-readable error message.</param>
    protected Error(string code, string message)
    {
        Code = code;
        Message = message;
    }

    /// <summary>
    /// Returns a string representation of the error.
    /// Format: "[Code] Message"
    /// </summary>
    public override string ToString() => $"[{Code}] {Message}";
}
