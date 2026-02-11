namespace OpenID4VP.Common;

/// <summary>
/// Result of a validation operation.
/// </summary>
public sealed record ValidationResult
{
    /// <summary>
    /// Indicates whether the validation succeeded.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Collection of validation errors. Empty if validation succeeded.
    /// </summary>
    public required IReadOnlyList<string> Errors { get; init; }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static ValidationResult Success() => new() { IsValid = true, Errors = [] };

    /// <summary>
    /// Creates a failed validation result with the given errors.
    /// </summary>
    public static ValidationResult Failure(params string[] errors) =>
        new() { IsValid = false, Errors = errors.ToList() };

    /// <summary>
    /// Creates a failed validation result with the given errors.
    /// </summary>
    public static ValidationResult Failure(IEnumerable<string> errors) =>
        new() { IsValid = false, Errors = errors.ToList() };
}
