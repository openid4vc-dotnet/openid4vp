namespace OpenID4VC.Core.Results;

/// <summary>
/// Non-generic result container for success/failure operations with no return value.
/// Used primarily for validation operations where only success or failure matters.
/// </summary>
public sealed record Result
{
    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// Gets the list of errors that occurred. Only populated if IsSuccess is false.
    /// </summary>
    public IReadOnlyList<Error> Errors { get; init; }

    private Result(bool isSuccess, IReadOnlyList<Error> errors)
    {
        IsSuccess = isSuccess;
        Errors = errors;
    }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <returns>A successful Result with no errors.</returns>
    public static Result Success()
    {
        return new Result(isSuccess: true, errors: []);
    }

    /// <summary>
    /// Creates a failed result with the given error(s).
    /// </summary>
    /// <param name="errors">The error(s) that occurred.</param>
    /// <returns>A failed Result containing the error(s).</returns>
    public static Result Failure(params Error[] errors)
    {
        if (errors.Length == 0)
            throw new ArgumentException("At least one error must be provided", nameof(errors));
        
        return new Result(isSuccess: false, errors: errors);
    }

    /// <summary>
    /// Creates a failed result with the given error(s).
    /// </summary>
    /// <param name="errors">The error(s) that occurred.</param>
    /// <returns>A failed Result containing the error(s).</returns>
    public static Result Failure(IEnumerable<Error> errors)
    {
        var errorList = errors.ToList();
        if (errorList.Count == 0)
            throw new ArgumentException("At least one error must be provided", nameof(errors));
        
        return new Result(isSuccess: false, errors: errorList);
    }

    /// <summary>
    /// Returns a string representation of the result.
    /// Shows "Success" for success or "Failure: {Count} error(s)" for failures.
    /// </summary>
    public override string ToString()
    {
        return IsSuccess
            ? "Success"
            : $"Failure: {Errors.Count} error(s) - {string.Join(", ", Errors.Select(e => e.Code))}";
    }

    /// <summary>
    /// Implicitly converts a failed Result to a single Error.
    /// Gets the first error if multiple errors exist.
    /// Throws InvalidOperationException if the result is successful.
    /// Usage: Error error = result;  (only works if result.IsSuccess is false)
    /// </summary>
    /// <param name="result">The result to convert.</param>
    /// <returns>The first error from the result.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is successful or has no errors.</exception>
    public static implicit operator Error(Result result)
    {
        if (result.IsSuccess)
            throw new InvalidOperationException("Cannot convert successful Result to Error. Check IsSuccess first.");
        if (result.Errors.Count == 0)
            throw new InvalidOperationException("Result has no errors to convert.");
        return result.Errors[0];
    }

    /// <summary>
    /// Implicitly converts a failed Result to an Error array.
    /// Throws InvalidOperationException if the result is successful.
    /// Usage: Error[] errors = result;  (only works if result.IsSuccess is false)
    /// </summary>
    /// <param name="result">The result to convert.</param>
    /// <returns>Array of all errors from the result.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is successful.</exception>
    public static implicit operator Error[](Result result)
    {
        if (result.IsSuccess)
            throw new InvalidOperationException("Cannot convert successful Result to Error[]. Check IsSuccess first.");
        return result.Errors.ToArray();
    }

    public static implicit operator Result(Error error) => Failure([error]);

    public static implicit operator Result(Error[] errors) => Failure(errors);
}
