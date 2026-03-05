namespace OpenID4VC.Core.Results;

/// <summary>
/// Universal success/failure container for operations that can fail.
/// Replaces throwing exceptions for expected failures and ValidationResult
/// for operations beyond validation (building, parsing, business logic).
/// 
/// Result<T> is immutable and supports functional composition via Map, Bind, Tap methods.
/// </summary>
/// <typeparam name="T">The type of the success value.</typeparam>
public sealed record Result<T>
{
    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// Gets the success value. Only valid if IsSuccess is true.
    /// Accessing this when IsSuccess is false returns null.
    /// </summary>
    public T? Value { get; init; }

    /// <summary>
    /// Gets the list of errors that occurred. Only populated if IsSuccess is false.
    /// </summary>
    public IReadOnlyList<Error> Errors { get; init; }

    private Result(bool isSuccess, T? value, IReadOnlyList<Error> errors)
    {
        IsSuccess = isSuccess;
        Value = value;
        Errors = errors;
    }

    /// <summary>
    /// Creates a successful result with the given value.
    /// </summary>
    /// <param name="value">The success value.</param>
    /// <returns>A successful Result<T> containing the value.</returns>
    public static Result<T> Success(T value)
    {
        return new Result<T>(isSuccess: true, value: value, errors: []);
    }

    /// <summary>
    /// Creates a failed result with the given error(s).
    /// </summary>
    /// <param name="errors">The error(s) that occurred.</param>
    /// <returns>A failed Result<T> containing the error(s).</returns>
    public static Result<T> Failure(params Error[] errors)
    {
        if (errors.Length == 0)
            throw new ArgumentException("At least one error must be provided", nameof(errors));
        
        return new Result<T>(isSuccess: false, value: default, errors: errors);
    }

    /// <summary>
    /// Creates a failed result with the given error(s).
    /// </summary>
    /// <param name="errors">The error(s) that occurred.</param>
    /// <returns>A failed Result<T> containing the error(s).</returns>
    public static Result<T> Failure(IEnumerable<Error> errors)
    {
        var errorList = errors.ToList();
        if (errorList.Count == 0)
            throw new ArgumentException("At least one error must be provided", nameof(errors));
        
        return new Result<T>(isSuccess: false, value: default, errors: errorList);
    }

    /// <summary>
    /// Transforms the success value using the given function.
    /// If the result is already failed, returns the failure unchanged.
    /// This is the monadic "Map" operation.
    /// </summary>
    /// <typeparam name="TNew">The type of the transformed value.</typeparam>
    /// <param name="map">Function to transform the success value.</param>
    /// <returns>A new Result<TNew> with the transformed value, or the original failure.</returns>
    public Result<TNew> Map<TNew>(Func<T, TNew> map)
    {
        if (!IsSuccess)
            return Result<TNew>.Failure(Errors);

        try
        {
            var newValue = map(Value!);
            return Result<TNew>.Success(newValue);
        }
        catch (Exception ex)
        {
            return Result<TNew>.Failure(new DomainError($"Transformation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Chains a Result-returning operation on the success value.
    /// If the result is already failed, returns the failure unchanged.
    /// If the mapping function returns a failure, returns that failure instead.
    /// This is the monadic "Bind" (or "FlatMap") operation.
    /// </summary>
    /// <typeparam name="TNew">The type of the new success value.</typeparam>
    /// <param name="bind">Function that returns a Result<TNew> from the success value.</param>
    /// <returns>The result of the bind function, or the original failure.</returns>
    public Result<TNew> Bind<TNew>(Func<T, Result<TNew>> bind)
    {
        if (!IsSuccess)
            return Result<TNew>.Failure(Errors);

        try
        {
            return bind(Value!);
        }
        catch (Exception ex)
        {
            return Result<TNew>.Failure(new DomainError($"Operation failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Executes a side effect on the success value without changing the result.
    /// Useful for logging, updating state, or other side effects.
    /// If the result is already failed, the side effect is not executed.
    /// </summary>
    /// <param name="tap">The side effect to execute on success.</param>
    /// <returns>The same result, unchanged.</returns>
    public Result<T> Tap(Action<T> tap)
    {
        if (IsSuccess)
        {
            try
            {
                tap(Value!);
            }
            catch (Exception ex)
            {
                // Log but don't change the result
                System.Diagnostics.Debug.WriteLine($"Tap side effect failed: {ex.Message}");
            }
        }

        return this;
    }

    /// <summary>
    /// Executes a side effect on the error list without changing the result.
    /// Useful for logging errors, incrementing metrics, or other side effects.
    /// If the result is already successful, the side effect is not executed.
    /// </summary>
    /// <param name="tapError">The side effect to execute on failure.</param>
    /// <returns>The same result, unchanged.</returns>
    public Result<T> TapError(Action<IReadOnlyList<Error>> tapError)
    {
        if (!IsSuccess)
        {
            try
            {
                tapError(Errors);
            }
            catch (Exception ex)
            {
                // Log but don't change the result
                System.Diagnostics.Debug.WriteLine($"TapError side effect failed: {ex.Message}");
            }
        }

        return this;
    }

    /// <summary>
    /// Gets the success value or throws an exception with a custom message.
    /// Useful for unwrapping Result<T> when you want to treat failures as exceptions.
    /// </summary>
    /// <param name="throwException">Function to create the exception to throw on failure.</param>
    /// <returns>The success value.</returns>
    /// <exception cref="Exception">Thrown when the result is a failure.</exception>
    public T GetValueOrThrow(Func<IReadOnlyList<Error>, Exception> throwException)
    {
        if (IsSuccess)
            return Value!;

        throw throwException(Errors);
    }

    /// <summary>
    /// Gets the success value or throws an ApplicationException with error details.
    /// Useful for simple unwrapping without custom exception handling.
    /// </summary>
    /// <returns>The success value.</returns>
    /// <exception cref="ApplicationException">Thrown with all error messages when the result is a failure.</exception>
    public T GetValueOrThrow()
    {
        if (IsSuccess)
            return Value!;

        var errorMessage = string.Join(Environment.NewLine, Errors.Select(e => e.ToString()));
        throw new ApplicationException($"Operation failed:{Environment.NewLine}{errorMessage}");
    }

    /// <summary>
    /// Executes a different handler based on success or failure.
    /// This is the standard case/match pattern for Result<T>.
    /// </summary>
    /// <typeparam name="TResult">The return type of both handlers.</typeparam>
    /// <param name="onSuccess">Handler to execute if the result succeeded.</param>
    /// <param name="onFailure">Handler to execute if the result failed.</param>
    /// <returns>The result of whichever handler was executed.</returns>
    public TResult Match<TResult>(Func<T, TResult> onSuccess, Func<IReadOnlyList<Error>, TResult> onFailure)
    {
        return IsSuccess ? onSuccess(Value!) : onFailure(Errors);
    }

    /// <summary>
    /// Executes different handlers based on success or failure without returning a value.
    /// </summary>
    /// <param name="onSuccess">Handler to execute if the result succeeded.</param>
    /// <param name="onFailure">Handler to execute if the result failed.</param>
    public void Match(Action<T> onSuccess, Action<IReadOnlyList<Error>> onFailure)
    {
        if (IsSuccess)
            onSuccess(Value!);
        else
            onFailure(Errors);
    }

    /// <summary>
    /// Converts a failed Result<T> to a successful Result<T> using a recovery function.
    /// If the result is already successful, returns it unchanged.
    /// </summary>
    /// <param name="recover">Function to create a recovery value from errors.</param>
    /// <returns>A successful Result<T> with the original or recovered value.</returns>
    public Result<T> Or(Func<IReadOnlyList<Error>, T> recover)
    {
        if (IsSuccess)
            return this;

        try
        {
            var recoveredValue = recover(Errors);
            return Result<T>.Success(recoveredValue);
        }
        catch (Exception ex)
        {
            return Result<T>.Failure(new DomainError($"Recovery failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Returns a string representation of the result.
    /// Shows "Success: {Value}" for success or "Failure: {Count} error(s)" for failures.
    /// </summary>
    public override string ToString()
    {
        return IsSuccess
            ? $"Success: {Value}"
            : $"Failure: {Errors.Count} error(s) - {string.Join(", ", Errors.Select(e => e.Code))}";
    }

    /// <summary>
    /// Implicitly converts a successful Result<T> to its value.
    /// Throws InvalidOperationException if the result is a failure.
    /// Usage: T value = result;  (only works if result.IsSuccess is true)
    /// </summary>
    /// <param name="result">The result to convert.</param>
    /// <returns>The success value.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is a failure.</exception>
    public static implicit operator T(Result<T> result)
    {
        if (!result.IsSuccess)
            throw new InvalidOperationException($"Cannot convert failed Result<T> to {typeof(T).Name}. " +
                $"Check IsSuccess first or use Value property. Errors: {string.Join(", ", result.Errors.Select(e => e.Message))}");
        return result.Value!;
    }

    /// <summary>
    /// Implicitly converts a failed Result<T> to a single Error.
    /// Gets the first error if multiple errors exist.
    /// Throws InvalidOperationException if the result is successful.
    /// Usage: Error error = result;  (only works if result.IsSuccess is false)
    /// </summary>
    /// <param name="result">The result to convert.</param>
    /// <returns>The first error from the result.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is successful or has no errors.</exception>
    public static implicit operator Error(Result<T> result)
    {
        if (result.IsSuccess)
            throw new InvalidOperationException($"Cannot convert successful Result<T> to Error. Check IsSuccess first.");
        if (result.Errors.Count == 0)
            throw new InvalidOperationException("Result<T> has no errors to convert.");
        return result.Errors[0];
    }

    /// <summary>
    /// Implicitly converts a failed Result<T> to an Error array.
    /// Throws InvalidOperationException if the result is successful.
    /// Usage: Error[] errors = result;  (only works if result.IsSuccess is false)
    /// </summary>
    /// <param name="result">The result to convert.</param>
    /// <returns>Array of all errors from the result.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the result is successful.</exception>
    public static implicit operator Error[](Result<T> result)
    {
        if (result.IsSuccess)
            throw new InvalidOperationException("Cannot convert successful Result<T> to Error[]. Check IsSuccess first.");
        return result.Errors.ToArray();
    }

    public static implicit operator Result<T>(T successResult) => Success(successResult);

    public static implicit operator Result<T>(Error error) => Failure([error]);

    public static implicit operator Result<T>(Error[] errors) => Failure(errors);
}
