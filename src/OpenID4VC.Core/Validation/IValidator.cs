namespace OpenID4VC.Core.Validation;

using OpenID4VC.Core.Results;

/// <summary>
/// Base interface for all validators.
/// Implementations validate spec compliance and business logic.
/// </summary>
/// <typeparam name="T">The type to validate</typeparam>
public interface IValidator<T>
{
    /// <summary>
    /// Validates the given object for spec compliance and business logic.
    /// </summary>
    /// <param name="obj">The object to validate</param>
    /// <returns>Result with Success() if valid, or Failure with ValidationErrors if invalid</returns>
    Result Validate(T obj);
}


/// <summary>
/// Base interface for validators that should validate two objects with each other.
/// Implementations validate spec compliance and business logic.
/// </summary>
/// <typeparam name="T">The type to validate with <typeparamref name="U"/></typeparam>
/// <typeparam name="U">The type to validate with <typeparamref name="T"/></typeparam>
public interface IValidator<T, U>
{
    /// <summary>
    /// Validates the given object for spec compliance and business logic.
    /// </summary>
    /// <param name="obj">The object to validate</param>
    /// <returns>Result with Success() if valid, or Failure with ValidationErrors if invalid</returns>
    Result Validate(T first, U second);
}
