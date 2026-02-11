namespace OpenID4VP.Common;

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
    /// <returns>Validation result containing any errors found</returns>
    ValidationResult Validate(T obj);
}
