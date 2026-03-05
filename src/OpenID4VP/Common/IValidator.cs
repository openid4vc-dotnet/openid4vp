namespace OpenID4VP.Common;

/// <summary>
/// Re-export of IValidator from OpenID4VC.Core.Validation for backward compatibility.
/// Use OpenID4VC.Core.Validation.IValidator directly in new code.
/// </summary>
public interface IValidator<T> : OpenID4VC.Core.Validation.IValidator<T>
{
}
