using System.Text.RegularExpressions;

namespace OpenID4VP.Dcql.Common;

/// <summary>
/// Common regular expressions and validation patterns for DCQL.
/// </summary>
public static partial class ValidationPatterns
{
    /// <summary>
    /// Regex for DCQL identifiers: alphanumeric, underscore, or hyphen characters.
    /// Pattern: ^[a-zA-Z0-9_-]+$
    /// </summary>
    [GeneratedRegex(@"^[a-zA-Z0-9_-]+$", RegexOptions.Compiled)]
    public static partial Regex IdPattern();

    /// <summary>
    /// Regex for base64url encoding validation (URL-safe base64 without padding).
    /// </summary>
    [GeneratedRegex(@"^(?:[\w-]{4})*(?:[\w-]{2}(?:==)?|[\w-]{3}=?)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    public static partial Regex Base64UrlPattern();

    /// <summary>
    /// Validates if a string is a valid DCQL identifier.
    /// </summary>
    public static bool IsValidId(string? value)
    {
        return !string.IsNullOrEmpty(value) && IdPattern().IsMatch(value);
    }

    /// <summary>
    /// Validates if a string is valid base64url encoding.
    /// </summary>
    public static bool IsValidBase64Url(string? value)
    {
        return !string.IsNullOrEmpty(value) && Base64UrlPattern().IsMatch(value);
    }
}
