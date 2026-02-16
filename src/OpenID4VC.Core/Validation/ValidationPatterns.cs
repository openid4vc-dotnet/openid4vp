using System.Text.RegularExpressions;

namespace OpenID4VC.Core.Validation
{
    /// <summary>
    /// Reusable validation patterns for common OpenID specifications.
    /// 
    /// These patterns are used across multiple projects (Core, VP, DCQL) to ensure
    /// consistent validation of common values like nonce, state, etc.
    /// </summary>
    public static class ValidationPatterns
    {
        /// <summary>
        /// RFC 3986 unreserved characters pattern.
        /// 
        /// Used for validating values that must only contain ASCII URL-safe characters:
        /// - Letters: A-Z, a-z
        /// - Digits: 0-9
        /// - Unreserved: - (hyphen), . (period), _ (underscore), ~ (tilde)
        /// 
        /// Per OpenID4VP Spec Section 5.2 (nonce):
        /// "Values MUST only contain ASCII URL safe characters."
        /// </summary>
        public const string AsciiUrlSafeCharactersPattern = @"^[A-Za-z0-9\-._~]+$";

        /// <summary>
        /// Validates that a nonce value contains only ASCII URL-safe characters.
        /// 
        /// Per OpenID4VP Spec Section 5.2:
        /// "nonce: REQUIRED. A case-sensitive String... Values MUST only contain ASCII URL safe characters."
        /// </summary>
        /// <param name="nonce">The nonce value to validate</param>
        /// <returns>True if nonce is valid (non-empty and contains only URL-safe chars), false otherwise</returns>
        public static bool IsValidNonce(string? nonce)
        {
            return !string.IsNullOrEmpty(nonce) && Regex.IsMatch(nonce, AsciiUrlSafeCharactersPattern);
        }

        /// <summary>
        /// Validates that a state value contains only ASCII URL-safe characters.
        /// 
        /// State values should also be URL-safe for consistency with nonce and for
        /// safe transmission in URLs and headers.
        /// </summary>
        /// <param name="state">The state value to validate</param>
        /// <returns>True if state is valid (non-empty and contains only URL-safe chars), false otherwise</returns>
        public static bool IsValidState(string? state)
        {
            return !string.IsNullOrEmpty(state) && Regex.IsMatch(state, AsciiUrlSafeCharactersPattern);
        }
    }
}
