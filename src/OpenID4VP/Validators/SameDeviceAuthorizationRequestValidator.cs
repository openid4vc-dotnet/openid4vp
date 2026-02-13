using OpenID4VP.Common;
using OpenID4VP.Models;

namespace OpenID4VP.Validators
{
    /// <summary>
    /// Validator for same-device mode authorization requests (Section 3.1 of OpenID4VP spec).
    /// 
    /// Same-device mode requirements:
    /// - response_mode must be "fragment" or "query"
    /// - redirect_uri MUST be set (for response delivery)
    /// - response_type MUST be set
    /// - nonce MUST be set
    /// - dcql_query OR scope must be set (not both, not neither)
    /// - request_uri MUST NOT be set
    /// - response_uri MUST NOT be set (or is optional and ignored)
    /// </summary>
    public sealed class SameDeviceAuthorizationRequestValidator : IValidator<AuthorizationRequest>
    {
        public ValidationResult Validate(AuthorizationRequest request)
        {
            var errors = new List<string>();

            // Check response_mode
            if (string.IsNullOrEmpty(request.ResponseMode))
            {
                errors.Add("response_mode is REQUIRED");
            }
            else if (request.ResponseMode != "fragment" && request.ResponseMode != "query")
            {
                errors.Add($"response_mode '{request.ResponseMode}' is not valid for same-device mode. " +
                          "Same-device requires 'fragment' or 'query'");
            }

            // Check redirect_uri (REQUIRED for same-device)
            if (string.IsNullOrEmpty(request.RedirectUri))
            {
                errors.Add("redirect_uri is REQUIRED for same-device mode (used for response delivery)");
            }

            // Check response_type (REQUIRED)
            if (string.IsNullOrEmpty(request.ResponseType) || request.ResponseType == "vp_token")
            {
                errors.Add("response_type is REQUIRED for same-device mode");
            }

            // Check nonce (REQUIRED)
            if (string.IsNullOrEmpty(request.Nonce) || request.Nonce == "nonce")
            {
                errors.Add("nonce is REQUIRED for same-device mode");
            }

            // Check DCQL query OR scope (at least one, not both)
            var hasDcql = request.DcqlQuery != null;
            var hasScope = !string.IsNullOrEmpty(request.Scope);

            if (!hasDcql && !hasScope)
            {
                errors.Add("Either dcql_query or scope MUST be set for same-device mode");
            }
            else if (hasDcql && hasScope)
            {
                errors.Add("Only one of dcql_query or scope can be set, not both");
            }

            // Check forbidden fields
            if (!string.IsNullOrEmpty(request.RequestUri))
            {
                errors.Add("request_uri MUST NOT be set in same-device mode. " +
                          "Same-device sends all parameters inline via redirect_uri. " +
                          "request_uri is only used in cross-device mode");
            }

            if (!string.IsNullOrEmpty(request.ResponseUri))
            {
                errors.Add("response_uri MUST NOT be set in same-device mode. " +
                          "Same-device uses redirect_uri for response delivery");
            }

            return errors.Count == 0 
                ? ValidationResult.Success()
                : ValidationResult.Failure(errors);
        }
    }
}
