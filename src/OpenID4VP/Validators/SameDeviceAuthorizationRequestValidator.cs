using OpenID4VP.Common;
using OpenID4VP.Models;
using OpenID4VC.Core.Results;

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
        public Result Validate(AuthorizationRequest request)
        {
            var errors = new List<ValidationError>();

            // Check response_mode
            if (string.IsNullOrEmpty(request.ResponseMode))
            {
                errors.Add(new ValidationError("response_mode is REQUIRED", "response_mode"));
            }
            else if (request.ResponseMode != "fragment" && request.ResponseMode != "query")
            {
                errors.Add(new ValidationError($"response_mode '{request.ResponseMode}' is not valid for same-device mode. " +
                          "Same-device requires 'fragment' or 'query'", "response_mode"));
            }

            // Check redirect_uri (REQUIRED for same-device)
            if (string.IsNullOrEmpty(request.RedirectUri))
            {
                errors.Add(new ValidationError("redirect_uri is REQUIRED for same-device mode (used for response delivery)", "redirect_uri"));
            }

            // Check response_type (REQUIRED)
            if (string.IsNullOrEmpty(request.ResponseType) || request.ResponseType != "vp_token")
            {
                errors.Add(new ValidationError("response_type is REQUIRED and must be 'vp_token' for same-device mode", "response_type"));
            }

            // Check nonce (REQUIRED)
            if (string.IsNullOrEmpty(request.Nonce))
            {
                errors.Add(new ValidationError("nonce is REQUIRED for same-device mode", "nonce"));
            }

            // Check DCQL query OR scope (at least one, not both)
            var hasDcql = request.DcqlQuery != null;
            var hasScope = !string.IsNullOrEmpty(request.Scope);

            if (!hasDcql && !hasScope)
            {
                errors.Add(new ValidationError("Either dcql_query or scope MUST be set for same-device mode", "dcql_query"));
            }
            else if (hasDcql && hasScope)
            {
                errors.Add(new ValidationError("Only one of dcql_query or scope can be set, not both", "dcql_query"));
            }

            // Check forbidden fields
            if (!string.IsNullOrEmpty(request.RequestUri))
            {
                errors.Add(new ValidationError("request_uri MUST NOT be set in same-device mode. " +
                          "Same-device sends all parameters inline via redirect_uri. " +
                          "request_uri is only used in cross-device mode", "request_uri"));
            }

            if (!string.IsNullOrEmpty(request.ResponseUri))
            {
                errors.Add(new ValidationError("response_uri MUST NOT be set in same-device mode. " +
                          "Same-device uses redirect_uri for response delivery", "response_uri"));
            }

            return errors.Count == 0 
                ? Result.Success()
                : errors.Cast<Error>().ToArray();
        }
    }
}
